// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/httpc"
	oauth "github.com/oakwood-commons/oauth-helpers"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/oakwood-commons/scafctl-plugin-sdk/plugin/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/oakwood-commons/scafctl-plugin-auth-github/internal/clock"
)

const browserCaptureFile = "captured-browser-url.txt"

func TestMain(m *testing.M) {
	if os.Getenv("SCAFCTL_TEST_BROWSER_HELPER") == "1" {
		if len(os.Args) > 1 {
			_ = os.WriteFile(browserCaptureFile, []byte(os.Args[len(os.Args)-1]), 0o600)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func clearGitHubCredentialEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvGitHubToken, "")
	t.Setenv(EnvGHToken, "")
	t.Setenv(EnvGitHubAppID, "")
	t.Setenv(EnvGitHubAppInstallationID, "")
	t.Setenv(EnvGitHubAppPrivateKey, "")
	t.Setenv(EnvGitHubAppPrivateKeyPath, "")
}

func configureCustomPages(t *testing.T, p *Plugin, settings map[string]json.RawMessage) (string, string) {
	t.Helper()
	successDoc := "<!doctype html><html><body>GITHUB-BLUEPRINT-SUCCESS</body></html>"
	failureDoc := "<!doctype html><html><body>GITHUB-BLUEPRINT-FAILURE</body></html>"
	pages := &sdkplugin.AuthCallbackPages{
		SuccessHTML: []byte(successDoc),
		FailureHTML: []byte(failureDoc),
	}
	cfgCtx := sdkplugin.WithHostClient(context.Background(), p.cachedHostClient)
	require.NoError(t, p.ConfigureAuthHandler(cfgCtx, HandlerName, sdkplugin.ProviderConfig{
		BinaryName:        "mycli",
		Settings:          settings,
		AuthCallbackPages: pages,
	}))
	return successDoc, failureDoc
}

func authCodeClientSettings(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(Config{ //nolint:gosec // test fixture
		ClientID:      "gh-oauth-client",
		ClientSecret:  "gh-oauth-secret",
		Hostname:      DefaultHostname,
		DefaultScopes: []string{"repo", "read:user"},
	})
	require.NoError(t, err)
	return map[string]json.RawMessage{HandlerName: raw}
}

func jsonTestResponse(status int, payload any) *http.Response {
	b, _ := json.Marshal(payload)
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(b)),
	}
}

type funcHTTPClient struct {
	postFormFn func(ctx context.Context, endpoint string, data url.Values) (*http.Response, error)
	getFn      func(ctx context.Context, endpoint string, headers map[string]string) (*http.Response, error)
	postJSONFn func(ctx context.Context, endpoint string, body any, headers map[string]string) (*http.Response, error)
}

func (f *funcHTTPClient) PostForm(ctx context.Context, endpoint string, data url.Values) (*http.Response, error) {
	if f.postFormFn != nil {
		return f.postFormFn(ctx, endpoint, data)
	}
	return nil, errors.New("unexpected PostForm call")
}

func (f *funcHTTPClient) Get(ctx context.Context, endpoint string, headers map[string]string) (*http.Response, error) {
	if f.getFn != nil {
		return f.getFn(ctx, endpoint, headers)
	}
	return nil, errors.New("unexpected Get call")
}

func (f *funcHTTPClient) PostJSON(ctx context.Context, endpoint string, body any, headers map[string]string) (*http.Response, error) {
	if f.postJSONFn != nil {
		return f.postJSONFn(ctx, endpoint, body, headers)
	}
	return nil, errors.New("unexpected PostJSON call")
}

type browserOutcome struct {
	status int
	body   string
	csp    string
	err    error
}

func asyncBrowserCallback(querySuffix string) (BrowserOpenFunc, <-chan browserOutcome) {
	ch := make(chan browserOutcome, 1)
	client := &http.Client{Timeout: 5 * time.Second}
	opener := func(_ context.Context, authURL string) error {
		u, err := url.Parse(authURL)
		if err != nil {
			return err
		}
		redirectURI := u.Query().Get("redirect_uri")
		state := u.Query().Get("state")
		target := redirectURI + "/?" + querySuffix
		if !strings.Contains(querySuffix, "state=") {
			target += "&state=" + url.QueryEscape(state)
		}
		go func() {
			req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
			if reqErr != nil {
				ch <- browserOutcome{err: reqErr}
				return
			}
			resp, getErr := client.Do(req)
			if getErr != nil {
				ch <- browserOutcome{err: getErr}
				return
			}
			defer func() { _ = resp.Body.Close() }()
			b, readErr := io.ReadAll(resp.Body)
			ch <- browserOutcome{
				status: resp.StatusCode,
				body:   string(b),
				csp:    resp.Header.Get("Content-Security-Policy"),
				err:    readErr,
			}
		}()
		return nil
	}
	return opener, ch
}

func completeLoopbackCallback(authURL, code string) error {
	u, err := url.Parse(authURL)
	if err != nil {
		return err
	}
	redirectURI := u.Query().Get("redirect_uri")
	state := u.Query().Get("state")
	client := &http.Client{Timeout: 5 * time.Second}
	target := redirectURI + "/?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)
	go func() {
		req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
		if reqErr != nil {
			return
		}
		resp, getErr := client.Do(req)
		if getErr == nil {
			_ = resp.Body.Close()
		}
	}()
	return nil
}

// startPluginAuthGRPCServer starts a real gRPC AuthHandlerServiceServer backed
// by p and returns a connected proto.AuthHandlerServiceClient.
func startPluginAuthGRPCServer(t *testing.T, p *Plugin) proto.AuthHandlerServiceClient {
	t.Helper()
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer()
	proto.RegisterAuthHandlerServiceServer(srv, &sdkplugin.AuthHandlerGRPCServer{Impl: p})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.Stop() })

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return proto.NewAuthHandlerServiceClient(conn)
}

type sliceLogSink struct {
	mu    *sync.Mutex
	lines *[]string
}

func (s sliceLogSink) Init(logr.RuntimeInfo) {}
func (s sliceLogSink) Enabled(int) bool      { return true }
func (s sliceLogSink) Info(_ int, msg string, keysAndValues ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	*s.lines = append(*s.lines, fmt.Sprintf("%s %v", msg, keysAndValues))
}

func (s sliceLogSink) Error(err error, msg string, keysAndValues ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	*s.lines = append(*s.lines, fmt.Sprintf("ERR %v %s %v", err, msg, keysAndValues))
}
func (s sliceLogSink) WithValues(...any) logr.LogSink { return s }
func (s sliceLogSink) WithName(string) logr.LogSink   { return s }

func capturingLoggerContext() (context.Context, *sync.Mutex, *[]string) {
	var mu sync.Mutex
	var lines []string
	lgr := logr.New(sliceLogSink{mu: &mu, lines: &lines})
	return logr.NewContext(context.Background(), lgr), &mu, &lines
}

func TestAuthCodeLogin_WithholdsSuccessUntilExchangeAndStoreFinish(t *testing.T) {
	clearGitHubCredentialEnv(t)

	exchangeEntered := make(chan struct{})
	releaseExchange := make(chan struct{})

	fake := newFakeHostService()
	p := newTestPluginWithHost(nil, fake)
	p.httpClient = &funcHTTPClient{
		postFormFn: func(_ context.Context, _ string, data url.Values) (*http.Response, error) {
			assert.Equal(t, "GH-CODE-1", data.Get("code"))
			assert.NotEmpty(t, data.Get("code_verifier"))
			assert.Equal(t, "gh-oauth-secret", data.Get("client_secret"))
			close(exchangeEntered)
			<-releaseExchange
			return jsonTestResponse(http.StatusOK, TokenResponse{
				AccessToken:           "ghu_test_at",
				RefreshToken:          "ghr_test_rt",
				TokenType:             "bearer",
				Scope:                 "repo read:user",
				ExpiresIn:             28800,
				RefreshTokenExpiresIn: 15897600,
			}), nil
		},
		getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
			return jsonTestResponse(http.StatusOK, User{
				Login: "octocat",
				ID:    1,
				Name:  "The Octocat",
				Email: "octocat@example.com",
			}), nil
		},
	}

	wantSuccess, _ := configureCustomPages(t, p, authCodeClientSettings(t))
	opener, browserCh := asyncBrowserCallback("code=GH-CODE-1")
	p.openBrowser = opener

	var prompts []sdkplugin.DeviceCodePrompt
	loginDone := make(chan error, 1)
	go func() {
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowInteractive,
		}, func(dp sdkplugin.DeviceCodePrompt) {
			prompts = append(prompts, dp)
		})
		loginDone <- err
	}()

	<-exchangeEntered

	// Browser HTTP response MUST remain held while exchangeAuthCode and storeCredentials are incomplete.
	select {
	case out := <-browserCh:
		t.Fatalf("browser received premature response before exchange/storage completed: %+v", out)
	case <-time.After(60 * time.Millisecond):
	}

	close(releaseExchange)
	require.NoError(t, <-loginDone)
	require.Len(t, prompts, 1)
	parsedPromptURL, err := url.Parse(prompts[0].VerificationURI)
	require.NoError(t, err)
	assert.Equal(t, "S256", parsedPromptURL.Query().Get("code_challenge_method"))
	assert.NotEmpty(t, parsedPromptURL.Query().Get("code_challenge"))

	out := <-browserCh
	require.NoError(t, out.err)
	assert.Equal(t, http.StatusOK, out.status)
	assert.Equal(t, wantSuccess, out.body)
	assert.Contains(t, out.csp, "default-src 'none'")
}

func TestAuthCodeLogin_PostCallbackFailuresServeFailurePage(t *testing.T) {
	clearGitHubCredentialEnv(t)

	tests := []struct {
		name         string
		setup        func(p *Plugin, fake *fakeHostService, mock *MockHTTPClient)
		wantTermErr  string
		forbidInHTML string
	}{
		{
			name: "token exchange OAuth error",
			setup: func(_ *Plugin, _ *fakeHostService, mock *MockHTTPClient) {
				mock.AddResponse(http.StatusOK, TokenErrorResponse{
					Error:            "bad_verification_code",
					ErrorDescription: "The code passed is incorrect or expired: secret-trace-99",
				})
			},
			wantTermErr:  "token_exchange",
			forbidInHTML: "secret-trace-99",
		},
		{
			name: "token exchange HTTP 500 non-JSON",
			setup: func(p *Plugin, _ *fakeHostService, _ *MockHTTPClient) {
				p.httpClient = &funcHTTPClient{
					postFormFn: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusBadGateway,
							Body:       io.NopCloser(strings.NewReader("<html>upstream gateway failure detail</html>")),
						}, nil
					},
				}
			},
			wantTermErr:  "status 502",
			forbidInHTML: "upstream gateway failure detail",
		},
		{
			name: "token exchange network error",
			setup: func(_ *Plugin, _ *fakeHostService, mock *MockHTTPClient) {
				mock.AddError(errors.New("dial tcp timeout internal-proxy.example.com"))
			},
			wantTermErr:  "token_exchange",
			forbidInHTML: "internal-proxy.example.com",
		},
		{
			name: "storeCredentials refresh token SetSecret failure",
			setup: func(_ *Plugin, fake *fakeHostService, mock *MockHTTPClient) {
				mock.AddResponse(http.StatusOK, TokenResponse{
					AccessToken:  "ghu_at_secret",
					RefreshToken: "ghr_rt_secret",
					TokenType:    "bearer",
					ExpiresIn:    3600,
				})
				mock.AddResponse(http.StatusOK, User{Login: "octocat", ID: 1})
				fake.setSecretErr = errors.New("keyring locked detail")
			},
			wantTermErr:  "store_credentials",
			forbidInHTML: "keyring locked detail",
		},
		{
			name: "storeCredentials access token SetSecret failure rolls back refresh token",
			setup: func(_ *Plugin, fake *fakeHostService, mock *MockHTTPClient) {
				mock.AddResponse(http.StatusOK, TokenResponse{
					AccessToken:  "ghu_at_secret",
					RefreshToken: "ghr_rt_secret",
					TokenType:    "bearer",
					ExpiresIn:    3600,
				})
				mock.AddResponse(http.StatusOK, User{Login: "octocat", ID: 1})
				fake.setSecretKeyErr = map[string]error{
					SecretKeyAccessToken: errors.New("access secret write denied"),
				}
			},
			wantTermErr:  "store_credentials",
			forbidInHTML: "access secret write denied",
		},
		{
			name: "storeCredentials metadata SetSecret failure rolls back refresh and access tokens",
			setup: func(_ *Plugin, fake *fakeHostService, mock *MockHTTPClient) {
				mock.AddResponse(http.StatusOK, TokenResponse{
					AccessToken:  "ghu_at_secret",
					RefreshToken: "ghr_rt_secret",
					TokenType:    "bearer",
					ExpiresIn:    3600,
				})
				mock.AddResponse(http.StatusOK, User{Login: "octocat", ID: 1})
				fake.setSecretKeyErr = map[string]error{
					SecretKeyMetadata: errors.New("metadata secret write denied"),
				}
			},
			wantTermErr:  "store_credentials",
			forbidInHTML: "metadata secret write denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockHTTPClient()
			fake := newFakeHostService()
			p := newTestPluginWithHost(mock, fake)
			wantSuccess, wantFailure := configureCustomPages(t, p, authCodeClientSettings(t))
			p.httpClient = mock
			tt.setup(p, fake, mock)

			opener, browserCh := asyncBrowserCallback("code=FAIL-CODE")
			p.openBrowser = opener

			_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
				Flow: auth.FlowInteractive,
			}, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantTermErr)

			fake.mu.Lock()
			assert.Empty(t, fake.secrets, "failed fresh login must not leave partial credentials in secret store")
			fake.mu.Unlock()

			st, statusErr := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
			require.NoError(t, statusErr)
			assert.False(t, st.Authenticated)

			out := <-browserCh
			require.NoError(t, out.err)
			assert.Equal(t, http.StatusServiceUnavailable, out.status)
			assert.Equal(t, wantFailure, out.body)
			assert.NotEqual(t, wantSuccess, out.body)
			assert.NotContains(t, out.body, tt.forbidInHTML)
		})
	}
}

func TestAuthCodeLogin_AccountReplacementRollbackAndBoundedCleanup(t *testing.T) {
	clearGitHubCredentialEnv(t)

	t.Run("metadata write failure during replacement login preserves previous account session", func(t *testing.T) {
		mock := NewMockHTTPClient()
		// 1. Alice initial login (exchange + /user).
		mock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "alice_at_1", RefreshToken: "alice_rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
		})
		mock.AddResponse(http.StatusOK, User{Login: "alice", ID: 101, Name: "Alice"})
		// 2. Bob replacement login (exchange + /user), then metadata SetSecret fails.
		mock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "bob_at_1", RefreshToken: "bob_rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
		})
		mock.AddResponse(http.StatusOK, User{Login: "bob", ID: 202, Name: "Bob"})
		// 3. Subsequent ForceRefresh GetToken must use alice_rt, never bob_rt.
		mock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "alice_at_2", RefreshToken: "alice_rt", TokenType: "bearer", ExpiresIn: 3600,
		})

		fake := newFakeHostService()
		p := newTestPluginWithHost(mock, fake)
		wantSuccess, wantFailure := configureCustomPages(t, p, authCodeClientSettings(t))
		p.httpClient = mock

		aliceOpener, aliceCh := asyncBrowserCallback("code=ALICE-CODE")
		p.openBrowser = aliceOpener
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.NoError(t, err)
		aliceOut := <-aliceCh
		require.NoError(t, aliceOut.err)
		assert.Equal(t, http.StatusOK, aliceOut.status)
		assert.Equal(t, wantSuccess, aliceOut.body)

		// Fail metadata write on Bob's replacement login.
		fake.mu.Lock()
		fake.setSecretKeyErr = map[string]error{
			SecretKeyMetadata: errors.New("metadata quota exceeded"),
		}
		fake.mu.Unlock()

		bobOpener, bobCh := asyncBrowserCallback("code=BOB-CODE")
		p.openBrowser = bobOpener
		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "store_credentials")

		bobOut := <-bobCh
		require.NoError(t, bobOut.err)
		assert.Equal(t, http.StatusServiceUnavailable, bobOut.status)
		assert.Equal(t, wantFailure, bobOut.body)
		assert.NotContains(t, bobOut.body, "metadata quota exceeded")

		// Clear injected error and verify Alice's session and refresh token were rolled back cleanly.
		fake.mu.Lock()
		fake.setSecretKeyErr = nil
		assert.Equal(t, "alice_rt", fake.secrets[SecretKeyRefreshToken])
		assert.Equal(t, "alice_at_1", fake.secrets[SecretKeyAccessToken])
		fake.mu.Unlock()

		st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		require.True(t, st.Authenticated)
		assert.Equal(t, "alice", st.Claims.Subject)

		tok, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		require.NoError(t, err)
		assert.Equal(t, "alice_at_2", tok.AccessToken)
		reqs := mock.GetRequests()
		assert.Equal(t, "alice_rt", reqs[len(reqs)-1].Data.Get("refresh_token"))
	})

	t.Run("stalled rollback DeleteSecret respects bounded cleanup timeout", func(t *testing.T) {
		mock := NewMockHTTPClient()
		mock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "bob_at", RefreshToken: "bob_rt", TokenType: "bearer", ExpiresIn: 3600,
		})
		mock.AddResponse(http.StatusOK, User{Login: "bob", ID: 202})

		fake := newFakeHostService()
		p := newTestPluginWithHost(mock, fake)
		p.cleanupTimeout = 45 * time.Millisecond
		_, wantFailure := configureCustomPages(t, p, authCodeClientSettings(t))
		p.httpClient = mock

		deleteHasDeadline := make(chan bool, 1)
		fake.mu.Lock()
		fake.setSecretKeyErr = map[string]error{
			SecretKeyMetadata: errors.New("metadata write failed"),
		}
		fake.deleteSecretFunc = func(ctx context.Context, _ string) error {
			_, ok := ctx.Deadline()
			select {
			case deleteHasDeadline <- ok:
			default:
			}
			<-ctx.Done()
			return ctx.Err()
		}
		fake.mu.Unlock()

		opener, browserCh := asyncBrowserCallback("code=STALL-CODE")
		p.openBrowser = opener

		start := time.Now()
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		elapsed := time.Since(start)
		require.Error(t, err)
		assert.Less(t, elapsed, 2*time.Second)
		assert.True(t, <-deleteHasDeadline)

		out := <-browserCh
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusServiceUnavailable, out.status)
		assert.Equal(t, wantFailure, out.body)
	})
}

func TestAuthCodeLogin_NilPagesDirectErrorsCancellationAndPort(t *testing.T) {
	clearGitHubCredentialEnv(t)

	t.Run("nil AuthCallbackPages serves built-in 503 failure page without leaking error detail", func(t *testing.T) {
		mock := NewMockHTTPClient()
		mock.AddResponse(http.StatusOK, TokenErrorResponse{
			Error:            "bad_verification_code",
			ErrorDescription: "confidential-nil-pages-detail",
		})
		fake := newFakeHostService()
		p := newTestPluginWithHost(mock, fake)
		cfgCtx := sdkplugin.WithHostClient(context.Background(), p.cachedHostClient)
		require.NoError(t, p.ConfigureAuthHandler(cfgCtx, HandlerName, sdkplugin.ProviderConfig{
			BinaryName:        "scafctl",
			Settings:          authCodeClientSettings(t),
			AuthCallbackPages: nil,
		}))
		p.httpClient = mock

		opener, browserCh := asyncBrowserCallback("code=NIL-PAGES-CODE")
		p.openBrowser = opener

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.Error(t, err)

		out := <-browserCh
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusServiceUnavailable, out.status)
		assert.Contains(t, out.body, "Authentication Failed")
		assert.NotContains(t, out.body, "confidential-nil-pages-detail")
	})

	t.Run("direct callback OAuth error drains 400 FailureHTML and strips control chars", func(t *testing.T) {
		mock := NewMockHTTPClient()
		fake := newFakeHostService()
		p := newTestPluginWithHost(mock, fake)
		_, wantFailure := configureCustomPages(t, p, authCodeClientSettings(t))
		p.httpClient = mock

		opener, browserCh := asyncBrowserCallback("error=access_denied&error_description=%1B%5B31muser+denied+consent%1B%5B0m")
		p.openBrowser = opener

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_denied")
		assert.NotContains(t, err.Error(), "\x1b")

		out := <-browserCh
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusBadRequest, out.status)
		assert.Equal(t, wantFailure, out.body)
		assert.NotContains(t, out.body, "user denied consent")
	})

	t.Run("in-flight callback during context cancellation drains 503 FailureHTML cleanly", func(t *testing.T) {
		exchangeEntered := make(chan struct{})
		releaseExchange := make(chan struct{})

		fake := newFakeHostService()
		p := newTestPluginWithHost(nil, fake)
		_, wantFailure := configureCustomPages(t, p, authCodeClientSettings(t))
		p.httpClient = &funcHTTPClient{
			postFormFn: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
				close(exchangeEntered)
				<-releaseExchange
				return nil, context.Canceled
			},
		}

		opener, browserCh := asyncBrowserCallback("code=CANCEL-CODE")
		p.openBrowser = opener

		loginCtx, cancelLogin := context.WithCancel(context.Background())
		loginDone := make(chan error, 1)
		go func() {
			_, err := p.Login(loginCtx, HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
			loginDone <- err
		}()

		<-exchangeEntered
		cancelLogin()
		close(releaseExchange)

		require.Error(t, <-loginDone)
		out := <-browserCh
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusServiceUnavailable, out.status)
		assert.Equal(t, wantFailure, out.body)
	})

	t.Run("CallbackPort binds requested unprivileged port and treats out-of-range port as ephemeral", func(t *testing.T) {
		lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "localhost:0")
		require.NoError(t, err)
		port := lis.Addr().(*net.TCPAddr).Port
		require.NoError(t, lis.Close())

		mock := NewMockHTTPClient()
		mock.AddResponse(http.StatusOK, TokenResponse{AccessToken: "port_at", TokenType: "bearer"})
		mock.AddResponse(http.StatusOK, User{Login: "portuser", ID: 7})
		fake := newFakeHostService()
		p := newTestPluginWithHost(mock, fake)
		configureCustomPages(t, p, authCodeClientSettings(t))
		p.httpClient = mock

		var gotRedirectURI string
		p.openBrowser = func(_ context.Context, authURL string) error {
			u, parseErr := url.Parse(authURL)
			if parseErr != nil {
				return parseErr
			}
			gotRedirectURI = u.Query().Get("redirect_uri")
			return completeLoopbackCallback(authURL, "PORT-CODE")
		}

		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:         auth.FlowInteractive,
			CallbackPort: port,
		}, nil)
		require.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("http://localhost:%d", port), gotRedirectURI)

		// Out-of-range CallbackPort (e.g. 80) falls back to ephemeral port without error.
		mock.Reset()
		mock.AddResponse(http.StatusOK, TokenResponse{AccessToken: "ephem_at", TokenType: "bearer"})
		mock.AddResponse(http.StatusOK, User{Login: "ephemuser", ID: 8})
		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:         auth.FlowInteractive,
			CallbackPort: 80,
		}, nil)
		require.NoError(t, err)
	})
}

func TestInteractiveLogin_BrowserPreference(t *testing.T) {
	t.Run("forwards LoginRequest.Browser over gRPC for both authCodeLogin and interactiveDeviceCodeLogin", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		for _, useAuthCode := range []bool{true, false} {
			modeName := "interactiveDeviceCode"
			if useAuthCode {
				modeName = "authCode"
			}
			t.Run(modeName, func(t *testing.T) {
				for _, wantBrowser := range []string{"msedge", "chrome", ""} {
					t.Run("browser="+wantBrowser, func(t *testing.T) {
						mock := NewMockHTTPClient()
						fake := newFakeHostService()
						p := newTestPluginWithHost(mock, fake)

						var settingsBytes []byte
						if useAuthCode {
							mock.AddResponse(http.StatusOK, TokenResponse{
								AccessToken: "ghu_b", RefreshToken: "ghr_b", TokenType: "bearer", ExpiresIn: 3600,
							})
							mock.AddResponse(http.StatusOK, User{Login: "browser-user", ID: 50})
							settingsBytes = []byte(`{"clientId":"cid","clientSecret":"csec","hostname":"github.com"}`)
						} else {
							mock.AddResponse(http.StatusOK, DeviceCodeResponse{
								DeviceCode: "dc-b", UserCode: "ABCD-1111", VerificationURI: "https://github.com/login/device", ExpiresIn: 900, Interval: 1,
							})
							mock.AddResponse(http.StatusOK, TokenResponse{
								AccessToken: "ghu_dc", RefreshToken: "ghr_dc", TokenType: "bearer", ExpiresIn: 3600,
							})
							mock.AddResponse(http.StatusOK, User{Login: "browser-user", ID: 50})
						}
						p.mu.Lock()
						p.clock = clock.Mock{}
						p.mu.Unlock()

						var gotBrowser string
						p.openBrowser = func(ctx context.Context, targetURL string) error {
							gotBrowser = browserPreferenceFromContext(ctx)
							if useAuthCode {
								return completeLoopbackCallback(targetURL, "BROWSER-CODE")
							}
							return nil
						}

						grpcClient := startPluginAuthGRPCServer(t, p)
						stream, err := grpcClient.Login(context.Background(), &proto.LoginRequest{
							HandlerName:    HandlerName,
							Flow:           string(auth.FlowInteractive),
							Browser:        wantBrowser,
							Settings:       settingsBytes,
							TimeoutSeconds: 10,
						})
						require.NoError(t, err)

						var gotResult *proto.LoginResult
						for {
							msg, recvErr := stream.Recv()
							if errors.Is(recvErr, io.EOF) {
								break
							}
							require.NoError(t, recvErr)
							require.Empty(t, msg.GetError())
							if r := msg.GetResult(); r != nil {
								gotResult = r
							}
						}
						require.NotNil(t, gotResult)
						assert.Equal(t, "browser-user", gotResult.GetClaims().GetSubject())
						assert.Equal(t, wantBrowser, gotBrowser)
					})
				}
			})
		}
	})

	t.Run("defaultBrowserOpener launches configured browser executable via oauth.OpenBrowserWithPreference", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX shell script browser stub requires unix-like OS")
		}
		clearGitHubCredentialEnv(t)

		tmpDir := t.TempDir()
		t.Chdir(tmpDir)
		t.Setenv("SCAFCTL_TEST_BROWSER_HELPER", "1")
		selfBin, execErr := os.Executable()
		require.NoError(t, execErr)
		fakeBrowserScript := filepath.Join(tmpDir, "fake-edge")
		require.NoError(t, os.Symlink(selfBin, fakeBrowserScript))
		urlCaptureFile := browserCaptureFile

		mock := NewMockHTTPClient()
		mock.AddResponse(http.StatusOK, TokenResponse{AccessToken: "real_at", TokenType: "bearer"})
		mock.AddResponse(http.StatusOK, User{Login: "real-opener", ID: 77})
		fake := newFakeHostService()
		p := newTestPluginWithHost(mock, fake)
		configureCustomPages(t, p, authCodeClientSettings(t))
		p.httpClient = mock
		// Reset openBrowser to nil so Login exercises production defaultBrowserOpener.
		p.openBrowser = nil

		loginDone := make(chan error, 1)
		go func() {
			_, loginErr := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
				Flow:    auth.FlowInteractive,
				Browser: fakeBrowserScript,
				Timeout: 10 * time.Second,
			}, nil)
			loginDone <- loginErr
		}()

		var launchedURL string
		require.Eventually(t, func() bool {
			b, err := os.ReadFile(urlCaptureFile) //nolint:gosec // test temp file
			if err != nil || len(b) == 0 {
				return false
			}
			launchedURL = string(b)
			return true
		}, 5*time.Second, 20*time.Millisecond)

		u, err := url.Parse(launchedURL)
		require.NoError(t, err)
		assert.NotEmpty(t, u.Query().Get("code_challenge"))

		require.NoError(t, completeLoopbackCallback(launchedURL, "REAL-OPENER-CODE"))
		require.NoError(t, <-loginDone)

		reqs := mock.GetRequests()
		require.GreaterOrEqual(t, len(reqs), 1)
		assert.Equal(t, oauth.GenerateCodeChallenge(reqs[0].Data.Get("code_verifier")), u.Query().Get("code_challenge"))
	})

	t.Run("defaultBrowserOpener logs warning via logr and falls back to xdg-open when preferred browser fails", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("xdg-open PATH stub is linux-specific")
		}

		tmpDir := t.TempDir()
		t.Chdir(tmpDir)
		t.Setenv("SCAFCTL_TEST_BROWSER_HELPER", "1")
		selfBin, execErr := os.Executable()
		require.NoError(t, execErr)
		fakeXdgOpen := filepath.Join(tmpDir, "xdg-open")
		require.NoError(t, os.Symlink(selfBin, fakeXdgOpen))
		fallbackFile := browserCaptureFile
		t.Setenv("PATH", tmpDir)

		ctx, logMu, logLines := capturingLoggerContext()
		targetURL := "https://github.com/login/device"
		err := defaultBrowserOpener(withBrowserPreference(ctx, filepath.Join(tmpDir, "missing-browser")), targetURL)
		require.NoError(t, err)

		require.Eventually(t, func() bool {
			b, readErr := os.ReadFile(fallbackFile) //nolint:gosec // test temp file
			return readErr == nil && string(b) == targetURL
		}, 3*time.Second, 20*time.Millisecond)

		logMu.Lock()
		joined := strings.Join(*logLines, "\n")
		logMu.Unlock()
		assert.Contains(t, joined, "falling back to system default browser")
	})
}

func TestPerRPCRequestSettingsAndProfileIsolation(t *testing.T) {
	t.Run("effectiveConfig supports nested key, flat settings, null, preserves ConfigureAuthHandler defaults when unset, and rejects invalid configs", func(t *testing.T) {
		p := &Plugin{}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			BinaryName: "scafctl",
			Settings: map[string]json.RawMessage{
				HandlerName: json.RawMessage(`{"clientId":"configured-cid","hostname":"ghes.configured.example.com","defaultScopes":["repo"]}`),
			},
		}))
		t.Cleanup(func() { _ = p.StopAuthHandler(context.Background(), HandlerName) })

		// 1. Empty context preserves ConfigureAuthHandler settings.
		baseCfg, err := p.effectiveConfig(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "configured-cid", baseCfg.ClientID)
		assert.Equal(t, "ghes.configured.example.com", baseCfg.Hostname)

		// 2a. Nil request settings on Go struct request preserves ConfigureAuthHandler settings.
		nilReqCtx := attachRequestSettings(context.Background(), nil)
		nilReqCfg, err := p.effectiveConfig(nilReqCtx)
		require.NoError(t, err)
		assert.Equal(t, "configured-cid", nilReqCfg.ClientID)
		assert.Equal(t, "ghes.configured.example.com", nilReqCfg.Hostname)

		// 2b. Explicit non-nil empty map resolves clean DefaultConfig without leaking activeProfile config.
		emptyReqCtx := attachRequestSettings(context.Background(), map[string]json.RawMessage{})
		emptyReqCfg, err := p.effectiveConfig(emptyReqCtx)
		require.NoError(t, err)
		assert.Equal(t, DefaultClientID, emptyReqCfg.ClientID)
		assert.Equal(t, DefaultHostname, emptyReqCfg.Hostname)

		// 3. Nested handler key overrides per-RPC without mutating p.config.
		nestedCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{"clientId":"nested-cid","hostname":"ghes.nested.example.com","defaultScopes":["read:org"]}`),
		})
		nestedCfg, err := p.effectiveConfig(nestedCtx)
		require.NoError(t, err)
		assert.Equal(t, "nested-cid", nestedCfg.ClientID)
		assert.Equal(t, "ghes.nested.example.com", nestedCfg.Hostname)
		assert.Equal(t, []string{"read:org"}, nestedCfg.DefaultScopes)
		assert.Equal(t, "configured-cid", p.config.ClientID, "p.config must never be mutated")
		assert.Equal(t, "ghes.configured.example.com", p.config.Hostname)

		// 4. Explicit null nested settings resolves clean defaults without leaking activeProfile config.
		nullCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
			HandlerName: json.RawMessage(`null`),
		})
		nullCfg, err := p.effectiveConfig(nullCtx)
		require.NoError(t, err)
		assert.Equal(t, DefaultClientID, nullCfg.ClientID)
		assert.Equal(t, DefaultHostname, nullCfg.Hostname)

		// 5. Malformed nested values fail fast.
		for _, badVal := range []string{`"bad-string"`, `123`, `[]`} {
			badCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
				HandlerName: json.RawMessage(badVal),
			})
			_, err := p.effectiveConfig(badCtx)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "failed to parse handler config")
		}

		// 6. URL-injection characters in hostname are rejected.
		for _, badHost := range []string{`https://github.com`, `github.com/evil`, `github.com?x=1`, `github.com#frag`, `user@github.com`} {
			raw, _ := json.Marshal(map[string]string{"hostname": badHost})
			badHostCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
				HandlerName: raw,
			})
			_, err := p.effectiveConfig(badHostCtx)
			require.Error(t, err, "hostname %q must be rejected", badHost)
			assert.Contains(t, err.Error(), "invalid characters")
		}
	})

	t.Run("Login, GetStatus, GetToken, and DetectAvailableFlows honor per-RPC Settings and Profile over gRPC without mutating p.config", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		pemKey := generateTestPEM(t)

		// Routing HTTP mock verifies exact endpoint hostnames and client_ids per RPC.
		var mu sync.Mutex
		var endpoints []string
		routingHTTP := &funcHTTPClient{
			postFormFn: func(_ context.Context, endpoint string, data url.Values) (*http.Response, error) {
				mu.Lock()
				endpoints = append(endpoints, "POST "+endpoint)
				mu.Unlock()
				switch {
				case strings.HasSuffix(endpoint, "/login/device/code"):
					epURL, _ := url.Parse(endpoint)
					verHost := DefaultHostname
					if epURL != nil && epURL.Host != "" {
						verHost = epURL.Host
					}
					return jsonTestResponse(http.StatusOK, DeviceCodeResponse{
						DeviceCode: "dc-" + data.Get("client_id"), UserCode: "UC-1", VerificationURI: "https://" + verHost + "/login/device", ExpiresIn: 900, Interval: 1,
					}), nil
				case data.Get("grant_type") == "urn:ietf:params:oauth:grant-type:device_code":
					return jsonTestResponse(http.StatusOK, TokenResponse{
						AccessToken: "at-" + data.Get("client_id"), RefreshToken: "rt-" + data.Get("client_id"), TokenType: "bearer", Scope: "repo", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
					}), nil
				case data.Get("grant_type") == "refresh_token":
					return jsonTestResponse(http.StatusOK, TokenResponse{
						AccessToken: "refreshed-" + data.Get("refresh_token"), RefreshToken: data.Get("refresh_token"), TokenType: "bearer", Scope: "repo", ExpiresIn: 3600,
					}), nil
				default:
					return jsonTestResponse(http.StatusOK, TokenResponse{
						AccessToken: "code-at-" + data.Get("client_id"), RefreshToken: "code-rt-" + data.Get("client_id"), TokenType: "bearer", Scope: "repo", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
					}), nil
				}
			},
			getFn: func(_ context.Context, endpoint string, _ map[string]string) (*http.Response, error) {
				mu.Lock()
				endpoints = append(endpoints, "GET "+endpoint)
				mu.Unlock()
				if strings.HasSuffix(endpoint, "/app") {
					return jsonTestResponse(http.StatusOK, AppInfo{ID: 500, Slug: "ghes-app", Name: "GHES App"}), nil
				}
				host := "public-octocat"
				if strings.Contains(endpoint, "ghes.corp.example.com") {
					host = "corp-octocat"
				}
				return jsonTestResponse(http.StatusOK, User{Login: host, ID: 99, Name: host}), nil
			},
			postJSONFn: func(_ context.Context, endpoint string, _ any, _ map[string]string) (*http.Response, error) {
				mu.Lock()
				endpoints = append(endpoints, "POSTJSON "+endpoint)
				mu.Unlock()
				return jsonTestResponse(http.StatusCreated, InstallationTokenResponse{
					Token:     "ghs_ghes_install_tok",
					ExpiresAt: time.Now().Add(time.Hour),
				}), nil
			},
		}

		fake := newFakeHostService()
		p := newTestPluginWithHost(routingHTTP, fake)
		p.mu.Lock()
		p.clock = clock.Mock{}
		p.mu.Unlock()
		origClientID := p.config.ClientID
		origHostname := p.config.Hostname

		grpcClient := startPluginAuthGRPCServer(t, p)

		// 1. DetectAvailableFlows over gRPC with GitHub App settings in per-RPC Settings.
		appSettingsJSON, err := json.Marshal(map[string]any{
			"hostname":       "ghes.corp.example.com",
			"appId":          500,
			"installationId": 777,
			"privateKey":     pemKey,
		})
		require.NoError(t, err)

		detResp, err := grpcClient.DetectAvailableFlows(context.Background(), &proto.DetectAvailableFlowsRequest{
			HandlerName: HandlerName,
			Profile:     "bot",
			Settings:    appSettingsJSON,
		})
		require.NoError(t, err)
		require.Empty(t, detResp.GetError())
		var appAvailable bool
		for _, f := range detResp.GetFlows() {
			if auth.Flow(f.GetFlow()) == auth.FlowGitHubApp {
				appAvailable = f.GetAvailable()
			}
		}
		assert.True(t, appAvailable, "GitHub App flow must be reported available from per-RPC settings")

		// Default DetectAvailableFlows (no settings) still sees GitHub App unavailable.
		detDefault, err := grpcClient.DetectAvailableFlows(context.Background(), &proto.DetectAvailableFlowsRequest{
			HandlerName: HandlerName,
		})
		require.NoError(t, err)
		for _, f := range detDefault.GetFlows() {
			if auth.Flow(f.GetFlow()) == auth.FlowGitHubApp {
				assert.False(t, f.GetAvailable())
			}
		}

		// 2. GitHub App Login on profile "bot" against GHES via per-RPC Settings.
		botStream, err := grpcClient.Login(context.Background(), &proto.LoginRequest{
			HandlerName: HandlerName,
			Profile:     "bot",
			Flow:        string(auth.FlowGitHubApp),
			Settings:    appSettingsJSON,
		})
		require.NoError(t, err)
		var botRes *proto.LoginResult
		for {
			msg, rErr := botStream.Recv()
			if errors.Is(rErr, io.EOF) {
				break
			}
			require.NoError(t, rErr)
			require.Empty(t, msg.GetError())
			if msg.GetResult() != nil {
				botRes = msg.GetResult()
			}
		}
		require.NotNil(t, botRes)
		assert.Equal(t, "app/ghes-app", botRes.GetClaims().GetSubject())
		assert.Equal(t, "ghes.corp.example.com", botRes.GetClaims().GetIssuer())

		// 3. Device-code Login on profile "corp" against GHES via per-RPC Settings.
		corpSettings := []byte(`{"clientId":"corp-cid","hostname":"ghes.corp.example.com","defaultScopes":["repo","read:org"]}`)
		corpStream, err := grpcClient.Login(context.Background(), &proto.LoginRequest{
			HandlerName:    HandlerName,
			Profile:        "corp",
			Flow:           string(auth.FlowDeviceCode),
			Settings:       corpSettings,
			TimeoutSeconds: 10,
		})
		require.NoError(t, err)
		var corpRes *proto.LoginResult
		for {
			msg, rErr := corpStream.Recv()
			if errors.Is(rErr, io.EOF) {
				break
			}
			require.NoError(t, rErr)
			require.Empty(t, msg.GetError())
			if msg.GetResult() != nil {
				corpRes = msg.GetResult()
			}
		}
		require.NotNil(t, corpRes)
		assert.Equal(t, "corp-octocat", corpRes.GetClaims().GetSubject())

		// 4. GetStatus across isolated profiles ("corp", "bot", and unauthenticated "personal").
		stCorp, err := grpcClient.GetStatus(context.Background(), &proto.GetStatusRequest{
			HandlerName: HandlerName,
			Profile:     "corp",
			Settings:    corpSettings,
		})
		require.NoError(t, err)
		assert.True(t, stCorp.GetAuthenticated())
		assert.Equal(t, "corp-octocat", stCorp.GetClaims().GetSubject())
		assert.Equal(t, "corp-cid", stCorp.GetClientId())
		assert.Equal(t, "ghes.corp.example.com", stCorp.GetHostname())

		stBot, err := grpcClient.GetStatus(context.Background(), &proto.GetStatusRequest{
			HandlerName: HandlerName,
			Profile:     "bot",
			Settings:    appSettingsJSON,
		})
		require.NoError(t, err)
		assert.True(t, stBot.GetAuthenticated())
		assert.Equal(t, string(auth.IdentityTypeServicePrincipal), stBot.GetIdentityType())

		stPersonal, err := grpcClient.GetStatus(context.Background(), &proto.GetStatusRequest{
			HandlerName: HandlerName,
			Profile:     "personal",
			Settings:    []byte(`{}`),
		})
		require.NoError(t, err)
		assert.False(t, stPersonal.GetAuthenticated())

		// 5. GetToken with ForceRefresh on "corp" mints against https://ghes.corp.example.com/login/oauth/access_token.
		tokCorp, err := grpcClient.GetToken(context.Background(), &proto.GetTokenRequest{
			HandlerName:  HandlerName,
			Profile:      "corp",
			ForceRefresh: true,
			Settings:     corpSettings,
		})
		require.NoError(t, err)
		assert.Equal(t, "refreshed-rt-corp-cid", tokCorp.GetAccessToken())

		mu.Lock()
		assert.Contains(t, endpoints, "POST https://ghes.corp.example.com/login/device/code")
		assert.Contains(t, endpoints, "POST https://ghes.corp.example.com/login/oauth/access_token")
		assert.Contains(t, endpoints, "GET https://ghes.corp.example.com/api/v3/user")
		assert.Contains(t, endpoints, "GET https://ghes.corp.example.com/api/v3/app")
		assert.Contains(t, endpoints, "POSTJSON https://ghes.corp.example.com/api/v3/app/installations/777/access_tokens")
		mu.Unlock()

		// Base plugin config was never mutated.
		assert.Equal(t, origClientID, p.config.ClientID)
		assert.Equal(t, origHostname, p.config.Hostname)
	})

	t.Run("LoginRequest.Hostname overrides hostname per call and rejects invalid hostnames", func(t *testing.T) {
		t.Setenv(EnvGitHubToken, "ghp_host_override")
		t.Setenv(EnvGHToken, "")

		mock := NewMockHTTPClient()
		mock.AddResponse(http.StatusOK, User{Login: "ghes-pat-user", ID: 12})
		p := newTestPlugin(mock)

		resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowPAT,
			Hostname: "ghes.override.example.com",
		}, nil)
		require.NoError(t, err)
		assert.Equal(t, "ghes-pat-user", resp.Claims.Subject)
		assert.Equal(t, "ghes.override.example.com", resp.Claims.Issuer)
		assert.Equal(t, "https://ghes.override.example.com/api/v3/user", mock.GetRequests()[0].Endpoint)
		assert.Equal(t, DefaultHostname, p.config.Hostname)

		// Invalid Hostname on LoginRequest fails fast.
		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowPAT,
			Hostname: "bad host/evil",
		}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid characters")
	})

	t.Run("concurrent multi-profile gRPC stress under -race", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		routingHTTP := &funcHTTPClient{
			postFormFn: func(_ context.Context, _ string, data url.Values) (*http.Response, error) {
				rt := data.Get("refresh_token")
				return jsonTestResponse(http.StatusOK, TokenResponse{
					AccessToken: "at-for-" + rt, RefreshToken: rt, TokenType: "bearer", ExpiresIn: 3600,
				}), nil
			},
			getFn: func(_ context.Context, endpoint string, _ map[string]string) (*http.Response, error) {
				login := "pub-user"
				if strings.Contains(endpoint, "ghes.work.example.com") {
					login = "work-user"
				}
				return jsonTestResponse(http.StatusOK, User{Login: login, ID: 1}), nil
			},
		}

		fake := newFakeHostService()
		p := newTestPluginWithHost(routingHTTP, fake)

		workCtx := sdkplugin.WithRequestSettings(auth.WithProfile(context.Background(), "work"), map[string]json.RawMessage{
			"clientId": json.RawMessage(`"work-cid"`),
			"hostname": json.RawMessage(`"ghes.work.example.com"`),
		})
		personalCtx := sdkplugin.WithRequestSettings(auth.WithProfile(context.Background(), "personal"), map[string]json.RawMessage{
			"clientId": json.RawMessage(`"personal-cid"`),
			"hostname": json.RawMessage(`"github.com"`),
		})

		_, err := p.storeCredentials(workCtx, &TokenResponse{
			AccessToken: "work-init-at", RefreshToken: "work-rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
		}, []string{"repo"}, "sess-work", auth.FlowInteractive)
		require.NoError(t, err)

		_, err = p.storeCredentials(personalCtx, &TokenResponse{
			AccessToken: "personal-init-at", RefreshToken: "personal-rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
		}, []string{"read:user"}, "sess-personal", auth.FlowDeviceCode)
		require.NoError(t, err)

		grpcClient := startPluginAuthGRPCServer(t, p)

		const workers = 10
		var wg sync.WaitGroup
		for range workers {
			wg.Add(3)
			go func() {
				defer wg.Done()
				tok, rpcErr := grpcClient.GetToken(context.Background(), &proto.GetTokenRequest{
					HandlerName:  HandlerName,
					Profile:      "work",
					ForceRefresh: true,
					Settings:     []byte(`{"clientId":"work-cid","hostname":"ghes.work.example.com"}`),
				})
				assert.NoError(t, rpcErr)
				if tok != nil {
					assert.Equal(t, "at-for-work-rt", tok.GetAccessToken())
				}
			}()
			go func() {
				defer wg.Done()
				tok, rpcErr := grpcClient.GetToken(context.Background(), &proto.GetTokenRequest{
					HandlerName:  HandlerName,
					Profile:      "personal",
					ForceRefresh: true,
					Settings:     []byte(`{"clientId":"personal-cid","hostname":"github.com"}`),
				})
				assert.NoError(t, rpcErr)
				if tok != nil {
					assert.Equal(t, "at-for-personal-rt", tok.GetAccessToken())
				}
			}()
			go func() {
				defer wg.Done()
				st, sErr := grpcClient.GetStatus(context.Background(), &proto.GetStatusRequest{
					HandlerName: HandlerName,
					Profile:     "work",
					Settings:    []byte(`{"clientId":"work-cid","hostname":"ghes.work.example.com"}`),
				})
				assert.NoError(t, sErr)
				if st != nil {
					assert.True(t, st.GetAuthenticated())
					assert.Equal(t, "work-user", st.GetClaims().GetSubject())
				}
			}()
		}
		wg.Wait()
	})
}

func TestHTTPClientCache_IsolationCircuitBreakerAndEviction(t *testing.T) {
	t.Run("isolates init-time httpClient from per-RPC configs omitting httpClient and reuses keep-alive connections", func(t *testing.T) {
		p := &Plugin{}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			BinaryName: "scafctl",
			Settings: map[string]json.RawMessage{
				HandlerName: json.RawMessage(`{"httpClient":{"timeout":"1ns","retryMax":0}}`),
			},
		}))
		t.Cleanup(func() { _ = p.StopAuthHandler(context.Background(), HandlerName) })
		initHTTP := p.httpClient

		sameCfg, err := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"1ns","retryMax":0}}`))
		require.NoError(t, err)
		gotSame, err := p.httpClientForConfig(context.Background(), sameCfg)
		require.NoError(t, err)
		assert.Same(t, initHTTP, gotSame)

		cleanCfg, err := parseHandlerConfig([]byte(`{"hostname":"ghes.example.com"}`))
		require.NoError(t, err)
		cleanHTTP1, err := p.httpClientForConfig(context.Background(), cleanCfg)
		require.NoError(t, err)
		assert.NotSame(t, initHTTP, cleanHTTP1)
		cleanHTTP2, err := p.httpClientForConfig(context.Background(), cleanCfg)
		require.NoError(t, err)
		assert.Same(t, cleanHTTP1, cleanHTTP2)

		// Semantically equivalent durations ("5s" vs "5000ms") share one cached client and TCP connection.
		var newConns atomic.Int32
		ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"login":"octocat","id":1}`))
		}))
		ts.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				newConns.Add(1)
			}
		}
		ts.Start()
		defer ts.Close()

		cfgA, err := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"5s","allowPrivateIPs":true}}`))
		require.NoError(t, err)
		cfgB, err := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"5000ms","allowPrivateIPs":true,"enableCache":false}}`))
		require.NoError(t, err)
		hcA, err := p.httpClientForConfig(context.Background(), cfgA)
		require.NoError(t, err)
		hcB, err := p.httpClientForConfig(context.Background(), cfgB)
		require.NoError(t, err)
		assert.Same(t, hcA, hcB)

		for range 3 {
			resp, reqErr := hcA.Get(context.Background(), ts.URL, map[string]string{"Authorization": "Bearer test"})
			require.NoError(t, reqErr)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		respPost, reqErr := hcA.PostJSON(context.Background(), ts.URL, map[string]string{"k": "v"}, map[string]string{"Authorization": "Bearer test"})
		require.NoError(t, reqErr)
		_, _ = io.Copy(io.Discard, respPost.Body)
		_ = respPost.Body.Close()
		assert.Equal(t, int32(1), newConns.Load())
	})

	t.Run("preserves circuit breaker state across RPCs, evicts LRU closing idle conns, and validates bad durations", func(t *testing.T) {
		var hits atomic.Int32
		failingTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"boom"}`))
		}))
		defer failingTS.Close()

		p := &Plugin{clientCacheSize: 2}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{BinaryName: "scafctl"}))

		cbJSON := `{"httpClient":{"timeout":"2s","retryMax":1,"retryWaitMin":"1ms","retryWaitMax":"2ms","allowPrivateIPs":true,"enableCircuitBreaker":true,"circuitBreakerMaxFailures":2,"circuitBreakerOpenTimeout":"1m"}}`
		cb1, err := parseHandlerConfig([]byte(cbJSON))
		require.NoError(t, err)
		cb2, err := parseHandlerConfig([]byte(cbJSON))
		require.NoError(t, err)

		hc1, err := p.httpClientForConfig(context.Background(), cb1)
		require.NoError(t, err)
		r1, err1 := hc1.PostForm(context.Background(), failingTS.URL, url.Values{"code": {"1"}})
		if r1 != nil {
			_ = r1.Body.Close()
		}
		require.Error(t, err1)

		hc2, err := p.httpClientForConfig(context.Background(), cb2)
		require.NoError(t, err)
		assert.Same(t, hc1, hc2)
		r2, err2 := hc2.PostForm(context.Background(), failingTS.URL, url.Values{"code": {"2"}})
		if r2 != nil {
			_ = r2.Body.Close()
		}
		require.Error(t, err2)

		hitsBeforeOpen := hits.Load()
		_, err3 := hc2.PostForm(context.Background(), failingTS.URL, url.Values{"code": {"3"}})
		require.Error(t, err3)
		assert.ErrorIs(t, err3, httpc.ErrCircuitBreakerOpen)
		assert.Equal(t, hitsBeforeOpen, hits.Load())

		// LRU eviction + StopAuthHandler connection cleanup.
		var closedConns atomic.Int32
		okTS := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{}`))
		}))
		okTS.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				closedConns.Add(1)
			}
		}
		okTS.Start()
		defer okTS.Close()

		evictP := &Plugin{clientCacheSize: 2}
		require.NoError(t, evictP.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{BinaryName: "scafctl"}))

		k1, _ := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"4s","allowPrivateIPs":true}}`))
		k2, _ := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"5s","allowPrivateIPs":true}}`))
		k3, _ := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"6s","allowPrivateIPs":true}}`))

		c1, err := evictP.httpClientForConfig(context.Background(), k1)
		require.NoError(t, err)
		c2, err := evictP.httpClientForConfig(context.Background(), k2)
		require.NoError(t, err)
		for _, c := range []HTTPClient{c1, c2} {
			resp, gErr := c.Get(context.Background(), okTS.URL, nil)
			require.NoError(t, gErr)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		// Promote k1 so k2 is evicted when k3 is inserted.
		_, _ = evictP.httpClientForConfig(context.Background(), k1)
		_, err = evictP.httpClientForConfig(context.Background(), k3)
		require.NoError(t, err)
		assert.Equal(t, 2, evictP.httpClientCache.Len())
		require.Eventually(t, func() bool { return closedConns.Load() == 1 }, 2*time.Second, 10*time.Millisecond)

		require.NoError(t, evictP.StopAuthHandler(context.Background(), HandlerName))
		require.Eventually(t, func() bool { return closedConns.Load() == 2 }, 2*time.Second, 10*time.Millisecond)

		// Invalid HTTPClient fields fail fast.
		for _, badJSON := range []string{
			`{"httpClient":{"timeout":"bad"}}`,
			`{"httpClient":{"retryWaitMin":"bad"}}`,
			`{"httpClient":{"retryWaitMax":"bad"}}`,
			`{"httpClient":{"cacheType":"redis"}}`,
			`{"httpClient":{"cacheTTL":"bad"}}`,
			`{"httpClient":{"circuitBreakerOpenTimeout":"bad"}}`,
		} {
			badCfg, pErr := parseHandlerConfig([]byte(badJSON))
			require.NoError(t, pErr)
			_, hErr := p.httpClientForConfig(context.Background(), badCfg)
			require.Error(t, hErr, "expected error for %s", badJSON)
		}

		// NewDefaultHTTPClientFromAppConfig validation coverage.
		_, err = NewDefaultHTTPClientFromAppConfig(&httpc.AppConfig{Timeout: "bad"}, discardLogger())
		require.Error(t, err)
		goodClient, err := NewDefaultHTTPClientFromAppConfig(&httpc.AppConfig{Timeout: "2s"}, discardLogger())
		require.NoError(t, err)
		require.NoError(t, goodClient.Close())
	})
}

func TestRefreshRotation_ConcurrentLoginGuard(t *testing.T) {
	clearGitHubCredentialEnv(t)

	refreshEntered := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var once sync.Once

	fake := newFakeHostService()
	p := newTestPluginWithHost(nil, fake)
	p.httpClient = &funcHTTPClient{
		postFormFn: func(_ context.Context, _ string, data url.Values) (*http.Response, error) {
			if data.Get("grant_type") == "refresh_token" && data.Get("refresh_token") == "alice_rt" {
				once.Do(func() { close(refreshEntered) })
				<-releaseRefresh
				return jsonTestResponse(http.StatusOK, TokenResponse{
					AccessToken: "alice_rot_at", RefreshToken: "alice_rot_rt", TokenType: "bearer", ExpiresIn: 3600,
				}), nil
			}
			return jsonTestResponse(http.StatusOK, TokenResponse{
				AccessToken: "bob_at", RefreshToken: "bob_rt", TokenType: "bearer", ExpiresIn: 3600,
			}), nil
		},
		getFn: func(_ context.Context, _ string, headers map[string]string) (*http.Response, error) {
			if strings.Contains(headers["Authorization"], "bob") {
				return jsonTestResponse(http.StatusOK, User{Login: "bob", ID: 2}), nil
			}
			return jsonTestResponse(http.StatusOK, User{Login: "alice", ID: 1}), nil
		},
	}

	configureCustomPages(t, p, authCodeClientSettings(t))

	// Seed Alice session.
	_, err := p.storeCredentials(context.Background(), &TokenResponse{
		AccessToken: "alice_at", RefreshToken: "alice_rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
	}, []string{"repo"}, "sess-alice", auth.FlowInteractive)
	require.NoError(t, err)

	refreshDone := make(chan error, 1)
	go func() {
		_, rErr := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		refreshDone <- rErr
	}()

	<-refreshEntered

	// While Alice's refresh HTTP request is in flight, Bob logs in and commits a new SessionID.
	opener, bobCh := asyncBrowserCallback("code=BOB-NEW-SESSION")
	p.openBrowser = opener
	_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
	require.NoError(t, err)
	<-bobCh

	// Release Alice's late rotated token response; Bob's session and token cache must NOT be overwritten.
	close(releaseRefresh)
	require.NoError(t, <-refreshDone)

	st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.True(t, st.Authenticated)
	assert.Equal(t, "bob", st.Claims.Subject)

	rt, err := p.loadRefreshToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "bob_rt", rt)

	tok, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{})
	require.NoError(t, err)
	assert.Equal(t, "bob_at", tok.AccessToken)

	t.Run("concurrent Logout during in-flight refresh does not repopulate token cache", func(t *testing.T) {
		logoutRefreshEntered := make(chan struct{})
		logoutReleaseRefresh := make(chan struct{})
		var logoutOnce sync.Once

		fake2 := newFakeHostService()
		p2 := newTestPluginWithHost(nil, fake2)
		p2.httpClient = &funcHTTPClient{
			postFormFn: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
				logoutOnce.Do(func() { close(logoutRefreshEntered) })
				<-logoutReleaseRefresh
				return jsonTestResponse(http.StatusOK, TokenResponse{
					AccessToken: "stale_after_logout_at", RefreshToken: "stale_after_logout_rt", TokenType: "bearer", ExpiresIn: 3600,
				}), nil
			},
			getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
				return jsonTestResponse(http.StatusOK, User{Login: "alice", ID: 1}), nil
			},
		}
		configureCustomPages(t, p2, authCodeClientSettings(t))

		_, err := p2.storeCredentials(context.Background(), &TokenResponse{
			AccessToken: "alice_at", RefreshToken: "alice_rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
		}, []string{"repo"}, "sess-logout", auth.FlowInteractive)
		require.NoError(t, err)

		inFlightDone := make(chan error, 1)
		go func() {
			_, gErr := p2.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
			inFlightDone <- gErr
		}()

		<-logoutRefreshEntered
		require.NoError(t, p2.Logout(context.Background(), HandlerName, sdkplugin.LogoutRequest{}))
		close(logoutReleaseRefresh)
		require.NoError(t, <-inFlightDone)

		stAfter, sErr := p2.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, sErr)
		assert.False(t, stAfter.Authenticated)

		_, gErr := p2.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{})
		require.Error(t, gErr)
	})
}

func TestSecurityAndSessionParityRegressions(t *testing.T) {
	clearGitHubCredentialEnv(t)

	t.Run("httpClient.enableCache true is forced off so Authorization-bearing GET /user is never shared", func(t *testing.T) {
		var upstreamCalls atomic.Int32
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			if strings.Contains(r.Header.Get("Authorization"), "tok-alice") {
				_, _ = w.Write([]byte(`{"login":"alice","id":1}`))
				return
			}
			_, _ = w.Write([]byte(`{"login":"bob","id":2}`))
		}))
		defer ts.Close()

		p := &Plugin{}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{BinaryName: "scafctl"}))
		t.Cleanup(func() { _ = p.StopAuthHandler(context.Background(), HandlerName) })

		cfgWithCache, err := parseHandlerConfig([]byte(`{"httpClient":{"enableCache":true,"cacheTTL":"10m","allowPrivateIPs":true}}`))
		require.NoError(t, err)
		hc, err := p.httpClientForConfig(context.Background(), cfgWithCache)
		require.NoError(t, err)

		r1, err := hc.Get(context.Background(), ts.URL+"/user", map[string]string{"Authorization": "Bearer tok-alice"})
		require.NoError(t, err)
		b1, _ := io.ReadAll(r1.Body)
		_ = r1.Body.Close()
		assert.Contains(t, string(b1), `"alice"`)

		r2, err := hc.Get(context.Background(), ts.URL+"/user", map[string]string{"Authorization": "Bearer tok-bob"})
		require.NoError(t, err)
		b2, _ := io.ReadAll(r2.Body)
		_ = r2.Body.Close()
		assert.Contains(t, string(b2), `"bob"`)
		assert.Equal(t, int32(2), upstreamCalls.Load(), "HTTP transport cache must remain disabled for auth requests")
	})

	t.Run("LoginRequest.Hostname persists across GetStatus, GetToken, ForceRefresh, ListCachedTokens and fails closed on explicit mismatch", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		var mu sync.Mutex
		var seenEndpoints []string
		routingHTTP := &funcHTTPClient{
			postFormFn: func(_ context.Context, endpoint string, data url.Values) (*http.Response, error) {
				mu.Lock()
				seenEndpoints = append(seenEndpoints, "POST "+endpoint)
				mu.Unlock()
				if strings.HasSuffix(endpoint, "/login/device/code") {
					return jsonTestResponse(http.StatusOK, DeviceCodeResponse{
						DeviceCode: "dc-ghes", UserCode: "GHES-1234", VerificationURI: "https://ghes.override.example.com/login/device", ExpiresIn: 900, Interval: 1,
					}), nil
				}
				if data.Get("grant_type") == "refresh_token" {
					return jsonTestResponse(http.StatusOK, TokenResponse{
						AccessToken: "ghes_refreshed_at", RefreshToken: "ghes_rt", TokenType: "bearer", ExpiresIn: 3600,
					}), nil
				}
				return jsonTestResponse(http.StatusOK, TokenResponse{
					AccessToken: "ghes_initial_at", RefreshToken: "ghes_rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
				}), nil
			},
			getFn: func(_ context.Context, endpoint string, _ map[string]string) (*http.Response, error) {
				mu.Lock()
				seenEndpoints = append(seenEndpoints, "GET "+endpoint)
				mu.Unlock()
				return jsonTestResponse(http.StatusOK, User{Login: "ghes-dev", ID: 42}), nil
			},
		}

		fake := newFakeHostService()
		p := newTestPluginWithHost(routingHTTP, fake)
		p.mu.Lock()
		p.clock = clock.Mock{}
		p.mu.Unlock()

		// Login with --hostname (no static hostname in config).
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowDeviceCode,
			Hostname: "ghes.override.example.com",
			Timeout:  10 * time.Second,
		}, nil)
		require.NoError(t, err)

		// Subsequent GetStatus with default config adopts stored metadata.Hostname.
		st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		require.True(t, st.Authenticated)
		assert.Equal(t, "ghes.override.example.com", st.Hostname)

		// Cached GetToken hits the GHES fingerprint cache key, and ForceRefresh refreshes against GHES (never github.com).
		tok1, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{})
		require.NoError(t, err)
		assert.Equal(t, "ghes_initial_at", tok1.AccessToken)

		tok2, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		require.NoError(t, err)
		assert.Equal(t, "ghes_refreshed_at", tok2.AccessToken)

		cachedList, err := p.ListCachedTokens(context.Background(), HandlerName)
		require.NoError(t, err)
		assert.NotEmpty(t, cachedList)

		mu.Lock()
		for _, ep := range seenEndpoints {
			assert.NotContains(t, ep, "github.com", "session authenticated to GHES must never contact github.com")
		}
		mu.Unlock()

		// Explicit mismatched hostname in per-RPC settings must fail closed on GetToken and report mismatch in GetStatus.
		mismatchSettings := map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{"hostname":"other.example.com"}`),
		}
		stMismatch, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{Settings: mismatchSettings})
		require.NoError(t, err)
		assert.False(t, stMismatch.Authenticated)
		assert.Contains(t, stMismatch.Reason, "authenticated to ghes.override.example.com, not other.example.com")

		_, err = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Settings: mismatchSettings})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `not authenticated for hostname "other.example.com"`)
	})

	t.Run("FlowGitHubApp preserves 1h expiry, re-mints on ForceRefresh, reports expired status, and clears prior user cache", func(t *testing.T) {
		clearGitHubCredentialEnv(t)
		pemKey := generateTestPEM(t)

		var mintCount atomic.Int32
		appHTTP := &funcHTTPClient{
			getFn: func(_ context.Context, endpoint string, _ map[string]string) (*http.Response, error) {
				if strings.HasSuffix(endpoint, "/app") {
					return jsonTestResponse(http.StatusOK, AppInfo{ID: 88, Slug: "deploy-bot\x1b[31m", Name: "Deploy Bot\x07"}), nil
				}
				return jsonTestResponse(http.StatusOK, User{Login: "prior-user", ID: 1}), nil
			},
			postJSONFn: func(_ context.Context, _ string, _ any, _ map[string]string) (*http.Response, error) {
				n := mintCount.Add(1)
				return jsonTestResponse(http.StatusCreated, InstallationTokenResponse{
					Token:     fmt.Sprintf("ghs_app_tok_%d", n),
					ExpiresAt: time.Now().Add(55 * time.Minute),
				}), nil
			},
		}

		fake := newFakeHostService()
		p := newTestPluginWithHost(appHTTP, fake)

		// Seed a prior user session + cached user token on the same profile.
		_, err := p.storeCredentials(context.Background(), &TokenResponse{
			AccessToken: "user_old_at", RefreshToken: "user_old_rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
		}, []string{"repo"}, "sess-user-old", auth.FlowInteractive)
		require.NoError(t, err)

		appSettingsRaw, err := json.Marshal(map[string]any{
			"appId":          88,
			"installationId": 999,
			"privateKey":     pemKey,
		})
		require.NoError(t, err)
		reqSettings := map[string]json.RawMessage{HandlerName: appSettingsRaw}

		loginResp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowGitHubApp,
			Settings: reqSettings,
		}, nil)
		require.NoError(t, err)
		assert.Equal(t, "app/deploy-bot[31m", loginResp.Claims.Subject, "ANSI ESC control char must be stripped from remote app slug")
		assert.NotContains(t, loginResp.Claims.Name, "\x07")

		// Prior user refresh_token and _github cache entry must have been cleared by appLogin.
		assert.False(t, p.secretExists(context.Background(), SecretKeyRefreshToken))

		tok1, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Settings: reqSettings})
		require.NoError(t, err)
		assert.Equal(t, "ghs_app_tok_1", tok1.AccessToken)
		assert.Equal(t, auth.FlowGitHubApp, tok1.Flow)
		assert.Less(t, time.Until(tok1.ExpiresAt), 2*time.Hour, "GitHub App token must never receive 365-day farFuture expiry")

		tok2, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			ForceRefresh: true,
			Settings:     reqSettings,
		})
		require.NoError(t, err)
		assert.Equal(t, "ghs_app_tok_2", tok2.AccessToken)

		// Simulate expired installation token in metadata: GetStatus must report session expired,
		// and GetToken without App credentials must fail instead of returning expired token.
		metaRaw, found, err := p.cachedHostClient.GetSecret(context.Background(), SecretKeyMetadata)
		require.NoError(t, err)
		require.True(t, found)
		var meta TokenMetadata
		require.NoError(t, decodeMetadata(metaRaw, &meta))
		meta.AccessTokenExpiresAt = time.Now().Add(-1 * time.Minute)
		expiredMetaBytes, err := json.Marshal(&meta)
		require.NoError(t, err)
		require.NoError(t, p.cachedHostClient.SetSecret(context.Background(), SecretKeyMetadata, string(expiredMetaBytes)))
		require.NoError(t, cacheClearErr(context.Background(), p.cachedHostClient, ""))

		stExpired, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.False(t, stExpired.Authenticated)
		assert.Equal(t, "session expired", stExpired.Reason)

		_, err = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "GitHub App installation token expired")
	})

	t.Run("PAT rotation in GITHUB_TOKEN does not return stale token from prior PAT cache entry", func(t *testing.T) {
		clearGitHubCredentialEnv(t)
		mock := NewMockHTTPClient()
		mock.AddResponse(http.StatusOK, User{Login: "pat-user-1", ID: 1})
		mock.AddResponse(http.StatusOK, User{Login: "pat-user-2", ID: 2})
		fake := newFakeHostService()
		p := newTestPluginWithHost(mock, fake)

		t.Setenv(EnvGitHubToken, "ghp_first_token")
		tok1, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{})
		require.NoError(t, err)
		assert.Equal(t, "ghp_first_token", tok1.AccessToken)

		// Second call with same token hits host secret cache (zero extra HTTP calls).
		tok1Cached, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{})
		require.NoError(t, err)
		assert.Equal(t, "ghp_first_token", tok1Cached.AccessToken)
		assert.Len(t, mock.GetRequests(), 1)

		// Rotating GITHUB_TOKEN misses the prior PAT cache entry and returns the rotated token.
		t.Setenv(EnvGitHubToken, "ghp_rotated_second_token")
		tok2, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{})
		require.NoError(t, err)
		assert.Equal(t, "ghp_rotated_second_token", tok2.AccessToken)
		assert.Len(t, mock.GetRequests(), 2)
	})

	t.Run("Logout propagates secret deletion errors instead of reporting silent success", func(t *testing.T) {
		fake := newFakeHostService()
		p := newTestPluginWithHost(NewMockHTTPClient(), fake)
		fake.mu.Lock()
		fake.secrets[SecretKeyRefreshToken] = "rt-1"
		fake.deleteSecretFunc = func(_ context.Context, _ string) error {
			return errors.New("secret store locked")
		}
		fake.mu.Unlock()

		err := p.Logout(context.Background(), HandlerName, sdkplugin.LogoutRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secret store locked")
	})

	t.Run("validateVerificationURI enforces HTTPS and matching hostname or subdomain", func(t *testing.T) {
		uri, err := validateVerificationURI("https://github.com/login/device", "github.com")
		require.NoError(t, err)
		assert.Equal(t, "https://github.com/login/device", uri)

		subURI, err := validateVerificationURI("https://auth.ghes.example.com/login/device", "ghes.example.com")
		require.NoError(t, err)
		assert.Equal(t, "https://auth.ghes.example.com/login/device", subURI)

		for _, bad := range []string{
			"http://github.com/login/device",
			"https://evil-phishing.example.com/login/device",
			"https://user:pass@github.com/login/device",
			"https://github.com/login/device\x1b[31m",
			"javascript:alert(1)",
			"",
		} {
			_, vErr := validateVerificationURI(bad, "github.com")
			require.Error(t, vErr, "URI %q must be rejected", bad)
		}
	})

	t.Run("sanitizeCallbackPages drops oversized HTML and defends against caller slice mutation", func(t *testing.T) {
		oversized := bytes.Repeat([]byte("a"), sdkplugin.MaxAuthCallbackPageBytes+1)
		assert.Nil(t, sanitizeCallbackPages(&sdkplugin.AuthCallbackPages{
			SuccessHTML: oversized,
			FailureHTML: oversized,
		}))

		validBuf := []byte("<html>ok</html>")
		sanitized := sanitizeCallbackPages(&sdkplugin.AuthCallbackPages{SuccessHTML: validBuf})
		require.NotNil(t, sanitized)
		validBuf[0] = 'X'
		assert.Equal(t, "<html>ok</html>", string(sanitized.SuccessHTML))
	})

	t.Run("ActivateServerMode supports unconfigured p.httpClient, secret:// SecretRef, strict hostname validation, and empty StopAuthHandler", func(t *testing.T) {
		fake := newFakeHostService()
		fake.secrets["server-pat"] = "ghp_from_host_secret_store"
		hostClient := newFakeHostClient(fake)

		p := &Plugin{cachedHostClient: hostClient}

		// Invalid hostname in ServerConfig must fail validation.
		badServerCfg := json.RawMessage(`{"hostname":"github.com/evil","serverFlow":"pat","credential":{"pat":{"token":"secret://server-pat"}}}`)
		err := p.ActivateServerMode(context.Background(), badServerCfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid characters")

		// Valid secret:// PAT in ServerConfig succeeds even when ConfigureAuthHandler was never called (p.httpClient == nil).
		goodServerCfg := json.RawMessage(`{"hostname":"ghes.server.example.com","serverFlow":"pat","credential":{"pat":{"token":"secret://server-pat"}}}`)
		ctx := sdkplugin.WithHostClient(context.Background(), hostClient)
		require.NoError(t, p.ActivateServerMode(ctx, goodServerCfg))

		tok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextServer,
		})
		require.NoError(t, err)
		assert.Equal(t, "ghp_from_host_secret_store", tok.AccessToken)

		// StopAuthHandler accepts empty handlerName (shutdown cleanup) as well as HandlerName.
		require.NoError(t, p.StopAuthHandler(context.Background(), ""))
	})

	t.Run("Logout still deletes corrupt secrets when GetSecret fails while reporting the read error", func(t *testing.T) {
		fake := newFakeHostService()
		p := newTestPluginWithHost(NewMockHTTPClient(), fake)
		fake.mu.Lock()
		fake.secrets[SecretKeyRefreshToken] = "corrupt-rt"
		fake.secrets[SecretKeyAccessToken] = "valid-at"
		fake.getSecretFunc = func(_ context.Context, name string) error {
			if name == SecretKeyRefreshToken {
				return errors.New("decrypt MAC check failed")
			}
			return nil
		}
		fake.mu.Unlock()

		err := p.Logout(context.Background(), HandlerName, sdkplugin.LogoutRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decrypt MAC check failed")

		// Even though GetSecret failed, DeleteSecret was still attempted so the corrupt secret was cleared.
		fake.mu.Lock()
		fake.getSecretFunc = nil
		_, stillThere := fake.secrets[SecretKeyRefreshToken]
		_, accessThere := fake.secrets[SecretKeyAccessToken]
		fake.mu.Unlock()
		assert.False(t, stillThere, "corrupt refresh secret must be deleted on Logout")
		assert.False(t, accessThere)
	})

	t.Run("GetToken propagates refresh-token read errors instead of treating expiring session as non-expiring", func(t *testing.T) {
		clearGitHubCredentialEnv(t)
		fake := newFakeHostService()
		p := newTestPluginWithHost(NewMockHTTPClient(), fake)

		_, err := p.storeCredentials(context.Background(), &TokenResponse{
			AccessToken: "expiring_at", RefreshToken: "expiring_rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
		}, []string{"repo"}, "sess-read-err", auth.FlowInteractive)
		require.NoError(t, err)
		require.NoError(t, cacheClearErr(context.Background(), p.cachedHostClient, ""))

		fake.mu.Lock()
		fake.getSecretFunc = func(_ context.Context, name string) error {
			if name == SecretKeyRefreshToken {
				return errors.New("transient secret store read error")
			}
			return nil
		}
		fake.mu.Unlock()

		_, err = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "transient secret store read error")
	})

	t.Run("FlowGitHubApp bounds renewal to one mint attempt and guards renewal commit against concurrent Logout and Login", func(t *testing.T) {
		clearGitHubCredentialEnv(t)
		pemKey := generateTestPEM(t)
		appSettingsRaw, err := json.Marshal(map[string]any{
			"appId":          91,
			"installationId": 1001,
			"privateKey":     pemKey,
		})
		require.NoError(t, err)
		reqSettings := map[string]json.RawMessage{HandlerName: appSettingsRaw}

		// 1. Unattainable MinValidFor (>1h) mints at most ONCE and returns explicit insufficient-validity error.
		var mints atomic.Int32
		appHTTP := &funcHTTPClient{
			getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
				return jsonTestResponse(http.StatusOK, AppInfo{ID: 91, Slug: "bounded-bot", Name: "Bounded Bot"}), nil
			},
			postJSONFn: func(_ context.Context, _ string, _ any, _ map[string]string) (*http.Response, error) {
				n := mints.Add(1)
				return jsonTestResponse(http.StatusCreated, InstallationTokenResponse{
					Token:     fmt.Sprintf("ghs_bounded_%d", n),
					ExpiresAt: time.Now().Add(55 * time.Minute),
				}), nil
			},
		}
		fake := newFakeHostService()
		p := newTestPluginWithHost(appHTTP, fake)
		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowGitHubApp,
			Settings: reqSettings,
		}, nil)
		require.NoError(t, err)
		assert.Equal(t, int32(1), mints.Load())

		_, err = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			MinValidFor: 2 * time.Hour,
			Settings:    reqSettings,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "shorter than requested minimum validity")
		assert.Equal(t, int32(2), mints.Load(), "must attempt at most one renewal mint")

		// 2. Concurrent Logout during in-flight GitHub App renewal must NOT restore credentials.
		renewEntered := make(chan struct{})
		releaseRenew := make(chan struct{})
		var renewOnce sync.Once
		logoutAppHTTP := &funcHTTPClient{
			getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
				return jsonTestResponse(http.StatusOK, AppInfo{ID: 91, Slug: "bounded-bot", Name: "Bounded Bot"}), nil
			},
			postJSONFn: func(_ context.Context, _ string, _ any, _ map[string]string) (*http.Response, error) {
				if mints.Add(1) == 4 {
					renewOnce.Do(func() { close(renewEntered) })
					<-releaseRenew
				}
				return jsonTestResponse(http.StatusCreated, InstallationTokenResponse{
					Token:     "ghs_late_after_logout",
					ExpiresAt: time.Now().Add(55 * time.Minute),
				}), nil
			},
		}
		fake2 := newFakeHostService()
		p2 := newTestPluginWithHost(logoutAppHTTP, fake2)
		_, err = p2.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowGitHubApp,
			Settings: reqSettings,
		}, nil)
		require.NoError(t, err)

		renewDone := make(chan error, 1)
		go func() {
			_, rErr := p2.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
				ForceRefresh: true,
				Settings:     reqSettings,
			})
			renewDone <- rErr
		}()

		<-renewEntered
		require.NoError(t, p2.Logout(context.Background(), HandlerName, sdkplugin.LogoutRequest{}))
		close(releaseRenew)
		require.Error(t, <-renewDone)

		stAfter, err := p2.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{Settings: reqSettings})
		require.NoError(t, err)
		assert.False(t, stAfter.Authenticated, "late GitHub App renewal must not restore logged-out session")

		// 3. Concurrent replacement Login during in-flight GitHub App renewal must NOT overwrite the replacement session.
		replaceEntered := make(chan struct{})
		releaseReplace := make(chan struct{})
		var replaceOnce sync.Once
		var replaceMints atomic.Int32
		replaceAppHTTP := &funcHTTPClient{
			getFn: func(_ context.Context, endpoint string, _ map[string]string) (*http.Response, error) {
				if strings.HasSuffix(endpoint, "/app") {
					return jsonTestResponse(http.StatusOK, AppInfo{ID: 91, Slug: "bounded-bot", Name: "Bounded Bot"}), nil
				}
				return jsonTestResponse(http.StatusOK, User{Login: "replacement-user", ID: 55}), nil
			},
			postJSONFn: func(_ context.Context, _ string, _ any, _ map[string]string) (*http.Response, error) {
				if replaceMints.Add(1) == 2 {
					replaceOnce.Do(func() { close(replaceEntered) })
					<-releaseReplace
				}
				return jsonTestResponse(http.StatusCreated, InstallationTokenResponse{
					Token:     "ghs_stale_renewal",
					ExpiresAt: time.Now().Add(55 * time.Minute),
				}), nil
			},
		}
		fake3 := newFakeHostService()
		p3 := newTestPluginWithHost(replaceAppHTTP, fake3)
		_, err = p3.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowGitHubApp,
			Settings: reqSettings,
		}, nil)
		require.NoError(t, err)

		replaceRenewDone := make(chan error, 1)
		go func() {
			_, rErr := p3.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
				ForceRefresh: true,
				Settings:     reqSettings,
			})
			replaceRenewDone <- rErr
		}()

		<-replaceEntered
		_, err = p3.storeCredentials(context.Background(), &TokenResponse{
			AccessToken: "replacement_user_at", RefreshToken: "replacement_user_rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
		}, []string{"repo"}, "sess-user-replace", auth.FlowInteractive)
		require.NoError(t, err)

		close(releaseReplace)
		replaceErr := <-replaceRenewDone
		require.Error(t, replaceErr)
		assert.Contains(t, replaceErr.Error(), "session changed during token renewal")

		stReplaced, err := p3.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, stReplaced.Authenticated)
		assert.Equal(t, "replacement-user", stReplaced.Claims.Subject)
	})

	t.Run("refresh-token rotation preserves original session ClientID when GetToken has no per-RPC settings", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		var refreshClientIDs []string
		var mu sync.Mutex
		rotHTTP := &funcHTTPClient{
			postFormFn: func(_ context.Context, _ string, data url.Values) (*http.Response, error) {
				mu.Lock()
				refreshClientIDs = append(refreshClientIDs, data.Get("client_id"))
				n := len(refreshClientIDs)
				mu.Unlock()
				return jsonTestResponse(http.StatusOK, TokenResponse{
					AccessToken:           fmt.Sprintf("rot_at_%d", n),
					RefreshToken:          fmt.Sprintf("rot_rt_%d", n),
					TokenType:             "bearer",
					ExpiresIn:             3600,
					RefreshTokenExpiresIn: 86400,
				}), nil
			},
			getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
				return jsonTestResponse(http.StatusOK, User{Login: "custom-client-user", ID: 7}), nil
			},
		}

		fake := newFakeHostService()
		p := newTestPluginWithHost(rotHTTP, fake)

		customCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{"clientId":"custom-login-cid"}`),
		})
		_, err := p.storeCredentials(customCtx, &TokenResponse{
			AccessToken: "init_at", RefreshToken: "init_rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
		}, []string{"repo"}, "sess-cid", auth.FlowDeviceCode)
		require.NoError(t, err)

		// First ForceRefresh with NO per-RPC settings rotates init_rt -> rot_rt_1.
		_, err = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		require.NoError(t, err)

		// Second ForceRefresh with NO per-RPC settings must STILL send custom-login-cid!
		_, err = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		require.NoError(t, err)

		mu.Lock()
		assert.Equal(t, []string{"custom-login-cid", "custom-login-cid"}, refreshClientIDs)
		mu.Unlock()
	})

	t.Run("access-token-only replacement login checks refresh-token deletion before metadata commit and rolls back on failure", func(t *testing.T) {
		clearGitHubCredentialEnv(t)
		fake := newFakeHostService()
		mock := NewMockHTTPClient()
		mock.AddResponse(http.StatusOK, User{Login: "alice", ID: 1})
		mock.AddResponse(http.StatusOK, User{Login: "bob", ID: 2})
		mock.AddResponse(http.StatusOK, User{Login: "carol", ID: 3})
		p := newTestPluginWithHost(mock, fake)

		// 1. Seed Alice with a refresh token.
		_, err := p.storeCredentials(context.Background(), &TokenResponse{
			AccessToken: "alice_at", RefreshToken: "alice_rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
		}, []string{"repo"}, "sess-alice", auth.FlowInteractive)
		require.NoError(t, err)

		// 2. Bob logs in with an access-token-only OAuth App response, but DeleteSecret(refresh_token) fails -> must abort!
		fake.mu.Lock()
		fake.deleteSecretFunc = func(_ context.Context, name string) error {
			if name == SecretKeyRefreshToken {
				return errors.New("cannot delete old refresh token")
			}
			return nil
		}
		fake.mu.Unlock()

		_, err = p.storeCredentials(context.Background(), &TokenResponse{
			AccessToken: "bob_nonexp_at", TokenType: "bearer",
		}, []string{"repo"}, "sess-bob", auth.FlowInteractive)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to clear previous refresh token")

		st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.Equal(t, "alice", st.Claims.Subject, "Alice's session must remain intact when refresh-token removal fails")

		// 3. Carol logs in with access-token-only response, DeleteSecret succeeds, then metadata SetSecret fails -> must restore Alice's refresh_token!
		fake.mu.Lock()
		fake.deleteSecretFunc = nil
		fake.setSecretKeyErr = map[string]error{
			SecretKeyMetadata: errors.New("metadata write failed"),
		}
		fake.mu.Unlock()

		_, err = p.storeCredentials(context.Background(), &TokenResponse{
			AccessToken: "carol_nonexp_at", TokenType: "bearer",
		}, []string{"repo"}, "sess-carol", auth.FlowInteractive)
		require.Error(t, err)

		fake.mu.Lock()
		fake.setSecretKeyErr = nil
		assert.Equal(t, "alice_rt", fake.secrets[SecretKeyRefreshToken], "Alice's refresh token must be restored when metadata write fails")
		assert.Equal(t, "alice_at", fake.secrets[SecretKeyAccessToken])
		fake.mu.Unlock()
	})

	t.Run("boundedClientCache returns closed error after CloseAll and Plugin rejects client acquisition after StopAuthHandler", func(t *testing.T) {
		cache := newBoundedClientCache[string, *DefaultHTTPClient](2)
		cache.CloseAll()

		var built atomic.Int32
		got, err := cache.GetOrCreate("k", func() *DefaultHTTPClient {
			built.Add(1)
			return NewDefaultHTTPClient(discardLogger())
		})
		require.ErrorIs(t, err, errClientCacheClosed)
		assert.Nil(t, got)
		assert.Equal(t, int32(0), built.Load(), "closed cache must not build an untracked client")

		// Also verify StopAuthHandler prevents httpClientForConfig from creating untracked clients,
		// while a subsequent ConfigureAuthHandler re-enables caching cleanly.
		p := &Plugin{}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{BinaryName: "scafctl"}))
		require.NoError(t, p.StopAuthHandler(context.Background(), HandlerName))

		customCfg, err := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"4s"}}`))
		require.NoError(t, err)
		_, err = p.httpClientForConfig(context.Background(), customCfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "auth handler stopped")

		// Also verify the default/baseConfig fast path (key == initKey) fails closed after StopAuthHandler.
		_, err = p.httpClientForConfig(context.Background(), p.baseConfig())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "auth handler stopped")

		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{BinaryName: "scafctl"}))
		hcBase, err := p.httpClientForConfig(context.Background(), p.baseConfig())
		require.NoError(t, err)
		require.NotNil(t, hcBase)
		hc, err := p.httpClientForConfig(context.Background(), customCfg)
		require.NoError(t, err)
		require.NotNil(t, hc)
		require.NoError(t, p.StopAuthHandler(context.Background(), HandlerName))
	})

	t.Run("FlowGitHubApp rejects AppID or InstallationID mismatch and pins renewal to stored IDs", func(t *testing.T) {
		clearGitHubCredentialEnv(t)
		pemKey := generateTestPEM(t)

		var seenInstallPaths []string
		var mu sync.Mutex
		appHTTP := &funcHTTPClient{
			getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
				return jsonTestResponse(http.StatusOK, AppInfo{ID: 88, Slug: "pin-bot", Name: "Pin Bot"}), nil
			},
			postJSONFn: func(_ context.Context, endpoint string, _ any, _ map[string]string) (*http.Response, error) {
				mu.Lock()
				seenInstallPaths = append(seenInstallPaths, endpoint)
				n := len(seenInstallPaths)
				mu.Unlock()
				return jsonTestResponse(http.StatusCreated, InstallationTokenResponse{
					Token:     fmt.Sprintf("ghs_pinned_%d", n),
					ExpiresAt: time.Now().Add(55 * time.Minute),
				}), nil
			},
		}
		fake := newFakeHostService()
		p := newTestPluginWithHost(appHTTP, fake)

		loginSettings, _ := json.Marshal(map[string]any{
			"appId":          88,
			"installationId": 1001,
			"privateKey":     pemKey,
		})
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowGitHubApp,
			Settings: map[string]json.RawMessage{HandlerName: loginSettings},
		}, nil)
		require.NoError(t, err)

		// Request with mismatched installationId must be rejected BEFORE returning cached token.
		mismatchInstall, _ := json.Marshal(map[string]any{
			"appId":          88,
			"installationId": 2002,
			"privateKey":     pemKey,
		})
		_, err = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Settings: map[string]json.RawMessage{HandlerName: mismatchInstall},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authenticated for installationId 1001, not 2002")

		// Request with mismatched appId must also be rejected.
		mismatchApp, _ := json.Marshal(map[string]any{
			"appId":          99,
			"installationId": 1001,
			"privateKey":     pemKey,
		})
		_, err = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Settings: map[string]json.RawMessage{HandlerName: mismatchApp},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authenticated for appId 88, not 99")

		// ForceRefresh with only privateKey configured renews using the stored (88, 1001) IDs.
		keyOnlySettings, _ := json.Marshal(map[string]any{
			"privateKey": pemKey,
		})
		renewed, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			ForceRefresh: true,
			Settings:     map[string]json.RawMessage{HandlerName: keyOnlySettings},
		})
		require.NoError(t, err)
		assert.Equal(t, "ghs_pinned_2", renewed.AccessToken)
		mu.Lock()
		assert.Len(t, seenInstallPaths, 2)
		assert.True(t, strings.HasSuffix(seenInstallPaths[1], "/app/installations/1001/access_tokens"))
		mu.Unlock()
	})

	t.Run("partial Logout where metadata deletion fails still prevents late refresh rotation from restoring tokens", func(t *testing.T) {
		clearGitHubCredentialEnv(t)
		refreshEntered := make(chan struct{})
		releaseRefresh := make(chan struct{})
		var once sync.Once

		fake := newFakeHostService()
		p := newTestPluginWithHost(nil, fake)
		p.httpClient = &funcHTTPClient{
			postFormFn: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
				once.Do(func() { close(refreshEntered) })
				<-releaseRefresh
				return jsonTestResponse(http.StatusOK, TokenResponse{
					AccessToken: "resurrected_at", RefreshToken: "resurrected_rt", TokenType: "bearer", ExpiresIn: 3600,
				}), nil
			},
			getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
				return jsonTestResponse(http.StatusOK, User{Login: "alice", ID: 1}), nil
			},
		}

		_, err := p.storeCredentials(context.Background(), &TokenResponse{
			AccessToken: "alice_at", RefreshToken: "alice_rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
		}, []string{"repo"}, "sess-partial-logout", auth.FlowInteractive)
		require.NoError(t, err)

		inFlightDone := make(chan error, 1)
		go func() {
			_, gErr := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
			inFlightDone <- gErr
		}()

		<-refreshEntered

		// Simulate Logout deleting refresh_token and access_token, but failing to delete metadata.
		fake.mu.Lock()
		fake.deleteSecretFunc = func(_ context.Context, name string) error {
			if name == SecretKeyMetadata {
				return errors.New("metadata delete failed")
			}
			return nil
		}
		fake.mu.Unlock()
		require.Error(t, p.Logout(context.Background(), HandlerName, sdkplugin.LogoutRequest{}))

		close(logoutOrRelease(releaseRefresh))
		require.NoError(t, <-inFlightDone)

		fake.mu.Lock()
		fake.deleteSecretFunc = nil
		_, hasRT := fake.secrets[SecretKeyRefreshToken]
		_, hasAT := fake.secrets[SecretKeyAccessToken]
		fake.mu.Unlock()
		assert.False(t, hasRT, "late rotation must not recreate deleted refresh token after partial Logout")
		assert.False(t, hasAT, "late rotation must not recreate deleted access token after partial Logout")
	})

	t.Run("host default hostname github.com in settings does not reject session created with Login Hostname override", func(t *testing.T) {
		clearGitHubCredentialEnv(t)
		routingHTTP := &funcHTTPClient{
			postFormFn: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
				return jsonTestResponse(http.StatusOK, DeviceCodeResponse{
					DeviceCode: "dc-1", UserCode: "UC-1", VerificationURI: "https://ghes.login.example.com/login/device", ExpiresIn: 900, Interval: 1,
				}), nil
			},
			getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
				return jsonTestResponse(http.StatusOK, User{Login: "ghes-user", ID: 9}), nil
			},
		}
		fake := newFakeHostService()
		p := newTestPluginWithHost(routingHTTP, fake)
		p.mu.Lock()
		p.clock = clock.Mock{}
		p.mu.Unlock()

		// Simulate host forwarding defaults.yaml {"hostname":"github.com"} in ConfigureAuthHandler and every RPC Settings.
		hostDefaultSettings := map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{"hostname":"github.com","clientId":"Ov23li6xn492GhPmt4YG"}`),
		}
		require.NoError(t, p.ConfigureAuthHandler(
			sdkplugin.WithHostClient(context.Background(), p.cachedHostClient),
			HandlerName,
			sdkplugin.ProviderConfig{BinaryName: "scafctl", Settings: hostDefaultSettings},
		))
		p.httpClient = routingHTTP
		p.mu.Lock()
		p.clock = clock.Mock{}
		p.mu.Unlock()

		// Seed device-code poll response after requestDeviceCode.
		var call int
		p.httpClient = &funcHTTPClient{
			postFormFn: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
				call++
				if call == 1 {
					return jsonTestResponse(http.StatusOK, DeviceCodeResponse{
						DeviceCode: "dc-1", UserCode: "UC-1", VerificationURI: "https://ghes.login.example.com/login/device", ExpiresIn: 900, Interval: 1,
					}), nil
				}
				return jsonTestResponse(http.StatusOK, TokenResponse{
					AccessToken: "ghes_at", RefreshToken: "ghes_rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
				}), nil
			},
			getFn: routingHTTP.getFn,
		}

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowDeviceCode,
			Hostname: "ghes.login.example.com",
			Settings: hostDefaultSettings,
			Timeout:  10 * time.Second,
		}, nil)
		require.NoError(t, err)

		st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{
			Settings: hostDefaultSettings,
		})
		require.NoError(t, err)
		assert.True(t, st.Authenticated)
		assert.Equal(t, "ghes.login.example.com", st.Hostname)

		tok, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Settings: hostDefaultSettings,
		})
		require.NoError(t, err)
		assert.Equal(t, "ghes_at", tok.AccessToken)

		// Explicit StatusRequest.Hostname = "github.com" still fails closed.
		stExplicitMismatch, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{
			Hostname: "github.com",
			Settings: hostDefaultSettings,
		})
		require.NoError(t, err)
		assert.False(t, stExplicitMismatch.Authenticated)
	})

	t.Run("legacy GitHub App session without Flow or AccessTokenExpiresAt is rejected instead of receiving farFuture expiry", func(t *testing.T) {
		clearGitHubCredentialEnv(t)
		fake := newFakeHostService()
		p := newTestPluginWithHost(NewMockHTTPClient(), fake)

		legacyMeta := TokenMetadata{
			Claims:       &auth.Claims{Issuer: DefaultHostname, Subject: "app/legacy-bot"},
			LastRefresh:  time.Now().Add(-2 * time.Hour),
			Hostname:     DefaultHostname,
			IdentityType: string(auth.IdentityTypeServicePrincipal),
			SessionID:    "legacy-app-sess",
		}
		metaBytes, _ := json.Marshal(legacyMeta)
		require.NoError(t, p.cachedHostClient.SetSecret(context.Background(), SecretKeyAccessToken, "ghs_legacy_expired_install_tok"))
		require.NoError(t, p.cachedHostClient.SetSecret(context.Background(), SecretKeyMetadata, string(metaBytes)))

		st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.False(t, st.Authenticated)

		_, err = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "legacy GitHub App session is missing expiration metadata")
	})

	t.Run("leased HTTP client in pollForToken defers transport close on LRU eviction until lease release", func(t *testing.T) {
		var closedConns atomic.Int32
		ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{}`))
		}))
		ts.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				closedConns.Add(1)
			}
		}
		ts.Start()
		defer ts.Close()

		p := &Plugin{clientCacheSize: 1}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{BinaryName: "scafctl"}))

		cfg1, _ := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"4s","allowPrivateIPs":true}}`))
		cfg2, _ := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"5s","allowPrivateIPs":true}}`))

		hc1, release1, err := p.acquireHTTPClient(context.Background(), cfg1, true)
		require.NoError(t, err)
		resp1, err := hc1.Get(context.Background(), ts.URL, nil)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp1.Body)
		_ = resp1.Body.Close()

		// Evict cfg1 from the 1-entry LRU while hc1 is still leased.
		hc2, err := p.httpClientForConfig(context.Background(), cfg2)
		require.NoError(t, err)
		require.NotNil(t, hc2)

		// hc1's idle connection must NOT be closed while the lease is still held.
		assert.Equal(t, int32(0), closedConns.Load())

		// Releasing the lease closes the retired transport's idle connection.
		release1()
		require.Eventually(t, func() bool { return closedConns.Load() == 1 }, 2*time.Second, 10*time.Millisecond)
		require.NoError(t, p.StopAuthHandler(context.Background(), HandlerName))
	})

	t.Run("concurrent GetToken calls on expired cache coalesce onto a single refresh-token rotation", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		var refreshCalls atomic.Int32
		refreshEntered := make(chan struct{})
		releaseRefresh := make(chan struct{})
		var once sync.Once

		fake := newFakeHostService()
		p := newTestPluginWithHost(nil, fake)
		p.httpClient = &funcHTTPClient{
			postFormFn: func(_ context.Context, _ string, data url.Values) (*http.Response, error) {
				n := refreshCalls.Add(1)
				once.Do(func() { close(refreshEntered) })
				<-releaseRefresh
				if data.Get("refresh_token") != "initial_rt" {
					return jsonTestResponse(http.StatusOK, TokenErrorResponse{Error: "bad_refresh_token"}), nil
				}
				return jsonTestResponse(http.StatusOK, TokenResponse{
					AccessToken:           fmt.Sprintf("coalesced_at_%d", n),
					RefreshToken:          "rotated_rt_1",
					TokenType:             "bearer",
					ExpiresIn:             3600,
					RefreshTokenExpiresIn: 86400,
				}), nil
			},
			getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
				return jsonTestResponse(http.StatusOK, User{Login: "coalesced-user", ID: 1}), nil
			},
		}

		_, err := p.storeCredentials(context.Background(), &TokenResponse{
			AccessToken: "seed_at", RefreshToken: "initial_rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
		}, []string{"repo"}, "sess-coalesce", auth.FlowInteractive)
		require.NoError(t, err)
		// Clear the token cache so concurrent GetToken calls both miss the initial check.
		require.NoError(t, cacheClearErr(context.Background(), p.cachedHostClient, ""))

		const callers = 5
		errs := make(chan error, callers)
		tokens := make(chan string, callers)
		for range callers {
			go func() {
				tok, gErr := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{})
				errs <- gErr
				if tok != nil {
					tokens <- tok.AccessToken
				}
			}()
		}

		<-refreshEntered
		time.Sleep(30 * time.Millisecond)
		close(releaseRefresh)

		for range callers {
			require.NoError(t, <-errs)
			assert.Equal(t, "coalesced_at_1", <-tokens)
		}
		assert.Equal(t, int32(1), refreshCalls.Load(), "concurrent expired-cache GetToken calls must coalesce into 1 HTTP refresh")
	})

	t.Run("flow timeout during post-metadata cache cleanup rolls back credentials and serves 503 failure page", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		mock := NewMockHTTPClient()
		mock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "timeout_at", RefreshToken: "timeout_rt", TokenType: "bearer", ExpiresIn: 3600,
		})
		mock.AddResponse(http.StatusOK, User{Login: "timeout-user", ID: 99})

		fake := newFakeHostService()
		p := newTestPluginWithHost(mock, fake)
		_, wantFailure := configureCustomPages(t, p, authCodeClientSettings(t))
		p.httpClient = mock

		// Seed a cached token key so cacheClear calls DeleteSecret on it, and block
		// that cache DeleteSecret until the login context expires.
		prefix, _ := profileTokenPrefix("")
		staleCacheKey := prefix + "stale_entry"
		fake.mu.Lock()
		fake.secrets[staleCacheKey] = `{"accessToken":"old"}`
		fake.deleteSecretFunc = func(ctx context.Context, name string) error {
			if name == staleCacheKey {
				<-ctx.Done()
				return ctx.Err()
			}
			return nil
		}
		fake.mu.Unlock()

		opener, browserCh := asyncBrowserCallback("code=TIMEOUT-CLEANUP-CODE")
		p.openBrowser = opener

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:    auth.FlowInteractive,
			Timeout: 80 * time.Millisecond,
		}, nil)
		require.Error(t, err)

		out := <-browserCh
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusServiceUnavailable, out.status)
		assert.Equal(t, wantFailure, out.body)

		// Verify refresh_token, access_token, and metadata were rolled back!
		fake.mu.Lock()
		_, hasRT := fake.secrets[SecretKeyRefreshToken]
		_, hasAT := fake.secrets[SecretKeyAccessToken]
		_, hasMeta := fake.secrets[SecretKeyMetadata]
		fake.mu.Unlock()
		assert.False(t, hasRT, "refresh_token must be rolled back when flow times out during cache cleanup")
		assert.False(t, hasAT, "access_token must be rolled back when flow times out during cache cleanup")
		assert.False(t, hasMeta, "metadata must be rolled back when flow times out during cache cleanup")
	})

	t.Run("refresh-token rotation preserves new refresh token on access/metadata write failure or claims cancellation", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		fake := newFakeHostService()
		p := newTestPluginWithHost(nil, fake)

		_, err := p.storeCredentials(context.Background(), &TokenResponse{
			AccessToken: "old_at", RefreshToken: "consumed_old_rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
		}, []string{"repo"}, "sess-rot-preserve", auth.FlowInteractive)
		require.NoError(t, err)

		// 1. Access-token write failure during rotation must NOT restore consumed_old_rt.
		fake.mu.Lock()
		fake.setSecretKeyErr = map[string]error{
			SecretKeyAccessToken: errors.New("transient access token write error"),
		}
		fake.mu.Unlock()

		var call int
		p.httpClient = &funcHTTPClient{
			postFormFn: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
				call++
				return jsonTestResponse(http.StatusOK, TokenResponse{
					AccessToken:           fmt.Sprintf("new_at_%d", call),
					RefreshToken:          fmt.Sprintf("new_rt_%d", call),
					TokenType:             "bearer",
					ExpiresIn:             3600,
					RefreshTokenExpiresIn: 86400,
				}), nil
			},
			getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
				return jsonTestResponse(http.StatusOK, User{Login: "rot-user", ID: 1}), nil
			},
		}

		_, err = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		require.NoError(t, err)

		fake.mu.Lock()
		fake.setSecretKeyErr = nil
		gotRT1 := fake.secrets[SecretKeyRefreshToken]
		fake.mu.Unlock()
		assert.Equal(t, "new_rt_1", gotRT1, "new refresh token must be preserved even if access token write failed")

		// 2. Caller context cancelled during claims lookup after refresh HTTP succeeds still persists new_rt_2.
		p.httpClient = &funcHTTPClient{
			postFormFn: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
				return jsonTestResponse(http.StatusOK, TokenResponse{
					AccessToken:           "new_at_2",
					RefreshToken:          "new_rt_2",
					TokenType:             "bearer",
					ExpiresIn:             3600,
					RefreshTokenExpiresIn: 86400,
				}), nil
			},
			getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
				return nil, context.Canceled
			},
		}
		cancelCtx, cancel := context.WithCancel(context.Background())
		p.httpClient = &funcHTTPClient{
			postFormFn: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
				cancel()
				return jsonTestResponse(http.StatusOK, TokenResponse{
					AccessToken:           "new_at_2",
					RefreshToken:          "new_rt_2",
					TokenType:             "bearer",
					ExpiresIn:             3600,
					RefreshTokenExpiresIn: 86400,
				}), nil
			},
			getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
				return nil, context.Canceled
			},
		}
		_, err = p.GetToken(cancelCtx, HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		require.NoError(t, err)

		fake.mu.Lock()
		gotRT2 := fake.secrets[SecretKeyRefreshToken]
		fake.mu.Unlock()
		assert.Equal(t, "new_rt_2", gotRT2, "new refresh token must be persisted even when caller cancels during claims lookup")
	})

	t.Run("cancelled waiter exits acquireRefreshSlot immediately while first refresh is blocked, and closed DefaultHTTPClient fails closed", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		refreshEntered := make(chan struct{})
		releaseRefresh := make(chan struct{})
		var once sync.Once

		fake := newFakeHostService()
		p := newTestPluginWithHost(nil, fake)
		p.httpClient = &funcHTTPClient{
			postFormFn: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
				once.Do(func() { close(refreshEntered) })
				<-releaseRefresh
				return jsonTestResponse(http.StatusOK, TokenResponse{
					AccessToken: "first_at", RefreshToken: "first_rt", TokenType: "bearer", ExpiresIn: 3600,
				}), nil
			},
			getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
				return jsonTestResponse(http.StatusOK, User{Login: "wait-user", ID: 1}), nil
			},
		}

		_, err := p.storeCredentials(context.Background(), &TokenResponse{
			AccessToken: "seed_at", RefreshToken: "seed_rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
		}, []string{"repo"}, "sess-wait-cancel", auth.FlowInteractive)
		require.NoError(t, err)
		require.NoError(t, cacheClearErr(context.Background(), p.cachedHostClient, ""))

		firstDone := make(chan error, 1)
		go func() {
			_, fErr := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
			firstDone <- fErr
		}()

		<-refreshEntered

		shortCtx, shortCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
		defer shortCancel()
		start := time.Now()
		_, waitErr := p.GetToken(shortCtx, HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		elapsed := time.Since(start)
		require.ErrorIs(t, waitErr, context.DeadlineExceeded)
		assert.Less(t, elapsed, time.Second, "cancelled waiter must return before blocked refresh finishes")

		close(releaseRefresh)
		require.NoError(t, <-firstDone)

		// Closed DefaultHTTPClient rejects subsequent requests instead of reopening connections.
		dh := NewDefaultHTTPClient(discardLogger())
		require.NoError(t, dh.Close())
		_, err = dh.Get(context.Background(), "https://api.github.com/user", nil)
		require.ErrorIs(t, err, errHTTPClientClosed)
		_, err = dh.PostForm(context.Background(), "https://github.com/login/oauth/access_token", url.Values{})
		require.ErrorIs(t, err, errHTTPClientClosed)
		_, err = dh.PostJSON(context.Background(), "https://api.github.com/app", nil, nil)
		require.ErrorIs(t, err, errHTTPClientClosed)
	})

	t.Run("refresh-token rotation persists rotated refresh token even when access-token or second metadata read fails", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		fake := newFakeHostService()
		p := newTestPluginWithHost(nil, fake)

		_, err := p.storeCredentials(context.Background(), &TokenResponse{
			AccessToken: "seed_at", RefreshToken: "seed_rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
		}, []string{"repo"}, "sess-rot-read-err", auth.FlowInteractive)
		require.NoError(t, err)

		var exchanged atomic.Bool
		var postExchangeMetaReads atomic.Int32
		var postExchangeRefreshReads atomic.Int32
		var seenRefreshTokens []string
		var mu sync.Mutex

		fake.mu.Lock()
		fake.getSecretFunc = func(_ context.Context, name string) error {
			if !exchanged.Load() {
				return nil
			}
			switch name {
			case SecretKeyAccessToken:
				return errors.New("access token read failed during rotation")
			case SecretKeyMetadata:
				if postExchangeMetaReads.Add(1) > 1 {
					return errors.New("redundant metadata snapshot read failed")
				}
			case SecretKeyRefreshToken:
				if postExchangeRefreshReads.Add(1) > 1 {
					return errors.New("redundant refresh-token snapshot read failed")
				}
			}
			return nil
		}
		fake.mu.Unlock()

		p.httpClient = &funcHTTPClient{
			postFormFn: func(_ context.Context, _ string, data url.Values) (*http.Response, error) {
				mu.Lock()
				seenRefreshTokens = append(seenRefreshTokens, data.Get("refresh_token"))
				n := len(seenRefreshTokens)
				mu.Unlock()
				exchanged.Store(true)
				return jsonTestResponse(http.StatusOK, TokenResponse{
					AccessToken:           fmt.Sprintf("rot_at_%d", n),
					RefreshToken:          fmt.Sprintf("rot_rt_%d", n),
					TokenType:             "bearer",
					ExpiresIn:             3600,
					RefreshTokenExpiresIn: 86400,
				}), nil
			},
			getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
				return jsonTestResponse(http.StatusOK, User{Login: "rot-read-user", ID: 1}), nil
			},
		}

		_, err = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		require.NoError(t, err)

		fake.mu.Lock()
		fake.getSecretFunc = nil
		persistedRT := fake.secrets[SecretKeyRefreshToken]
		fake.mu.Unlock()
		assert.Equal(t, "rot_rt_1", persistedRT, "rotated refresh token must be persisted without running rollback-only snapshot reads")

		// Subsequent refresh after store recovery must present rot_rt_1 (not consumed seed_rt).
		_, err = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		require.NoError(t, err)

		mu.Lock()
		assert.Equal(t, []string{"seed_rt", "rot_rt_1"}, seenRefreshTokens)
		mu.Unlock()
	})

	t.Run("admitted requests and leases close httpc cloned transport pool when closed mid-flight", func(t *testing.T) {
		// 1. Standalone DefaultHTTPClient (enterRequest drain path): Close() runs during
		// attempt 1, retry attempt 2 opens a new keep-alive connection after Close(), and
		// closing resp.Body drains active == 0 -> closes httpc's cloned transport pool.
		var newConns1, closedConns1 atomic.Int32
		var standalone *DefaultHTTPClient
		var attempts1 atomic.Int32
		ts1 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if attempts1.Add(1) == 1 {
				_ = standalone.Close()
				w.Header().Set("Connection", "close")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"retry"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		ts1.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				newConns1.Add(1)
			case http.StateClosed:
				closedConns1.Add(1)
			}
		}
		ts1.Start()
		defer ts1.Close()

		var err error
		standalone, err = NewDefaultHTTPClientFromAppConfig(&httpc.AppConfig{
			Timeout:             "2s",
			RetryMax:            1,
			RetryWaitMin:        "1ms",
			RetryWaitMax:        "2ms",
			AllowedPrivateCIDRs: []string{"127.0.0.0/8", "::1/128"},
		}, discardLogger())
		require.NoError(t, err)

		resp1, err := standalone.Get(context.Background(), ts1.URL, nil)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp1.Body)
		require.NoError(t, resp1.Body.Close())
		assert.Equal(t, int32(2), newConns1.Load())
		require.Eventually(t, func() bool {
			return closedConns1.Load() == newConns1.Load()
		}, 2*time.Second, 10*time.Millisecond, "enterRequest drain must close httpc cloned transport connections")

		// 2. Leased default Plugin HTTP client (acquireLease drain path): StopAuthHandler
		// closes defHTTP while both an outer lease and an admitted request are active;
		// retry attempt 2 opens a post-Stop keep-alive connection that stays open while
		// the outer lease is held and closes as soon as release() drains active == 0.
		var newConns2, closedConns2 atomic.Int32
		p := &Plugin{}
		initSettings := map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{"httpClient":{"timeout":"2s","retryMax":1,"retryWaitMin":"1ms","retryWaitMax":"2ms","allowPrivateIPs":true}}`),
		}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			BinaryName: "scafctl",
			Settings:   initSettings,
		}))

		var attempts2 atomic.Int32
		ts2 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if attempts2.Add(1) == 1 {
				_ = p.StopAuthHandler(context.Background(), HandlerName)
				w.Header().Set("Connection", "close")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"retry"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		ts2.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				newConns2.Add(1)
			case http.StateClosed:
				closedConns2.Add(1)
			}
		}
		ts2.Start()
		defer ts2.Close()

		leasedClient, releaseLease, err := p.acquireHTTPClient(context.Background(), p.baseConfig(), true)
		require.NoError(t, err)

		resp2, err := leasedClient.Get(context.Background(), ts2.URL, nil)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp2.Body)
		require.NoError(t, resp2.Body.Close())

		releaseLease()
		assert.Equal(t, int32(2), newConns2.Load())
		require.Eventually(t, func() bool {
			return closedConns2.Load() == newConns2.Load()
		}, 2*time.Second, 10*time.Millisecond, "acquireLease drain must close httpc cloned transport connections")
	})
}

func logoutOrRelease(ch chan struct{}) chan struct{} {
	return ch
}
