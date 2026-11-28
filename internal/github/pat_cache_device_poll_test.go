// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/oakwood-commons/scafctl-plugin-sdk/plugin/proto"
	"github.com/oakwood-commons/scafctl-plugin-sdk/plugintest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oakwood-commons/scafctl-plugin-auth-github/internal/clock"
)

func newTestPluginWithPlugintestHost(tb testing.TB, httpClient HTTPClient, opts ...plugintest.Option) (*Plugin, *sdkplugin.HostServiceClient, *plugintest.FakeHostService) {
	tb.Helper()
	hc, fakeHost := plugintest.NewFakeHostClient(tb, opts...)
	p := &Plugin{
		cachedHostClient: hc,
		openBrowser: func(_ context.Context, _ string) error {
			return nil
		},
	}
	require.NoError(tb, p.ConfigureAuthHandler(
		sdkplugin.WithHostClient(context.Background(), hc),
		HandlerName,
		sdkplugin.ProviderConfig{BinaryName: "scafctl"},
	))
	p.cachedHostClient = hc
	if httpClient != nil {
		p.httpClient = httpClient
	}
	tb.Cleanup(func() { _ = p.StopAuthHandler(context.Background(), HandlerName) })
	return p, hc, fakeHost
}

type recordingClock struct {
	mu     sync.Mutex
	events []string
	sleeps []time.Duration
}

func (r *recordingClock) NewTicker(_ time.Duration) clock.Ticker {
	return (clock.Mock{}).NewTicker(0)
}

func (r *recordingClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	r.sleeps = append(r.sleeps, d)
	r.events = append(r.events, "sleep:"+d.String())
	r.mu.Unlock()
	return nil
}

func (r *recordingClock) recordEvent(ev string) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
}

func TestPATLogin_PersistStatusTokenEnvPrecedenceAndLogout(t *testing.T) {
	clearGitHubCredentialEnv(t)

	mock := NewMockHTTPClient()
	mock.AddResponse(http.StatusOK, User{
		Login: "octocat",
		ID:    42,
		Name:  "The Octocat",
		Email: "octocat@example.com",
	})
	mock.AddResponse(http.StatusOK, User{
		Login: "octocat",
		ID:    42,
		Name:  "The Octocat",
		Email: "octocat@example.com",
	})
	mock.AddResponse(http.StatusOK, User{
		Login: "env-override-user",
		ID:    99,
		Name:  "Env Override",
	})

	p, _, fakeHost := newTestPluginWithPlugintestHost(t, mock)
	ctx := context.Background()

	// 1. Login with GH_TOKEN set persists the validated PAT in the host secret store.
	const persistedPAT = "ghp_persisted_login_secret"
	t.Setenv(EnvGHToken, persistedPAT)

	loginResp, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{
		Flow:   auth.FlowPAT,
		Scopes: []string{"repo"},
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, loginResp.Claims)
	assert.Equal(t, "octocat", loginResp.Claims.Subject)
	assert.Len(t, mock.GetRequests(), 1, "PAT login must validate claims once without duplicate /user calls")

	// 2. Unset GH_TOKEN and GITHUB_TOKEN: status and token calls use the persisted credential.
	t.Setenv(EnvGHToken, "")
	t.Setenv(EnvGitHubToken, "")

	st, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.True(t, st.Authenticated)
	assert.Equal(t, auth.FlowPAT, st.Flow)
	assert.Equal(t, "octocat", st.Claims.Subject)
	assert.Equal(t, DefaultHostname, st.Hostname)
	assert.Empty(t, st.ClientID)
	assert.Len(t, mock.GetRequests(), 1, "GetStatus for persisted PAT must read stored metadata without network I/O")

	tok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
	require.NoError(t, err)
	assert.Equal(t, persistedPAT, tok.AccessToken)
	assert.Equal(t, "Bearer", tok.TokenType)
	assert.Equal(t, auth.FlowPAT, tok.Flow)
	assert.Len(t, mock.GetRequests(), 1)

	// ForceRefresh revalidates the persisted PAT against /user before returning or caching it.
	forcedTok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
	require.NoError(t, err)
	assert.Equal(t, persistedPAT, forcedTok.AccessToken)
	assert.Equal(t, auth.FlowPAT, forcedTok.Flow)
	assert.Len(t, mock.GetRequests(), 2)

	cachedList, err := p.ListCachedTokens(ctx, HandlerName)
	require.NoError(t, err)
	require.Len(t, cachedList, 1)
	assert.Equal(t, auth.FlowPAT, cachedList[0].Flow)
	assert.Equal(t, "access", cachedList[0].TokenKind)

	// 3. Ambient environment PAT takes precedence without mutating the stored profile secret.
	const ambientPAT = "ghp_ambient_override_secret"
	t.Setenv(EnvGitHubToken, ambientPAT)

	envTok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
	require.NoError(t, err)
	assert.Equal(t, ambientPAT, envTok.AccessToken)
	assert.Equal(t, auth.FlowPAT, envTok.Flow)
	assert.Len(t, mock.GetRequests(), 3)

	storedRaw, storedOK := fakeHost.Secret(SecretKeyAccessToken)
	require.True(t, storedOK)
	assert.Equal(t, persistedPAT, storedRaw, "ambient environment PAT must not overwrite persisted profile PAT")

	// Unsetting ambient env var restores access to the persisted profile PAT.
	t.Setenv(EnvGitHubToken, "")
	restoredTok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
	require.NoError(t, err)
	assert.Equal(t, persistedPAT, restoredTok.AccessToken)

	// 4. Logout clears the persisted PAT, metadata, and cached token entries.
	require.NoError(t, p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{}))
	assert.Empty(t, fakeHost.Secrets())

	stAfter, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.False(t, stAfter.Authenticated)

	_, err = p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authenticated")
}

func TestPATLogin_HostnameOverrideProfileIsolationAndRollback(t *testing.T) {
	t.Run("persists GHES hostname override and isolates named profiles", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		var seenEndpoints []string
		var mu sync.Mutex
		routingHTTP := &funcHTTPClient{
			getFn: func(_ context.Context, endpoint string, _ map[string]string) (*http.Response, error) {
				mu.Lock()
				seenEndpoints = append(seenEndpoints, endpoint)
				mu.Unlock()
				return jsonTestResponse(http.StatusOK, User{
					Login: "ghes-octocat",
					ID:    7,
					Name:  "GHES Octocat",
				}), nil
			},
		}

		p, hc, _ := newTestPluginWithPlugintestHost(t, routingHTTP)
		hostDefaultSettings := map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{"hostname":"github.com","clientId":"Ov23li6xn492GhPmt4YG"}`),
		}
		require.NoError(t, p.ConfigureAuthHandler(
			sdkplugin.WithHostClient(context.Background(), hc),
			HandlerName,
			sdkplugin.ProviderConfig{BinaryName: "scafctl", Settings: hostDefaultSettings},
		))
		p.httpClient = routingHTTP

		entCtx := auth.WithProfile(context.Background(), "enterprise")
		t.Setenv(EnvGHToken, "ghp_ghes_enterprise_token")

		resp, err := p.Login(entCtx, HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowPAT,
			Hostname: "github.example.com",
			Settings: hostDefaultSettings,
			Timeout:  5 * time.Second,
		}, nil)
		require.NoError(t, err)
		assert.Equal(t, "ghes-octocat", resp.Claims.Subject)
		assert.Equal(t, "github.example.com", resp.Claims.Issuer)

		mu.Lock()
		assert.Equal(t, []string{"https://github.example.com/api/v3/user"}, seenEndpoints)
		mu.Unlock()

		// Unset GH_TOKEN: enterprise profile remains authenticated to github.example.com, default profile is unauthenticated.
		t.Setenv(EnvGHToken, "")

		stDefault, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{Settings: hostDefaultSettings})
		require.NoError(t, err)
		assert.False(t, stDefault.Authenticated)

		stEnt, err := p.GetStatus(entCtx, HandlerName, sdkplugin.StatusRequest{Settings: hostDefaultSettings})
		require.NoError(t, err)
		assert.True(t, stEnt.Authenticated)
		assert.Equal(t, auth.FlowPAT, stEnt.Flow)
		assert.Equal(t, "github.example.com", stEnt.Hostname)

		tokEnt, err := p.GetToken(entCtx, HandlerName, sdkplugin.TokenRequest{Settings: hostDefaultSettings})
		require.NoError(t, err)
		assert.Equal(t, "ghp_ghes_enterprise_token", tokEnt.AccessToken)

		// ForceRefresh revalidates against the persisted GHES hostname rather than the default github.com setting.
		forcedEnt, err := p.GetToken(entCtx, HandlerName, sdkplugin.TokenRequest{
			ForceRefresh: true,
			Settings:     hostDefaultSettings,
		})
		require.NoError(t, err)
		assert.Equal(t, "ghp_ghes_enterprise_token", forcedEnt.AccessToken)
		mu.Lock()
		assert.Equal(t, []string{
			"https://github.example.com/api/v3/user",
			"https://github.example.com/api/v3/user",
		}, seenEndpoints)
		mu.Unlock()

		// Explicit mismatched hostname on GetToken fails closed without returning the GHES PAT.
		_, err = p.GetToken(entCtx, HandlerName, sdkplugin.TokenRequest{
			Hostname: "github.com",
			Settings: hostDefaultSettings,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not authenticated for hostname")
		assert.NotContains(t, err.Error(), "ghp_ghes_enterprise_token")
	})

	t.Run("default-profile PAT login and logout preserve credentials and cache of profile named token", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		mock := NewMockHTTPClient()
		mock.AddResponse(http.StatusOK, User{Login: "token-prof-user", ID: 10, Name: "Token Profile User"})
		mock.AddResponse(http.StatusOK, User{Login: "default-pat-user", ID: 20, Name: "Default PAT User"})
		mock.AddResponse(http.StatusOK, User{Login: "default-pat-user-2", ID: 21, Name: "Default PAT User 2"})

		p, hc, _ := newTestPluginWithPlugintestHost(t, mock)
		defaultCtx := context.Background()
		tokenProfileCtx := auth.WithProfile(context.Background(), "token")

		// Seed credentials and cached tokens under the "token" profile (which shares the
		// "scafctl.auth.github.token." string prefix with the default profile's token cache).
		_, err := p.storeCredentials(tokenProfileCtx, &TokenResponse{
			AccessToken:           "token_prof_at",
			RefreshToken:          "token_prof_rt",
			TokenType:             "bearer",
			Scope:                 "repo read:org",
			ExpiresIn:             3600,
			RefreshTokenExpiresIn: 86400,
		}, []string{"repo", "read:org"}, "sess-token-prof", auth.FlowDeviceCode)
		require.NoError(t, err)

		require.NoError(t, cacheSet(tokenProfileCtx, hc, "expired_extra", &auth.Token{
			AccessToken: "token_prof_expired_cached",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(-time.Hour),
			Flow:        auth.FlowDeviceCode,
			SessionID:   "sess-token-prof",
		}, "token"))

		// 1. Default-profile PAT login clears only default-profile cache entries, keeping the "token" profile intact.
		t.Setenv(EnvGitHubToken, "ghp_default_profile_pat")
		_, err = p.Login(defaultCtx, HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowPAT}, nil)
		require.NoError(t, err)
		t.Setenv(EnvGitHubToken, "")

		tokenStatus, err := p.GetStatus(tokenProfileCtx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, tokenStatus.Authenticated)
		assert.Equal(t, "token-prof-user", tokenStatus.Claims.Subject)

		gotRT, err := p.loadRefreshToken(tokenProfileCtx)
		require.NoError(t, err)
		assert.Equal(t, "token_prof_rt", gotRT)

		gotAT, err := p.loadAccessToken(tokenProfileCtx)
		require.NoError(t, err)
		assert.Equal(t, "token_prof_at", gotAT)

		tokFromTokenProf, err := p.GetToken(tokenProfileCtx, HandlerName, sdkplugin.TokenRequest{})
		require.NoError(t, err)
		assert.Equal(t, "token_prof_at", tokFromTokenProf.AccessToken)

		// Default-profile ListCachedTokens and PurgeExpiredTokens must not view or purge "token" profile entries.
		defaultEntries, err := p.ListCachedTokens(defaultCtx, HandlerName)
		require.NoError(t, err)
		require.Len(t, defaultEntries, 1)
		assert.Equal(t, auth.FlowPAT, defaultEntries[0].Flow)

		purgedDefault, err := p.PurgeExpiredTokens(defaultCtx, HandlerName)
		require.NoError(t, err)
		assert.Equal(t, 0, purgedDefault)

		tokenEntriesBeforeLogout, err := p.ListCachedTokens(tokenProfileCtx, HandlerName)
		require.NoError(t, err)
		assert.Len(t, tokenEntriesBeforeLogout, 3, "refresh token plus active and expired cached access tokens must remain under token profile")

		// 2. Default-profile Logout clears default-profile secrets and cache without touching the "token" profile.
		require.NoError(t, p.Logout(defaultCtx, HandlerName, sdkplugin.LogoutRequest{}))

		defaultStatusAfter, err := p.GetStatus(defaultCtx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.False(t, defaultStatusAfter.Authenticated)

		tokenStatusAfter, err := p.GetStatus(tokenProfileCtx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, tokenStatusAfter.Authenticated)
		assert.Equal(t, "token-prof-user", tokenStatusAfter.Claims.Subject)

		gotRTAfter, err := p.loadRefreshToken(tokenProfileCtx)
		require.NoError(t, err)
		assert.Equal(t, "token_prof_rt", gotRTAfter)

		tokAfterDefaultLogout, err := p.GetToken(tokenProfileCtx, HandlerName, sdkplugin.TokenRequest{})
		require.NoError(t, err)
		assert.Equal(t, "token_prof_at", tokAfterDefaultLogout.AccessToken)

		// 3. Logging out the "token" profile preserves an active default-profile PAT session.
		t.Setenv(EnvGitHubToken, "ghp_default_profile_pat_2")
		_, err = p.Login(defaultCtx, HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowPAT}, nil)
		require.NoError(t, err)
		t.Setenv(EnvGitHubToken, "")

		require.NoError(t, p.Logout(tokenProfileCtx, HandlerName, sdkplugin.LogoutRequest{}))

		tokenStatusCleared, err := p.GetStatus(tokenProfileCtx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.False(t, tokenStatusCleared.Authenticated)

		defaultStatusPreserved, err := p.GetStatus(defaultCtx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, defaultStatusPreserved.Authenticated)
		assert.Equal(t, "default-pat-user-2", defaultStatusPreserved.Claims.Subject)

		defaultTokPreserved, err := p.GetToken(defaultCtx, HandlerName, sdkplugin.TokenRequest{})
		require.NoError(t, err)
		assert.Equal(t, "ghp_default_profile_pat_2", defaultTokPreserved.AccessToken)
	})

	t.Run("secret store write failure rolls back prior session without leaking PAT", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		mock := NewMockHTTPClient()
		mock.AddResponse(http.StatusOK, User{Login: "alice", ID: 1, Name: "Alice"})
		mock.AddResponse(http.StatusOK, User{Login: "pat-bob", ID: 2, Name: "Bob"})

		p, _, fakeHost := newTestPluginWithPlugintestHost(t, mock)
		ctx, logMu, logLines := capturingLoggerContext()

		_, err := p.storeCredentials(ctx, &TokenResponse{
			AccessToken: "alice_oauth_at", RefreshToken: "alice_oauth_rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400,
		}, []string{"repo"}, "sess-alice", auth.FlowInteractive)
		require.NoError(t, err)

		fakeHost.SetSetSecretErrorFunc(func(_ context.Context, name, _ string) error {
			if name == SecretKeyMetadata {
				return errors.New("secret store write denied")
			}
			return nil
		})

		const rawPAT = "ghp_never_echo_this_secret_98765"
		t.Setenv(EnvGitHubToken, rawPAT)

		_, err = p.Login(ctx, HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowPAT}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot persist PAT credentials")
		assert.NotContains(t, err.Error(), rawPAT)

		fakeHost.SetSetSecretErrorFunc(nil)
		t.Setenv(EnvGitHubToken, "")

		// Prior OAuth session must remain intact after rollback.
		gotRT, hasRT := fakeHost.Secret(SecretKeyRefreshToken)
		require.True(t, hasRT)
		assert.Equal(t, "alice_oauth_rt", gotRT)

		st, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, st.Authenticated)
		assert.Equal(t, "alice", st.Claims.Subject)

		logMu.Lock()
		allLogs := strings.Join(*logLines, "\n")
		logMu.Unlock()
		assert.NotContains(t, allLogs, rawPAT)
	})
}

func TestTokenCacheKeys_PlugintestAllFlowsAndRegexPrefixIsolation(t *testing.T) {
	t.Run("all flows persist valid secret names in plugintest FakeHostService without colons", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})

		routingHTTP := &funcHTTPClient{
			postFormFn: func(_ context.Context, endpoint string, data url.Values) (*http.Response, error) {
				if strings.HasSuffix(endpoint, "/login/device/code") {
					return jsonTestResponse(http.StatusOK, DeviceCodeResponse{
						DeviceCode:      "dc-1",
						UserCode:        "ABCD-1234",
						VerificationURI: "https://github.com/login/device",
						ExpiresIn:       900,
						Interval:        5,
					}), nil
				}
				return jsonTestResponse(http.StatusOK, TokenResponse{
					AccessToken:           "oauth_at_" + data.Get("grant_type"),
					RefreshToken:          "oauth_rt",
					TokenType:             "bearer",
					Scope:                 "repo",
					ExpiresIn:             3600,
					RefreshTokenExpiresIn: 86400,
				}), nil
			},
			getFn: func(_ context.Context, endpoint string, _ map[string]string) (*http.Response, error) {
				if strings.HasSuffix(endpoint, "/app") {
					return jsonTestResponse(http.StatusOK, AppInfo{ID: 321, Slug: "cache-app", Name: "Cache App"}), nil
				}
				return jsonTestResponse(http.StatusOK, User{Login: "cache-user", ID: 11, Name: "Cache User"}), nil
			},
			postJSONFn: func(_ context.Context, _ string, _ any, _ map[string]string) (*http.Response, error) {
				return jsonTestResponse(http.StatusCreated, InstallationTokenResponse{
					Token:     "ghs_app_cached_tok",
					ExpiresAt: time.Now().Add(55 * time.Minute),
				}), nil
			},
		}

		p, _, fakeHost := newTestPluginWithPlugintestHost(t, routingHTTP)
		p.mu.Lock()
		p.clock = clock.Mock{}
		p.mu.Unlock()

		// 1. Device-code login + refresh GetToken under profile "dev".
		devCtx := auth.WithProfile(context.Background(), "dev")
		_, err = p.Login(devCtx, HandlerName, sdkplugin.LoginRequest{
			Flow:    auth.FlowDeviceCode,
			Timeout: 5 * time.Second,
		}, nil)
		require.NoError(t, err)

		devTok, err := p.GetToken(devCtx, HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		require.NoError(t, err)
		assert.NotEmpty(t, devTok.AccessToken)

		devCached, err := p.ListCachedTokens(devCtx, HandlerName)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(devCached), 2)

		// 2. GitHub App login + cached GetToken + ForceRefresh renewal under profile "app".
		appCtx := auth.WithProfile(context.Background(), "app")
		appSettingsRaw, err := json.Marshal(map[string]any{
			"appId":          321,
			"installationId": 654,
			"privateKey":     string(pemBytes),
		})
		require.NoError(t, err)
		appSettings := map[string]json.RawMessage{HandlerName: appSettingsRaw}

		_, err = p.Login(appCtx, HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowGitHubApp,
			Settings: appSettings,
		}, nil)
		require.NoError(t, err)

		appTok1, err := p.GetToken(appCtx, HandlerName, sdkplugin.TokenRequest{Settings: appSettings})
		require.NoError(t, err)
		assert.Equal(t, "ghs_app_cached_tok", appTok1.AccessToken)

		appTok2, err := p.GetToken(appCtx, HandlerName, sdkplugin.TokenRequest{ForceRefresh: true, Settings: appSettings})
		require.NoError(t, err)
		assert.Equal(t, "ghs_app_cached_tok", appTok2.AccessToken)

		appCached, err := p.ListCachedTokens(appCtx, HandlerName)
		require.NoError(t, err)
		require.Len(t, appCached, 1)
		assert.Equal(t, auth.FlowGitHubApp, appCached[0].Flow)

		// 3. PAT login + ambient PAT GetToken under profile "patprof".
		patCtx := auth.WithProfile(context.Background(), "patprof")
		t.Setenv(EnvGitHubToken, "ghp_pat_prof_1")
		_, err = p.Login(patCtx, HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowPAT}, nil)
		require.NoError(t, err)

		t.Setenv(EnvGitHubToken, "ghp_pat_prof_ambient")
		ambTok, err := p.GetToken(patCtx, HandlerName, sdkplugin.TokenRequest{})
		require.NoError(t, err)
		assert.Equal(t, "ghp_pat_prof_ambient", ambTok.AccessToken)
		t.Setenv(EnvGitHubToken, "")

		patCached, err := p.ListCachedTokens(patCtx, HandlerName)
		require.NoError(t, err)
		assert.Len(t, patCached, 2, "both persisted session token and ambient PAT cache entry must be stored and listed")

		for secretName := range fakeHost.Secrets() {
			assert.NotContains(t, secretName, ":", "secret name %q must not contain ':'", secretName)
			require.NoError(t, sdkplugin.ValidateHostSecretName(secretName))
		}
	})

	t.Run("ListSecretsByPrefix matches only exact profile token prefix and ignores regex metacharacter lookalikes", func(t *testing.T) {
		_, hc, fakeHost := newTestPluginWithPlugintestHost(t, nil)
		ctx := context.Background()

		// Seed lookalike keys that would match an unescaped '.' or unanchored regex.
		expiredPayload := `{"accessToken":"keep_me","tokenType":"Bearer","expiresAt":"2020-01-01T00:00:00Z"}`
		require.NoError(t, fakeHost.PutSecret("scafctl.auth.github.tokenX_lookalike", expiredPayload))
		require.NoError(t, fakeHost.PutSecret("other.scafctl.auth.github.token.lookalike", expiredPayload))

		validTok := &auth.Token{
			AccessToken: "active_cached",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(time.Hour),
			Flow:        auth.FlowPAT,
		}
		expiredTok := &auth.Token{
			AccessToken: "expired_cached",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(-time.Hour),
			Flow:        auth.FlowDeviceCode,
		}
		require.NoError(t, cacheSet(ctx, hc, "active_entry", validTok, ""))
		require.NoError(t, cacheSet(ctx, hc, "expired_entry", expiredTok, ""))

		entries, err := cacheListEntries(ctx, hc, "")
		require.NoError(t, err)
		assert.Len(t, entries, 2, "only entries under scafctl.auth.github.token. may be listed")

		purged, err := cachePurgeExpired(ctx, hc, "")
		require.NoError(t, err)
		assert.Equal(t, 1, purged, "only expired entry under exact prefix may be purged")

		require.NoError(t, cacheClearErr(ctx, hc, ""))

		// Both lookalike secrets outside the exact prefix must remain untouched.
		_, hasUnescapedDot := fakeHost.Secret("scafctl.auth.github.tokenX_lookalike")
		_, hasUnanchored := fakeHost.Secret("other.scafctl.auth.github.token.lookalike")
		assert.True(t, hasUnescapedDot, "unescaped '.' lookalike must not be matched or deleted")
		assert.True(t, hasUnanchored, "unanchored prefix lookalike must not be matched or deleted")

		// Default-profile cacheGet and cacheSet reject keys reserved by the "token" profile namespace.
		for _, reserved := range []string{"", "refresh_token", "access_token", "metadata", "app_metadata", "token.nested"} {
			err = cacheSet(ctx, hc, reserved, validTok, "")
			require.Error(t, err, "cacheSet must reject reserved default-profile suffix %q", reserved)
			got, gErr := cacheGet(ctx, hc, reserved, "")
			require.NoError(t, gErr)
			assert.Nil(t, got, "cacheGet must ignore reserved default-profile suffix %q", reserved)
		}
	})

	t.Run("ForceRefresh revalidates non-PAT stored access tokens without refresh token and fails on 401", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		mock := NewMockHTTPClient()
		mock.AddResponse(http.StatusOK, User{Login: "oauth-no-rt", ID: 55})
		mock.AddResponse(http.StatusOK, User{Login: "oauth-no-rt", ID: 55})
		mock.AddResponse(http.StatusUnauthorized, map[string]string{"message": "Bad credentials"})

		p, _, _ := newTestPluginWithPlugintestHost(t, mock)
		ctx := context.Background()

		_, err := p.storeCredentials(ctx, &TokenResponse{
			AccessToken: "gho_non_expiring_oauth_tok",
			TokenType:   "bearer",
			Scope:       "repo read:user",
		}, []string{"repo", "read:user"}, "sess-oauth-no-rt", auth.FlowInteractive)
		require.NoError(t, err)

		tokOk, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		require.NoError(t, err)
		assert.Equal(t, "gho_non_expiring_oauth_tok", tokOk.AccessToken)
		assert.Equal(t, "repo read:user", tokOk.Scope)

		_, err = p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access token validation failed")
		assert.Contains(t, err.Error(), "401")
		assert.NotContains(t, err.Error(), "gho_non_expiring_oauth_tok")
	})

	t.Run("fakeHostService rejects invalid secret names and invalid regex patterns", func(t *testing.T) {
		fake := newFakeHostService()
		ctx := context.Background()

		invalidNames := []string{
			"",
			"scafctl.auth.github.token.abc:_github",
			"scafctl/slash/not/allowed",
			"scafctl..traversal",
			".leading_dot",
			strings.Repeat("a", 256),
		}
		for _, bad := range invalidNames {
			_, err := fake.SetSecret(ctx, &proto.SetSecretRequest{Name: bad, Value: "v"})
			require.Error(t, err, "SetSecret must reject %q", bad)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))

			_, err = fake.GetSecret(ctx, &proto.GetSecretRequest{Name: bad})
			require.Error(t, err, "GetSecret must reject %q", bad)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))

			_, err = fake.DeleteSecret(ctx, &proto.DeleteSecretRequest{Name: bad})
			require.Error(t, err, "DeleteSecret must reject %q", bad)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		}

		_, err := fake.ListSecrets(ctx, &proto.ListSecretsRequest{Pattern: "[invalid-regex"})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})
}

func TestDevicePoll_PostResponseWaitSlowDownIntervalAndDefaultInteractiveFlow(t *testing.T) {
	t.Run("waits interval plus safety margin after each HTTP response and honors server slow_down interval", func(t *testing.T) {
		recClk := &recordingClock{}
		var pollAttempt int
		httpMock := &funcHTTPClient{
			postFormFn: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
				pollAttempt++
				recClk.recordEvent("http_done")
				switch pollAttempt {
				case 1:
					return jsonTestResponse(http.StatusOK, TokenErrorResponse{
						Error: "authorization_pending",
					}), nil
				case 2:
					// Server supplies interval=15 (> current 5s + 5s slowDownIncr = 10s).
					return jsonTestResponse(http.StatusOK, TokenErrorResponse{
						Error:    "slow_down",
						Interval: 15,
					}), nil
				case 3:
					// Server supplies interval=10 (< current 15s + 5s slowDownIncr = 20s), so 20s wins.
					return jsonTestResponse(http.StatusOK, TokenErrorResponse{
						Error:    "slow_down",
						Interval: 10,
					}), nil
				default:
					return jsonTestResponse(http.StatusOK, TokenResponse{
						AccessToken: "ghu_polled_token",
						TokenType:   "bearer",
					}), nil
				}
			},
		}

		p := newTestPlugin(httpMock)
		p.mu.Lock()
		p.clock = recClk
		p.mu.Unlock()

		tok, err := p.pollForToken(context.Background(), &DeviceCodeResponse{
			DeviceCode: "dc-spacing",
			Interval:   5,
		})
		require.NoError(t, err)
		assert.Equal(t, "ghu_polled_token", tok.AccessToken)

		// Expect post-response sleeps with +1s safety margin:
		// initial: 5s + 1s = 6s
		// after authorization_pending: 5s + 1s = 6s
		// after slow_down(interval=15): max(15s, 10s) + 1s = 16s
		// after slow_down(interval=10): max(10s, 20s) + 1s = 21s
		assert.Equal(t, []time.Duration{
			6 * time.Second,
			6 * time.Second,
			16 * time.Second,
			21 * time.Second,
		}, recClk.sleeps)

		assert.Equal(t, []string{
			"sleep:6s",
			"http_done",
			"sleep:6s",
			"http_done",
			"sleep:16s",
			"http_done",
			"sleep:21s",
			"http_done",
		}, recClk.events)
	})

	t.Run("retries transient network error and fails closed on malformed JSON or HTTP 502", func(t *testing.T) {
		recClk := &recordingClock{}
		var call int
		httpMock := &funcHTTPClient{
			postFormFn: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
				call++
				if call == 1 {
					return nil, errors.New("temporary connection reset")
				}
				return jsonTestResponse(http.StatusOK, TokenResponse{
					AccessToken: "ghu_after_retry",
					TokenType:   "bearer",
				}), nil
			},
		}
		p := newTestPlugin(httpMock)
		p.mu.Lock()
		p.clock = recClk
		p.mu.Unlock()

		tok, err := p.pollForToken(context.Background(), &DeviceCodeResponse{DeviceCode: "dc-retry", Interval: 5})
		require.NoError(t, err)
		assert.Equal(t, "ghu_after_retry", tok.AccessToken)
		assert.Equal(t, []time.Duration{6 * time.Second, 6 * time.Second}, recClk.sleeps)

		// Non-200 responses with empty JSON or non-JSON HTML bodies fail immediately with status code.
		for _, bodyText := range []string{`{}`, `<html>502 Bad Gateway</html>`} {
			badStatusHTTP := &funcHTTPClient{
				postFormFn: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusBadGateway,
						Body:       io.NopCloser(strings.NewReader(bodyText)),
					}, nil
				},
			}
			pBad := newTestPlugin(badStatusHTTP)
			pBad.mu.Lock()
			pBad.clock = clock.Mock{}
			pBad.mu.Unlock()
			_, err = pBad.pollForToken(context.Background(), &DeviceCodeResponse{DeviceCode: "dc-502", Interval: 5})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "status 502")
		}

		// HTTP 200 with malformed JSON fails immediately with parse error.
		malformedHTTP := &funcHTTPClient{
			postFormFn: func(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`not-json`)),
				}, nil
			},
		}
		pMalformed := newTestPlugin(malformedHTTP)
		pMalformed.mu.Lock()
		pMalformed.clock = clock.Mock{}
		pMalformed.mu.Unlock()
		_, err = pMalformed.pollForToken(context.Background(), &DeviceCodeResponse{DeviceCode: "dc-malformed", Interval: 5})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse token response")
	})

	t.Run("bare login selects FlowInteractive via DetectAvailableFlows and auto-opens verification URI", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		var pollCount int
		httpMock := &funcHTTPClient{
			postFormFn: func(_ context.Context, endpoint string, _ url.Values) (*http.Response, error) {
				if strings.HasSuffix(endpoint, "/login/device/code") {
					return jsonTestResponse(http.StatusOK, DeviceCodeResponse{
						DeviceCode:      "dc-bare",
						UserCode:        "WDJB-MJHT",
						VerificationURI: "https://github.com/login/device",
						ExpiresIn:       900,
						Interval:        5,
					}), nil
				}
				pollCount++
				if pollCount == 1 {
					return jsonTestResponse(http.StatusOK, TokenErrorResponse{Error: "authorization_pending"}), nil
				}
				return jsonTestResponse(http.StatusOK, TokenResponse{
					AccessToken:           "ghu_bare_interactive",
					RefreshToken:          "ghr_bare_interactive",
					TokenType:             "bearer",
					Scope:                 "repo",
					ExpiresIn:             28800,
					RefreshTokenExpiresIn: 15897600,
				}), nil
			},
			getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
				return jsonTestResponse(http.StatusOK, User{Login: "interactive-octocat", ID: 88, Name: "Interactive Octocat"}), nil
			},
		}

		p, _, _ := newTestPluginWithPlugintestHost(t, httpMock)
		p.mu.Lock()
		p.clock = clock.Mock{}
		p.mu.Unlock()

		var openedURL string
		p.openBrowser = func(_ context.Context, rawURL string) error {
			openedURL = rawURL
			return nil
		}

		flows, err := p.DetectAvailableFlows(context.Background(), HandlerName)
		require.NoError(t, err)
		var selectedFlow auth.Flow
		for _, f := range flows {
			if f.Available {
				selectedFlow = f.Flow
				break
			}
		}
		require.Equal(t, auth.FlowInteractive, selectedFlow)

		resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:    selectedFlow,
			Timeout: 10 * time.Second,
		}, nil)
		require.NoError(t, err)
		assert.Equal(t, "interactive-octocat", resp.Claims.Subject)
		assert.Equal(t, "https://github.com/login/device", openedURL)
		assert.Equal(t, 2, pollCount)
	})
}

func TestPATForcedValidation_InvalidationTransientAndConcurrency(t *testing.T) {
	t.Run("401 forced validation invalidates persisted credentials and cache while transient errors preserve them", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		var step int
		var mu sync.Mutex
		httpMock := &funcHTTPClient{
			getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
				mu.Lock()
				step++
				cur := step
				mu.Unlock()
				switch cur {
				case 1:
					return jsonTestResponse(http.StatusOK, User{Login: "pat-user", ID: 1}), nil
				case 2:
					return jsonTestResponse(http.StatusBadGateway, map[string]string{"message": "Bad gateway"}), nil
				case 3:
					return nil, errors.New("temporary network timeout")
				case 4:
					return jsonTestResponse(http.StatusUnauthorized, map[string]string{"message": "Bad credentials"}), nil
				case 5:
					return jsonTestResponse(http.StatusOK, User{Login: "env-user", ID: 2}), nil
				default:
					return jsonTestResponse(http.StatusUnauthorized, map[string]string{"message": "Bad credentials"}), nil
				}
			},
		}

		p, _, _ := newTestPluginWithPlugintestHost(t, httpMock)
		ctx := context.Background()

		const storedPAT = "ghp_lifecycle_pat_secret"
		t.Setenv(EnvGHToken, storedPAT)
		_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowPAT}, nil)
		require.NoError(t, err)
		t.Setenv(EnvGHToken, "")

		// Transient 502 and network failures fail ForceRefresh without invalidating stored credentials.
		_, err = p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "502")

		_, err = p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "temporary network timeout")

		stAfterTransient, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, stAfterTransient.Authenticated)

		tokAfterTransient, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
		require.NoError(t, err)
		assert.Equal(t, storedPAT, tokAfterTransient.AccessToken)

		// HTTP 401 on ForceRefresh invalidates stored credentials and cache.
		_, err = p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PAT validation failed")
		assert.Contains(t, err.Error(), "401")
		assert.NotContains(t, err.Error(), storedPAT)

		stAfter401, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.False(t, stAfter401.Authenticated)

		_, err = p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not authenticated")

		cachedAfter401, err := p.ListCachedTokens(ctx, HandlerName)
		require.NoError(t, err)
		assert.Empty(t, cachedAfter401)

		// Ambient environment PAT also evicts its cache entry on forced 401 so ordinary GetToken re-validates.
		t.Setenv(EnvGHToken, "ghp_env_revoked_later")
		envTok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
		require.NoError(t, err)
		assert.Equal(t, "ghp_env_revoked_later", envTok.AccessToken)

		_, err = p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "401")

		_, err = p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "401")
	})

	t.Run("concurrent Logout while forced validation is blocked returns authentication error", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		validationEntered := make(chan struct{})
		releaseValidation := make(chan struct{})
		var enterOnce sync.Once
		var calls int
		var mu sync.Mutex

		httpMock := &funcHTTPClient{
			getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
				mu.Lock()
				calls++
				n := calls
				mu.Unlock()
				if n == 2 {
					enterOnce.Do(func() { close(validationEntered) })
					<-releaseValidation
				}
				return jsonTestResponse(http.StatusOK, User{Login: "logout-race-user", ID: 1}), nil
			},
		}

		p, _, _ := newTestPluginWithPlugintestHost(t, httpMock)
		ctx := context.Background()

		t.Setenv(EnvGHToken, "ghp_before_logout")
		_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowPAT}, nil)
		require.NoError(t, err)
		t.Setenv(EnvGHToken, "")

		errCh := make(chan error, 1)
		go func() {
			_, fErr := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
			errCh <- fErr
		}()

		<-validationEntered
		require.NoError(t, p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{}))
		close(releaseValidation)

		forcedErr := <-errCh
		require.Error(t, forcedErr)
		assert.Contains(t, forcedErr.Error(), "not authenticated")

		st, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.False(t, st.Authenticated)

		_, err = p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
		require.Error(t, err)
	})

	t.Run("concurrent replacement Login while forced validation is blocked rejects stale token and survives stale 401", func(t *testing.T) {
		for _, blockedStatus := range []int{http.StatusOK, http.StatusUnauthorized} {
			name := "blocked_200"
			if blockedStatus == http.StatusUnauthorized {
				name = "blocked_401"
			}
			t.Run(name, func(t *testing.T) {
				clearGitHubCredentialEnv(t)

				validationEntered := make(chan struct{})
				releaseValidation := make(chan struct{})
				var enterOnce sync.Once

				// Intercept only the second call for ghp_old_pat (the ForceRefresh call after Login).
				var oldCalls int
				var oldMu sync.Mutex
				httpMock := &funcHTTPClient{
					getFn: func(_ context.Context, _ string, headers map[string]string) (*http.Response, error) {
						if headers["Authorization"] == "Bearer ghp_new_pat" {
							return jsonTestResponse(http.StatusOK, User{Login: "new-user", ID: 2}), nil
						}
						oldMu.Lock()
						oldCalls++
						n := oldCalls
						oldMu.Unlock()
						if n == 2 {
							enterOnce.Do(func() { close(validationEntered) })
							<-releaseValidation
							if blockedStatus == http.StatusUnauthorized {
								return jsonTestResponse(http.StatusUnauthorized, map[string]string{"message": "Bad credentials"}), nil
							}
						}
						return jsonTestResponse(http.StatusOK, User{Login: "old-user", ID: 1}), nil
					},
				}

				p, _, _ := newTestPluginWithPlugintestHost(t, httpMock)
				ctx := context.Background()

				t.Setenv(EnvGHToken, "ghp_old_pat")
				_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowPAT}, nil)
				require.NoError(t, err)
				t.Setenv(EnvGHToken, "")

				errCh := make(chan error, 1)
				go func() {
					_, fErr := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
					errCh <- fErr
				}()

				<-validationEntered

				// Complete replacement Login with ghp_new_pat while old ForceRefresh is still in flight.
				t.Setenv(EnvGHToken, "ghp_new_pat")
				_, err = p.Login(ctx, HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowPAT}, nil)
				require.NoError(t, err)
				t.Setenv(EnvGHToken, "")

				close(releaseValidation)
				forcedErr := <-errCh
				require.Error(t, forcedErr)
				assert.Contains(t, forcedErr.Error(), "not authenticated")

				// Replacement session remains authenticated and ordinary GetToken returns ghp_new_pat.
				st, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
				require.NoError(t, err)
				assert.True(t, st.Authenticated)
				assert.Equal(t, "new-user", st.Claims.Subject)

				tok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
				require.NoError(t, err)
				assert.Equal(t, "ghp_new_pat", tok.AccessToken)
			})
		}
	})

	t.Run("storeCredentials fails on 401 from /user and preserves issuer fallback on transient errors", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		mock := NewMockHTTPClient()
		mock.AddResponse(http.StatusUnauthorized, map[string]string{"message": "Bad credentials"})
		mock.AddResponse(http.StatusBadGateway, map[string]string{"message": "Bad gateway"})

		p, _, _ := newTestPluginWithPlugintestHost(t, mock)
		ctx := context.Background()

		_, err := p.storeCredentials(ctx, &TokenResponse{
			AccessToken: "gho_rejected_401",
			TokenType:   "bearer",
		}, []string{"repo"}, "sess-401", auth.FlowInteractive)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access token validation failed")

		claims, err := p.storeCredentials(ctx, &TokenResponse{
			AccessToken: "gho_transient_502_ok",
			TokenType:   "bearer",
		}, []string{"repo"}, "sess-502", auth.FlowInteractive)
		require.NoError(t, err)
		assert.Equal(t, DefaultHostname, claims.Issuer)
	})

	t.Run("ambient PAT serialization, matching stored session 401 invalidation, and continuity read error surfacing", func(t *testing.T) {
		clearGitHubCredentialEnv(t)

		// 1. Overlapping ordinary 200 and forced 401 ambient PAT requests serialize so 401 leaves cache evicted.
		call1Entered := make(chan struct{})
		releaseCall1 := make(chan struct{})
		var enterOnce sync.Once
		var calls int
		var mu sync.Mutex
		overlapHTTP := &funcHTTPClient{
			getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
				mu.Lock()
				calls++
				n := calls
				mu.Unlock()
				if n == 1 {
					enterOnce.Do(func() { close(call1Entered) })
					<-releaseCall1
					return jsonTestResponse(http.StatusOK, User{Login: "amb-user", ID: 1}), nil
				}
				return jsonTestResponse(http.StatusUnauthorized, map[string]string{"message": "Bad credentials"}), nil
			},
		}
		pAmb, _, fakeAmb := newTestPluginWithPlugintestHost(t, overlapHTTP)
		ctx := context.Background()
		t.Setenv(EnvGHToken, "ghp_overlap_amb")

		ordErrCh := make(chan error, 1)
		go func() {
			_, err := pAmb.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
			ordErrCh <- err
		}()
		<-call1Entered

		forcedErrCh := make(chan error, 1)
		go func() {
			_, err := pAmb.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
			forcedErrCh <- err
		}()
		close(releaseCall1)

		require.NoError(t, <-ordErrCh)
		require.Error(t, <-forcedErrCh)
		assert.Empty(t, fakeAmb.Secrets(), "forced 401 must run after in-flight 200 and evict the ambient cache entry")

		// 2. Forced 401 with GH_TOKEN still set after PAT Login invalidates the matching stored session while preserving unrelated sessions.
		revoked := false
		var revMu sync.Mutex
		samePATHTTP := &funcHTTPClient{
			getFn: func(_ context.Context, _ string, _ map[string]string) (*http.Response, error) {
				revMu.Lock()
				isRev := revoked
				revMu.Unlock()
				if !isRev {
					return jsonTestResponse(http.StatusOK, User{Login: "same-pat-user", ID: 2}), nil
				}
				return jsonTestResponse(http.StatusUnauthorized, map[string]string{"message": "Bad credentials"}), nil
			},
		}
		pSame, _, _ := newTestPluginWithPlugintestHost(t, samePATHTTP)
		workCtx := auth.WithProfile(ctx, "work")

		t.Setenv(EnvGHToken, "ghp_other_unrelated")
		_, err := pSame.Login(workCtx, HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowPAT}, nil)
		require.NoError(t, err)

		t.Setenv(EnvGHToken, "ghp_logged_in_and_ambient")
		_, err = pSame.Login(ctx, HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowPAT}, nil)
		require.NoError(t, err)

		revMu.Lock()
		revoked = true
		revMu.Unlock()

		// GH_TOKEN is still set when ForceRefresh receives 401.
		_, err = pSame.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "401")

		// After unsetting GH_TOKEN, the matching stored session and its cache are also gone, while "work" is untouched.
		t.Setenv(EnvGHToken, "")
		st, err := pSame.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.False(t, st.Authenticated)

		_, err = pSame.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not authenticated")

		workSt, err := pSame.GetStatus(workCtx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, workSt.Authenticated)

		// 3. Continuity read error during post-401 cleanup is surfaced directly instead of discarded.
		fake := newFakeHostService()
		revMu.Lock()
		revoked = false
		revMu.Unlock()
		pCont := newTestPluginWithHost(samePATHTTP, fake)
		t.Setenv(EnvGHToken, "ghp_cont_surface")
		_, err = pCont.Login(ctx, HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowPAT}, nil)
		require.NoError(t, err)
		t.Setenv(EnvGHToken, "")

		revMu.Lock()
		revoked = true
		revMu.Unlock()
		var metaReads int
		fake.mu.Lock()
		fake.getSecretFunc = func(_ context.Context, name string) error {
			if name == SecretKeyMetadata {
				metaReads++
				if metaReads == 2 {
					return errors.New("continuity metadata read I/O failure")
				}
			}
			return nil
		}
		fake.mu.Unlock()

		_, err = pCont.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{ForceRefresh: true})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "401")
		assert.Contains(t, err.Error(), "continuity metadata read I/O failure")
	})
}
