package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"testing"
	"time"

	"os"
	"strings"

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oakwood-commons/scafctl-plugin-auth-github/internal/clock"
)

func newTestPluginWithHost(httpClient HTTPClient, fakeHost *fakeHostService) *Plugin {
	hc := newFakeHostClient(fakeHost)
	p := &Plugin{
		cachedHostClient: hc,
		openBrowser: func(_ context.Context, _ string) error {
			return nil
		},
	}
	_ = p.ConfigureAuthHandler(
		sdkplugin.WithHostClient(context.Background(), hc),
		HandlerName,
		sdkplugin.ProviderConfig{BinaryName: "scafctl"},
	)
	p.cachedHostClient = hc
	if httpClient != nil {
		p.httpClient = httpClient
	}
	return p
}

func discardLogger() logr.Logger {
	return logr.FromContextOrDiscard(context.Background())
}

func TestConfigureAuthHandler_UnknownHandler(t *testing.T) {
	p := &Plugin{}
	err := p.ConfigureAuthHandler(context.Background(), "bogus", sdkplugin.ProviderConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown handler")
}

func TestCacheGetSetPurge(t *testing.T) {
	fake := newFakeHostService()
	hc := newFakeHostClient(fake)
	ctx := context.Background()
	token, err := cacheGet(ctx, hc, "testkey")
	require.NoError(t, err)
	assert.Nil(t, token)
	tok := &auth.Token{AccessToken: "abc", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour), Scope: "repo", Flow: auth.FlowDeviceCode, SessionID: "sess1"}
	require.NoError(t, cacheSet(ctx, hc, "testkey", tok))
	got, err := cacheGet(ctx, hc, "testkey")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "abc", got.AccessToken)
	count, err := cachePurgeExpired(ctx, hc)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
	expired := &auth.Token{AccessToken: "old", TokenType: "Bearer", ExpiresAt: time.Now().Add(-time.Hour)}
	require.NoError(t, cacheSet(ctx, hc, "expired_key", expired))
	count, err = cachePurgeExpired(ctx, hc)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestCacheClear(t *testing.T) {
	fake := newFakeHostService()
	hc := newFakeHostClient(fake)
	ctx := context.Background()
	tok := &auth.Token{AccessToken: "x", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, cacheSet(ctx, hc, "k1", tok))
	require.NoError(t, cacheSet(ctx, hc, "k2", tok))
	cacheClear(ctx, discardLogger(), hc)
	g1, _ := cacheGet(ctx, hc, "k1")
	g2, _ := cacheGet(ctx, hc, "k2")
	assert.Nil(t, g1)
	assert.Nil(t, g2)
}

func TestCacheListEntries(t *testing.T) {
	fake := newFakeHostService()
	hc := newFakeHostClient(fake)
	ctx := context.Background()
	tok := &auth.Token{AccessToken: "tok1", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour), Flow: auth.FlowDeviceCode}
	require.NoError(t, cacheSet(ctx, hc, "entry1", tok))
	entries, err := cacheListEntries(ctx, hc)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, HandlerName, entries[0].Handler)
}

func TestCacheGetCorruptData(t *testing.T) {
	fake := newFakeHostService()
	hc := newFakeHostClient(fake)
	require.NoError(t, hc.SetSecret(context.Background(), SecretKeyTokenPrefix+"corrupt", "not-json"))
	_, err := cacheGet(context.Background(), hc, "corrupt")
	assert.Error(t, err)
}

func TestStoreAndLoadCredentials(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, User{Login: "octocat", ID: 1, Name: "Octocat"})
	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)
	ctx := context.Background()
	tokenResp := &TokenResponse{AccessToken: "at_123", RefreshToken: "rt_456", TokenType: "bearer", Scope: "repo", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400}
	claims, err := p.storeCredentials(ctx, tokenResp, []string{"repo"}, "sess-abc")
	require.NoError(t, err)
	assert.Equal(t, "octocat", claims.Subject)
	rt, err := p.loadRefreshToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, "rt_456", rt)
	at, err := p.loadAccessToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, "at_123", at)
	meta, err := p.loadMetadata(ctx)
	require.NoError(t, err)
	assert.Equal(t, "octocat", meta.Claims.Subject)
	assert.Equal(t, "sess-abc", meta.SessionID)
}

func TestLoadMetadataCorrupt(t *testing.T) {
	fake := newFakeHostService()
	p := newTestPluginWithHost(nil, fake)
	hc := newFakeHostClient(fake)
	require.NoError(t, hc.SetSecret(context.Background(), SecretKeyMetadata, "bad"))
	_, err := p.loadMetadata(context.Background())
	assert.Error(t, err)
}

func TestRefreshAccessToken_Success(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, TokenResponse{AccessToken: "new_at", TokenType: "bearer", Scope: "repo", ExpiresIn: 3600})
	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)
	tok, err := p.refreshAccessToken(context.Background(), "old_rt", "cid")
	require.NoError(t, err)
	assert.Equal(t, "new_at", tok.AccessToken)
}

func TestRefreshAccessToken_EmptyToken(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, TokenResponse{})
	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)
	_, err := p.refreshAccessToken(context.Background(), "old_rt", "cid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired or revoked")
}

func TestRefreshAccessToken_RotatesToken(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, TokenResponse{AccessToken: "new_at", RefreshToken: "new_rt", TokenType: "bearer", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400})
	mock.AddResponse(200, User{Login: "user1", ID: 1, Name: "User"})
	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)
	ctx := context.Background()
	meta := &TokenMetadata{Claims: &auth.Claims{Subject: "user1"}, Hostname: DefaultHostname, ClientID: DefaultClientID, Scopes: []string{"repo"}, SessionID: "s1"}
	metaBytes, _ := json.Marshal(meta)
	hc := newFakeHostClient(fake)
	require.NoError(t, hc.SetSecret(ctx, SecretKeyMetadata, string(metaBytes)))
	tok, err := p.refreshAccessToken(ctx, "old_rt", "cid")
	require.NoError(t, err)
	assert.Equal(t, "new_at", tok.AccessToken)
	rt, _ := p.loadRefreshToken(ctx)
	assert.Equal(t, "new_rt", rt)
}

func TestRefreshAccessToken_HTTPError(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddError(fmt.Errorf("network error"))
	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)
	_, err := p.refreshAccessToken(context.Background(), "rt", "cid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "network error")
}

func TestMintToken_NoRefreshToken(t *testing.T) {
	fake := newFakeHostService()
	p := newTestPluginWithHost(nil, fake)
	_, err := p.mintToken(context.Background())
	assert.Contains(t, err.Error(), "not authenticated")
}

func TestMintToken_NoMetadata(t *testing.T) {
	fake := newFakeHostService()
	p := newTestPluginWithHost(nil, fake)
	hc := newFakeHostClient(fake)
	_ = hc.SetSecret(context.Background(), SecretKeyRefreshToken, "rt")
	_, err := p.mintToken(context.Background())
	assert.Contains(t, err.Error(), "failed to load metadata")
}

func TestMintToken_MissingClientID(t *testing.T) {
	fake := newFakeHostService()
	p := newTestPluginWithHost(nil, fake)
	hc := newFakeHostClient(fake)
	ctx := context.Background()
	_ = hc.SetSecret(ctx, SecretKeyRefreshToken, "rt")
	meta := &TokenMetadata{Claims: &auth.Claims{Subject: "u"}}
	mb, _ := json.Marshal(meta)
	_ = hc.SetSecret(ctx, SecretKeyMetadata, string(mb))
	_, err := p.mintToken(ctx)
	assert.Contains(t, err.Error(), "missing client ID")
}

func TestGetToken_CachedAccessToken(t *testing.T) {
	fake := newFakeHostService()
	p := newTestPluginWithHost(nil, fake)
	t.Setenv(EnvGitHubToken, "")
	t.Setenv(EnvGHToken, "")
	hc := newFakeHostClient(fake)
	_ = hc.SetSecret(context.Background(), SecretKeyAccessToken, "stored_at")
	resp, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{})
	require.NoError(t, err)
	assert.Equal(t, "stored_at", resp.AccessToken)
}

func TestGetToken_PAT(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, User{Login: "pat_user", ID: 42})
	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)
	t.Setenv(EnvGitHubToken, "ghp_test_pat")
	t.Setenv(EnvGHToken, "")
	resp, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{})
	require.NoError(t, err)
	assert.Equal(t, "ghp_test_pat", resp.AccessToken)
	assert.Equal(t, auth.FlowPAT, resp.Flow)
}

func TestLogout_WithHostClient(t *testing.T) {
	fake := newFakeHostService()
	p := newTestPluginWithHost(nil, fake)
	hc := newFakeHostClient(fake)
	ctx := context.Background()
	_ = hc.SetSecret(ctx, SecretKeyRefreshToken, "rt")
	_ = hc.SetSecret(ctx, SecretKeyAccessToken, "at")
	_ = hc.SetSecret(ctx, SecretKeyMetadata, "meta")
	require.NoError(t, p.Logout(ctx, HandlerName))
	_, found, _ := hc.GetSecret(ctx, SecretKeyRefreshToken)
	assert.False(t, found)
}

func TestGetStatus_StoredCredentials(t *testing.T) {
	fake := newFakeHostService()
	p := newTestPluginWithHost(nil, fake)
	t.Setenv(EnvGitHubToken, "")
	t.Setenv(EnvGHToken, "")
	hc := newFakeHostClient(fake)
	ctx := context.Background()
	_ = hc.SetSecret(ctx, SecretKeyRefreshToken, "rt")
	meta := &TokenMetadata{Claims: &auth.Claims{Subject: "stored_user"}, RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour), LastRefresh: time.Now(), Hostname: DefaultHostname, ClientID: DefaultClientID, Scopes: []string{"repo"}}
	mb, _ := json.Marshal(meta)
	_ = hc.SetSecret(ctx, SecretKeyMetadata, string(mb))
	status, err := p.GetStatus(ctx, HandlerName)
	require.NoError(t, err)
	assert.True(t, status.Authenticated)
	assert.Equal(t, "stored_user", status.Claims.Subject)
}

func TestGetStatus_ExpiredSession(t *testing.T) {
	fake := newFakeHostService()
	p := newTestPluginWithHost(nil, fake)
	t.Setenv(EnvGitHubToken, "")
	t.Setenv(EnvGHToken, "")
	hc := newFakeHostClient(fake)
	ctx := context.Background()
	_ = hc.SetSecret(ctx, SecretKeyRefreshToken, "rt")
	meta := &TokenMetadata{Claims: &auth.Claims{Subject: "exp"}, RefreshTokenExpiresAt: time.Now().Add(-time.Hour), LastRefresh: time.Now().Add(-25 * time.Hour), Hostname: DefaultHostname, ClientID: DefaultClientID}
	mb, _ := json.Marshal(meta)
	_ = hc.SetSecret(ctx, SecretKeyMetadata, string(mb))
	status, err := p.GetStatus(ctx, HandlerName)
	require.NoError(t, err)
	assert.False(t, status.Authenticated)
	assert.Equal(t, "session expired", status.Reason)
}

func TestListCachedTokens_WithTokens(t *testing.T) {
	fake := newFakeHostService()
	p := newTestPluginWithHost(nil, fake)
	hc := newFakeHostClient(fake)
	ctx := context.Background()
	_ = hc.SetSecret(ctx, SecretKeyRefreshToken, "rt")
	meta := &TokenMetadata{Claims: &auth.Claims{Subject: "u"}, RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour), LastRefresh: time.Now(), SessionID: "s1"}
	mb, _ := json.Marshal(meta)
	_ = hc.SetSecret(ctx, SecretKeyMetadata, string(mb))
	tok := &auth.Token{AccessToken: "at", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}
	_ = cacheSet(ctx, hc, "somekey", tok)
	results, err := p.ListCachedTokens(ctx, HandlerName)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 2)
}

func TestPurgeExpiredTokens_WithHost(t *testing.T) {
	fake := newFakeHostService()
	p := newTestPluginWithHost(nil, fake)
	hc := newFakeHostClient(fake)
	expired := &auth.Token{AccessToken: "old", TokenType: "Bearer", ExpiresAt: time.Now().Add(-time.Hour)}
	_ = cacheSet(context.Background(), hc, "exp1", expired)
	count, err := p.PurgeExpiredTokens(context.Background(), HandlerName)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestRequestDeviceCode_Success(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(http.StatusOK, DeviceCodeResponse{DeviceCode: "dc_123", UserCode: "ABCD-1234", VerificationURI: "https://github.com/login/device", ExpiresIn: 900, Interval: 5})
	p := newTestPlugin(mock)
	dc, err := p.requestDeviceCode(context.Background(), []string{"repo"})
	require.NoError(t, err)
	assert.Equal(t, "dc_123", dc.DeviceCode)
}

func TestRequestDeviceCode_Error(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(http.StatusBadRequest, TokenErrorResponse{Error: "invalid_client", ErrorDescription: "bad"})
	p := newTestPlugin(mock)
	_, err := p.requestDeviceCode(context.Background(), []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_client")
}

func TestPollForToken_Success(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, map[string]any{"error": "authorization_pending"})
	mock.AddResponse(200, map[string]any{"access_token": "at_new", "token_type": "bearer"})
	p := newTestPlugin(mock)
	p.clock = clock.Mock{}
	dc := &DeviceCodeResponse{DeviceCode: "dc", Interval: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tok, err := p.pollForToken(ctx, dc)
	require.NoError(t, err)
	assert.Equal(t, "at_new", tok.AccessToken)
}

func TestPollForToken_SlowDown(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, map[string]any{"error": "slow_down"})
	mock.AddResponse(200, map[string]any{"access_token": "at_slow", "token_type": "bearer"})
	p := newTestPlugin(mock)
	p.clock = clock.Mock{}
	dc := &DeviceCodeResponse{DeviceCode: "dc", Interval: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tok, err := p.pollForToken(ctx, dc)
	require.NoError(t, err)
	assert.Equal(t, "at_slow", tok.AccessToken)
}

func TestPollForToken_ExpiredToken(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, map[string]any{"error": "expired_token"})
	p := newTestPlugin(mock)
	p.clock = clock.Mock{}
	dc := &DeviceCodeResponse{DeviceCode: "dc", Interval: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := p.pollForToken(ctx, dc)
	assert.Contains(t, err.Error(), "timed out")
}

func TestPollForToken_AccessDenied(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, map[string]any{"error": "access_denied"})
	p := newTestPlugin(mock)
	p.clock = clock.Mock{}
	dc := &DeviceCodeResponse{DeviceCode: "dc", Interval: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := p.pollForToken(ctx, dc)
	assert.Contains(t, err.Error(), "cancelled")
}

func TestPollForToken_ContextCancelled(t *testing.T) {
	p := newTestPlugin(nil)
	p.clock = clock.Mock{}
	dc := &DeviceCodeResponse{DeviceCode: "dc", Interval: 1}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.pollForToken(ctx, dc)
	require.Error(t, err)
}

func TestPollForToken_UnknownError(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, map[string]any{"error": "server_error", "error_description": "broke"})
	p := newTestPlugin(mock)
	p.clock = clock.Mock{}
	dc := &DeviceCodeResponse{DeviceCode: "dc", Interval: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := p.pollForToken(ctx, dc)
	assert.Contains(t, err.Error(), "server_error")
}

func TestExchangeAuthCode_Success(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, map[string]any{"access_token": "at_code", "refresh_token": "rt_code", "token_type": "bearer"})
	p := newTestPlugin(mock)
	tok, err := p.exchangeAuthCode(context.Background(), "code123", "http://localhost/cb", "verifier")
	require.NoError(t, err)
	assert.Equal(t, "at_code", tok.AccessToken)
}

func TestExchangeAuthCode_Error(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, map[string]any{"error": "invalid_grant", "error_description": "code expired"})
	p := newTestPlugin(mock)
	_, err := p.exchangeAuthCode(context.Background(), "bad_code", "http://localhost/cb", "verifier")
	assert.Contains(t, err.Error(), "invalid_grant")
}

func TestExchangeAuthCode_EmptyToken(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, map[string]any{})
	p := newTestPlugin(mock)
	_, err := p.exchangeAuthCode(context.Background(), "code", "http://localhost/cb", "verifier")
	assert.Contains(t, err.Error(), "empty access token")
}

func TestExchangeAuthCode_WithClientSecret(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, map[string]any{"access_token": "at_s", "token_type": "bearer"})
	p := newTestPlugin(mock)
	p.config.ClientSecret = "my_secret"
	_, _ = p.exchangeAuthCode(context.Background(), "code", "http://localhost/cb", "verifier")
	reqs := mock.GetRequests()
	require.Len(t, reqs, 1)
	assert.Contains(t, reqs[0].Data.Get("client_secret"), "my_secret")
}

func TestExchangeAuthCode_HTTPError(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddError(fmt.Errorf("connection refused"))
	p := newTestPlugin(mock)
	_, err := p.exchangeAuthCode(context.Background(), "code", "http://localhost/cb", "verifier")
	assert.Contains(t, err.Error(), "connection refused")
}

func TestGetInstallationID(t *testing.T) {
	t.Run("from config", func(t *testing.T) {
		assert.Equal(t, int64(42), (&Config{InstallationID: 42}).GetInstallationID())
	})
	t.Run("from env", func(t *testing.T) {
		t.Setenv(EnvGitHubAppInstallationID, "99")
		assert.Equal(t, int64(99), (&Config{}).GetInstallationID())
	})
	t.Run("not set", func(t *testing.T) {
		t.Setenv(EnvGitHubAppInstallationID, "")
		assert.Equal(t, int64(0), (&Config{}).GetInstallationID())
	})
	t.Run("invalid", func(t *testing.T) {
		t.Setenv(EnvGitHubAppInstallationID, "x")
		assert.Equal(t, int64(0), (&Config{}).GetInstallationID())
	})
}

func TestGetAppID_FromEnv(t *testing.T) {
	t.Setenv(EnvGitHubAppID, "123")
	assert.Equal(t, int64(123), (&Config{}).GetAppID())
}

func TestGetAppID_InvalidEnv(t *testing.T) {
	t.Setenv(EnvGitHubAppID, "x")
	assert.Equal(t, int64(0), (&Config{}).GetAppID())
}

func TestGetPATToken_NoPAT(t *testing.T) {
	t.Setenv(EnvGitHubToken, "")
	t.Setenv(EnvGHToken, "")
	_, err := newTestPlugin(nil).getPATToken(context.Background(), sdkplugin.TokenRequest{})
	assert.Contains(t, err.Error(), "personal access token not configured")
}

func TestGetPATToken_ValidationFails(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(401, map[string]string{"message": "Bad credentials"})
	t.Setenv(EnvGitHubToken, "ghp_bad")
	t.Setenv(EnvGHToken, "")
	_, err := newTestPlugin(mock).getPATToken(context.Background(), sdkplugin.TokenRequest{})
	assert.Contains(t, err.Error(), "PAT validation failed")
}

func TestFarFuture(t *testing.T) {
	assert.True(t, farFuture().After(time.Now().Add(364*24*time.Hour)))
}

func TestBrowserOpener_Default(t *testing.T) {
	assert.NotNil(t, (&Plugin{}).browserOpener())
}

func TestBrowserOpener_Custom(t *testing.T) {
	called := false
	p := &Plugin{openBrowser: func(_ context.Context, _ string) error { called = true; return nil }}
	require.NoError(t, p.browserOpener()(context.Background(), "https://example.com"))
	assert.True(t, called)
}

func TestMockHTTPClient_AddError(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddError(fmt.Errorf("boom"))
	_, err := mock.PostForm(context.Background(), "/test", nil)
	assert.Contains(t, err.Error(), "boom")
}

func TestMockHTTPClient_PostJSON(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, "ok")
	resp, _ := mock.PostJSON(context.Background(), "/test", nil, nil)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestMockHTTPClient_PostForm(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, "ok")
	resp, _ := mock.PostForm(context.Background(), "/test", nil)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestMockHTTPClient_ContextCancelled(t *testing.T) {
	mock := NewMockHTTPClient()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := mock.PostForm(ctx, "/test", nil)
	require.Error(t, err)
	_, err = mock.Get(ctx, "/test", nil)
	require.Error(t, err)
	_, err = mock.PostJSON(ctx, "/test", nil, nil)
	require.Error(t, err)
}

func TestMockHTTPClient_Reset(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, "ok")
	mock.Reset()
	assert.Empty(t, mock.Requests)
}

func TestMockHTTPClient_GetRequests(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, "ok")
	_, _ = mock.Get(context.Background(), "/test", nil)
	assert.Len(t, mock.GetRequests(), 1)
}

func TestMockHTTPClient_NoResponseConfigured(t *testing.T) {
	resp, _ := NewMockHTTPClient().Get(context.Background(), "/test", nil)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestDetectAvailableFlows_GHTokenOnly(t *testing.T) {
	p := newTestPlugin(nil)
	t.Setenv(EnvGitHubToken, "")
	t.Setenv(EnvGHToken, "ghp_via_gh")
	t.Setenv(EnvGitHubAppID, "")
	t.Setenv(EnvGitHubAppPrivateKey, "")
	t.Setenv(EnvGitHubAppPrivateKeyPath, "")
	flows, _ := p.DetectAvailableFlows(context.Background(), HandlerName)
	for _, f := range flows {
		if f.Flow == auth.FlowPAT {
			assert.True(t, f.Available)
			assert.Contains(t, f.Reason, "GH_TOKEN")
		}
	}
}

func TestDetectAvailableFlows_AppIDOnly(t *testing.T) {
	p := newTestPlugin(nil)
	t.Setenv(EnvGitHubToken, "")
	t.Setenv(EnvGHToken, "")
	t.Setenv(EnvGitHubAppID, "12345")
	t.Setenv(EnvGitHubAppPrivateKey, "")
	t.Setenv(EnvGitHubAppPrivateKeyPath, "")
	flows, _ := p.DetectAvailableFlows(context.Background(), HandlerName)
	for _, f := range flows {
		if f.Flow == auth.FlowGitHubApp {
			assert.Contains(t, f.Reason, "private key is missing")
		}
	}
}

func TestDetectAvailableFlows_PrivateKeyOnly(t *testing.T) {
	p := newTestPlugin(nil)
	t.Setenv(EnvGitHubToken, "")
	t.Setenv(EnvGHToken, "")
	t.Setenv(EnvGitHubAppID, "")
	t.Setenv(EnvGitHubAppPrivateKey, "fakepem")
	t.Setenv(EnvGitHubAppPrivateKeyPath, "")
	flows, _ := p.DetectAvailableFlows(context.Background(), HandlerName)
	for _, f := range flows {
		if f.Flow == auth.FlowGitHubApp {
			assert.Contains(t, f.Reason, "App ID is missing")
		}
	}
}

func TestDetectAvailableFlows_AppFullyConfigured(t *testing.T) {
	p := newTestPlugin(nil)
	t.Setenv(EnvGitHubToken, "")
	t.Setenv(EnvGHToken, "")
	t.Setenv(EnvGitHubAppID, "123")
	t.Setenv(EnvGitHubAppPrivateKey, "fakepem")
	t.Setenv(EnvGitHubAppPrivateKeyPath, "")
	flows, _ := p.DetectAvailableFlows(context.Background(), HandlerName)
	for _, f := range flows {
		if f.Flow == auth.FlowGitHubApp {
			assert.True(t, f.Available)
		}
	}
}

func TestParseRSAPrivateKey_Valid(t *testing.T) {
	// Generate a test RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	parsed, err := parseRSAPrivateKey(pemBytes)
	require.NoError(t, err)
	assert.NotNil(t, parsed)
}

func TestParseRSAPrivateKey_Invalid(t *testing.T) {
	_, err := parseRSAPrivateKey([]byte("not a pem key"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse RSA private key")
}

func TestCreateAppJWT_Success(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	token, err := createAppJWT(12345, key)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	// Verify the token can be parsed
	parsed, err := jwt.Parse(token, func(_ *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
}

func TestGetAppInfo_Success(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, AppInfo{ID: 123, Slug: "my-app", Name: "My App"})
	p := newTestPlugin(mock)
	info, err := p.getAppInfo(context.Background(), "fake-jwt")
	require.NoError(t, err)
	assert.Equal(t, int64(123), info.ID)
	assert.Equal(t, "my-app", info.Slug)
}

func TestGetAppInfo_HTTPError(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddError(fmt.Errorf("network fail"))
	p := newTestPlugin(mock)
	_, err := p.getAppInfo(context.Background(), "fake-jwt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "network fail")
}

func TestGetAppInfo_NonOK(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(401, map[string]string{"message": "Unauthorized"})
	p := newTestPlugin(mock)
	_, err := p.getAppInfo(context.Background(), "fake-jwt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 401")
}

func TestCreateInstallationToken_Success(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour)
	mock := NewMockHTTPClient()
	mock.AddResponse(201, InstallationTokenResponse{Token: "ghs_abc", ExpiresAt: expiresAt, Permissions: map[string]string{"contents": "read"}})
	p := newTestPlugin(mock)
	tok, err := p.createInstallationToken(context.Background(), "fake-jwt", 42)
	require.NoError(t, err)
	assert.Equal(t, "ghs_abc", tok.Token)
}

func TestCreateInstallationToken_HTTPError(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddError(fmt.Errorf("network fail"))
	p := newTestPlugin(mock)
	_, err := p.createInstallationToken(context.Background(), "jwt", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "network fail")
}

func TestCreateInstallationToken_NonCreated(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(404, map[string]string{"message": "Not Found"})
	p := newTestPlugin(mock)
	_, err := p.createInstallationToken(context.Background(), "jwt", 99)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 404")
}

func TestGetPrivateKey_Inline(t *testing.T) {
	t.Setenv(EnvGitHubAppPrivateKey, "inline-pem-data")
	cfg := &Config{}
	key, err := cfg.GetPrivateKey(context.Background(), discardLogger(), nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("inline-pem-data"), key)
}

func TestGetPrivateKey_FromFile(t *testing.T) {
	t.Setenv(EnvGitHubAppPrivateKey, "")
	tmpFile := t.TempDir() + "/key.pem"
	require.NoError(t, os.WriteFile(tmpFile, []byte("file-pem-data"), 0600))
	cfg := &Config{PrivateKeyPath: tmpFile}
	key, err := cfg.GetPrivateKey(context.Background(), discardLogger(), nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("file-pem-data"), key)
}

func TestGetPrivateKey_FromFilePath_Env(t *testing.T) {
	t.Setenv(EnvGitHubAppPrivateKey, "")
	tmpFile := t.TempDir() + "/envkey.pem"
	require.NoError(t, os.WriteFile(tmpFile, []byte("env-file-data"), 0600))
	t.Setenv(EnvGitHubAppPrivateKeyPath, tmpFile)
	cfg := &Config{}
	key, err := cfg.GetPrivateKey(context.Background(), discardLogger(), nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("env-file-data"), key)
}

func TestGetPrivateKey_FromHostSecret(t *testing.T) {
	t.Setenv(EnvGitHubAppPrivateKey, "")
	t.Setenv(EnvGitHubAppPrivateKeyPath, "")
	fake := newFakeHostService()
	hc := newFakeHostClient(fake)
	_ = hc.SetSecret(context.Background(), "my-key-secret", "secret-pem-data")
	cfg := &Config{PrivateKeySecretName: "my-key-secret"}
	key, err := cfg.GetPrivateKey(context.Background(), discardLogger(), hc)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret-pem-data"), key)
}

func TestGetPrivateKey_SecretNotFound(t *testing.T) {
	t.Setenv(EnvGitHubAppPrivateKey, "")
	t.Setenv(EnvGitHubAppPrivateKeyPath, "")
	fake := newFakeHostService()
	hc := newFakeHostClient(fake)
	cfg := &Config{PrivateKeySecretName: "missing"}
	_, err := cfg.GetPrivateKey(context.Background(), discardLogger(), hc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGetPrivateKey_NoneConfigured(t *testing.T) {
	t.Setenv(EnvGitHubAppPrivateKey, "")
	t.Setenv(EnvGitHubAppPrivateKeyPath, "")
	cfg := &Config{}
	_, err := cfg.GetPrivateKey(context.Background(), discardLogger(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no private key configured")
}

func TestValidateAppConfig_Valid(t *testing.T) {
	t.Setenv(EnvGitHubAppID, "123")
	t.Setenv(EnvGitHubAppInstallationID, "456")
	t.Setenv(EnvGitHubAppPrivateKey, "pem-data")
	cfg := &Config{}
	err := cfg.ValidateAppConfig(context.Background(), discardLogger(), nil)
	require.NoError(t, err)
}

func TestValidateAppConfig_MissingAppID(t *testing.T) {
	t.Setenv(EnvGitHubAppID, "")
	t.Setenv(EnvGitHubAppInstallationID, "456")
	t.Setenv(EnvGitHubAppPrivateKey, "pem-data")
	cfg := &Config{}
	err := cfg.ValidateAppConfig(context.Background(), discardLogger(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "app ID is required")
}

func TestValidateAppConfig_MissingInstallationID(t *testing.T) {
	t.Setenv(EnvGitHubAppID, "123")
	t.Setenv(EnvGitHubAppInstallationID, "")
	t.Setenv(EnvGitHubAppPrivateKey, "pem-data")
	cfg := &Config{}
	err := cfg.ValidateAppConfig(context.Background(), discardLogger(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "installation ID is required")
}

func TestValidateAppConfig_MissingKey(t *testing.T) {
	t.Setenv(EnvGitHubAppID, "123")
	t.Setenv(EnvGitHubAppInstallationID, "456")
	t.Setenv(EnvGitHubAppPrivateKey, "")
	t.Setenv(EnvGitHubAppPrivateKeyPath, "")
	cfg := &Config{}
	err := cfg.ValidateAppConfig(context.Background(), discardLogger(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no private key")
}

func TestPerformDeviceCodeFlow_Success(t *testing.T) {
	mock := NewMockHTTPClient()
	// requestDeviceCode response
	mock.AddResponse(200, DeviceCodeResponse{DeviceCode: "dc", UserCode: "CODE", VerificationURI: "https://github.com/login/device", ExpiresIn: 900, Interval: 5})
	// pollForToken response
	mock.AddResponse(200, map[string]any{"access_token": "flow_at", "refresh_token": "flow_rt", "token_type": "bearer", "scope": "repo", "expires_in": 3600, "refresh_token_expires_in": 86400})
	// storeCredentials -> getUserInfo
	mock.AddResponse(200, User{Login: "flowuser", ID: 10, Name: "Flow User"})
	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)
	p.clock = clock.Mock{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var prompt sdkplugin.DeviceCodePrompt
	resp, err := p.performDeviceCodeFlow(ctx, []string{"repo"}, false, func(dp sdkplugin.DeviceCodePrompt) { prompt = dp })
	require.NoError(t, err)
	assert.Equal(t, "flowuser", resp.Claims.Subject)
	assert.Equal(t, "CODE", prompt.UserCode)
}

func TestPerformDeviceCodeFlow_WithBrowser(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, DeviceCodeResponse{DeviceCode: "dc", UserCode: "CODE2", VerificationURI: "https://github.com/login/device", ExpiresIn: 900, Interval: 5})
	mock.AddResponse(200, map[string]any{"access_token": "at2", "refresh_token": "rt2", "token_type": "bearer", "scope": "repo", "expires_in": 3600, "refresh_token_expires_in": 86400})
	mock.AddResponse(200, User{Login: "buser", ID: 11})
	fake := newFakeHostService()
	browserCalled := false
	p := newTestPluginWithHost(mock, fake)
	p.openBrowser = func(_ context.Context, _ string) error { browserCalled = true; return nil }
	p.clock = clock.Mock{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := p.performDeviceCodeFlow(ctx, []string{"repo"}, true, func(_ sdkplugin.DeviceCodePrompt) {})
	require.NoError(t, err)
	assert.True(t, browserCalled)
}

func TestDeviceCodeLogin_Success(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, DeviceCodeResponse{DeviceCode: "dc", UserCode: "U-CODE", VerificationURI: "https://github.com/login/device", ExpiresIn: 900, Interval: 5})
	mock.AddResponse(200, map[string]any{"access_token": "dc_at", "refresh_token": "dc_rt", "token_type": "bearer", "scope": "repo", "expires_in": 3600, "refresh_token_expires_in": 86400})
	mock.AddResponse(200, User{Login: "dcuser", ID: 20})
	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)
	p.clock = clock.Mock{}
	resp, err := p.deviceCodeLogin(context.Background(), sdkplugin.LoginRequest{Scopes: []string{"repo"}, Timeout: 5 * time.Second}, func(_ sdkplugin.DeviceCodePrompt) {})
	require.NoError(t, err)
	assert.Equal(t, "dcuser", resp.Claims.Subject)
}

func TestInteractiveDeviceCodeLogin_Success(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, DeviceCodeResponse{DeviceCode: "dc", UserCode: "I-CODE", VerificationURI: "https://github.com/login/device", ExpiresIn: 900, Interval: 5})
	mock.AddResponse(200, map[string]any{"access_token": "i_at", "token_type": "bearer", "scope": "repo", "expires_in": 3600, "refresh_token_expires_in": 86400})
	mock.AddResponse(200, User{Login: "iuser", ID: 30})
	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)
	p.clock = clock.Mock{}
	resp, err := p.interactiveDeviceCodeLogin(context.Background(), sdkplugin.LoginRequest{Scopes: []string{"repo"}, Timeout: 5 * time.Second}, func(_ sdkplugin.DeviceCodePrompt) {})
	require.NoError(t, err)
	assert.Equal(t, "iuser", resp.Claims.Subject)
}

func TestAppLogin_Success(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	mock := NewMockHTTPClient()
	// getAppInfo
	appInfo := AppInfo{ID: 100, Slug: "test-app", Name: "Test App"}
	appInfo.Owner.Login = "org"
	appInfo.Owner.ID = 1
	mock.AddResponse(200, appInfo)
	// createInstallationToken
	mock.AddResponse(201, InstallationTokenResponse{Token: "ghs_inst_tok", ExpiresAt: time.Now().Add(time.Hour), Permissions: map[string]string{"contents": "read"}}) //nolint:gosec // test data

	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)
	p.config.AppID = 100
	p.config.InstallationID = 42
	p.config.PrivateKey = string(pemBytes)

	resp, err := p.appLogin(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "app/test-app", resp.Claims.Subject)
}

func TestAppLogin_MissingConfig(t *testing.T) {
	fake := newFakeHostService()
	p := newTestPluginWithHost(nil, fake)
	// No app config set
	t.Setenv(EnvGitHubAppID, "")
	t.Setenv(EnvGitHubAppInstallationID, "")
	t.Setenv(EnvGitHubAppPrivateKey, "")
	t.Setenv(EnvGitHubAppPrivateKeyPath, "")
	p.config.AppID = 0
	_, err := p.appLogin(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "app_config")
}

func TestLogin_FlowGitHubApp(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	mock := NewMockHTTPClient()
	appInfo := AppInfo{ID: 100, Slug: "test-app", Name: "Test App"}
	mock.AddResponse(200, appInfo)
	mock.AddResponse(201, InstallationTokenResponse{Token: "ghs_tok", ExpiresAt: time.Now().Add(time.Hour), Permissions: map[string]string{"contents": "read"}}) //nolint:gosec // test

	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)
	p.config.AppID = 100
	p.config.InstallationID = 42
	p.config.PrivateKey = string(pemBytes)
	t.Setenv(EnvGitHubToken, "")
	t.Setenv(EnvGHToken, "")

	resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
		Flow: auth.FlowGitHubApp,
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, "app/test-app", resp.Claims.Subject)
}

func TestLogin_InteractiveWithClientSecret(t *testing.T) {
	// When ClientSecret is set and flow is interactive, it should attempt authCodeLogin.
	// authCodeLogin will fail because we don't have a real callback server,
	// but we verify the dispatch path is exercised.
	mock := NewMockHTTPClient()
	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)
	p.config.ClientSecret = "test_secret"
	t.Setenv(EnvGitHubToken, "")
	t.Setenv(EnvGHToken, "")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{
		Flow:    auth.FlowInteractive,
		Timeout: 100 * time.Millisecond,
	}, nil)
	// Expected to fail (no browser/callback) but should not return "unsupported flow"
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "unsupported flow")
}

func TestLogin_EmptyFlowWithClientSecret(t *testing.T) {
	mock := NewMockHTTPClient()
	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)
	p.config.ClientSecret = "test_secret"
	t.Setenv(EnvGitHubToken, "")
	t.Setenv(EnvGHToken, "")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{
		Timeout: 100 * time.Millisecond,
	}, nil)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "unsupported flow")
}

func TestLogin_ImplicitPATDetection(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, User{Login: "auto_pat", ID: 55, Name: "Auto PAT"})
	p := newTestPlugin(mock)
	t.Setenv(EnvGitHubToken, "ghp_auto_detect")
	t.Setenv(EnvGHToken, "")

	// Empty flow, PAT set, no scopes => should auto-detect PAT
	resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{}, nil)
	require.NoError(t, err)
	assert.Equal(t, "auto_pat", resp.Claims.Subject)
}

func TestLogin_EmptyFlowNoClientSecret(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, DeviceCodeResponse{DeviceCode: "dc", UserCode: "CODE", VerificationURI: "https://github.com/login/device", ExpiresIn: 900, Interval: 5})
	mock.AddResponse(200, map[string]any{"access_token": "at_empty", "token_type": "bearer", "scope": "repo", "expires_in": 3600, "refresh_token_expires_in": 86400})
	mock.AddResponse(200, User{Login: "emptyflow", ID: 60})
	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)
	p.clock = clock.Mock{}
	t.Setenv(EnvGitHubToken, "")
	t.Setenv(EnvGHToken, "")

	resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
		Scopes:  []string{"repo"},
		Timeout: 5 * time.Second,
	}, func(_ sdkplugin.DeviceCodePrompt) {})
	require.NoError(t, err)
	assert.Equal(t, "emptyflow", resp.Claims.Subject)
}

func TestListCachedTokens_AccessTokenNotCached(t *testing.T) {
	fake := newFakeHostService()
	p := newTestPluginWithHost(nil, fake)
	hc := newFakeHostClient(fake)
	ctx := context.Background()
	// Store access token but no cached entry
	_ = hc.SetSecret(ctx, SecretKeyAccessToken, "direct_at")
	results, err := p.ListCachedTokens(ctx, HandlerName)
	require.NoError(t, err)
	// Should include an entry for the direct access token
	found := false
	for _, r := range results {
		if r.TokenKind == "access" && r.TokenType == "Bearer" {
			found = true
		}
	}
	assert.True(t, found, "should find direct access token entry")
}

func TestConfigValidate_InvalidHostname(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		wantErr  string
	}{
		{"space", "git hub.com", "invalid characters"},
		{"semicolon", "github.com;evil", "invalid characters"},
		{"quote", `github.com"`, "invalid characters"},
		{"newline", "github.com\n", "invalid characters"},
		{"tab", "github.com\t", "invalid characters"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{ClientID: "cid", Hostname: tt.hostname}
			err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestAuthCodeLogin_Timeout(t *testing.T) {
	mock := NewMockHTTPClient()
	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)
	t.Setenv(EnvGitHubToken, "")
	t.Setenv(EnvGHToken, "")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := p.authCodeLogin(ctx, sdkplugin.LoginRequest{
		Timeout: 200 * time.Millisecond,
	}, nil)
	require.Error(t, err)
	// Should fail with timeout or context error, not a panic
	assert.True(t,
		strings.Contains(err.Error(), "no response received") ||
			strings.Contains(err.Error(), "cancelled"),
		"expected timeout or cancel error, got: %s", err)
}

func TestAuthCodeLogin_ContextCancelled(t *testing.T) {
	mock := NewMockHTTPClient()
	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)
	t.Setenv(EnvGitHubToken, "")
	t.Setenv(EnvGHToken, "")

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately
	cancel()
	_, err := p.authCodeLogin(ctx, sdkplugin.LoginRequest{
		Timeout: 5 * time.Second,
	}, nil)
	require.Error(t, err)
}
