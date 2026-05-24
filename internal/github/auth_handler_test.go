package github

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestPlugin creates a Plugin initialized for testing.
func newTestPlugin(httpClient HTTPClient) *Plugin {
	p := &Plugin{}
	_ = p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
		BinaryName: "scafctl",
	})
	if httpClient != nil {
		p.httpClient = httpClient
	}
	return p
}

func TestGetAuthHandlers(t *testing.T) {
	p := &Plugin{}
	handlers, err := p.GetAuthHandlers(context.Background())
	require.NoError(t, err)
	require.Len(t, handlers, 1)
	assert.Equal(t, HandlerName, handlers[0].Name)
	assert.Equal(t, HandlerDisplayName, handlers[0].DisplayName)
	assert.Contains(t, handlers[0].Flows, auth.FlowInteractive)
	assert.Contains(t, handlers[0].Flows, auth.FlowDeviceCode)
	assert.Contains(t, handlers[0].Flows, auth.FlowPAT)
	assert.Contains(t, handlers[0].Flows, auth.FlowGitHubApp)
	assert.Contains(t, handlers[0].Capabilities, auth.CapScopesOnLogin)
	assert.Contains(t, handlers[0].Capabilities, auth.CapHostname)
	assert.Contains(t, handlers[0].Capabilities, auth.CapCallbackPort)
}

func TestConfigureAuthHandler(t *testing.T) {
	p := &Plugin{}
	err := p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
		BinaryName: "mycli",
	})
	require.NoError(t, err)
	assert.Equal(t, "mycli", p.cfg.BinaryName)
	assert.NotNil(t, p.config)
	assert.Equal(t, DefaultClientID, p.config.ClientID)
	assert.Equal(t, DefaultHostname, p.config.Hostname)
	assert.NotNil(t, p.httpClient)
	assert.NotNil(t, p.clock)
}

func TestLogin(t *testing.T) {
	t.Run("unknown handler", func(t *testing.T) {
		p := newTestPlugin(nil)
		_, err := p.Login(context.Background(), "unknown", sdkplugin.LoginRequest{}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown handler")
	})

	t.Run("unsupported flow", func(t *testing.T) {
		p := newTestPlugin(nil)
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowWorkloadIdentity,
		}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported flow")
	})

	t.Run("pat flow no env var", func(t *testing.T) {
		p := newTestPlugin(nil)
		t.Setenv(EnvGitHubToken, "")
		t.Setenv(EnvGHToken, "")
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowPAT,
		}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "personal access token not configured")
	})

	t.Run("pat flow with valid token", func(t *testing.T) {
		mock := NewMockHTTPClient()
		mock.AddResponse(200, User{
			Login: "octocat",
			ID:    42,
			Name:  "The Octocat",
			Email: "octocat@github.com",
		})
		p := newTestPlugin(mock)
		t.Setenv(EnvGitHubToken, "ghp_testtoken123")

		resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowPAT,
		}, nil)
		require.NoError(t, err)
		assert.NotNil(t, resp.Claims)
		assert.Equal(t, "octocat", resp.Claims.Subject)
		assert.Equal(t, "The Octocat", resp.Claims.Name)
	})
}

func TestLogout(t *testing.T) {
	t.Run("unknown handler", func(t *testing.T) {
		p := newTestPlugin(nil)
		err := p.Logout(context.Background(), "unknown")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown handler")
	})

	t.Run("known handler no host client", func(t *testing.T) {
		p := newTestPlugin(nil)
		err := p.Logout(context.Background(), HandlerName)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "host service not available")
	})
}

func TestGetStatus(t *testing.T) {
	t.Run("unknown handler", func(t *testing.T) {
		p := newTestPlugin(nil)
		_, err := p.GetStatus(context.Background(), "unknown")
		assert.Error(t, err)
	})

	t.Run("not authenticated", func(t *testing.T) {
		p := newTestPlugin(nil)
		t.Setenv(EnvGitHubToken, "")
		t.Setenv(EnvGHToken, "")
		status, err := p.GetStatus(context.Background(), HandlerName)
		require.NoError(t, err)
		assert.False(t, status.Authenticated)
	})

	t.Run("pat authenticated", func(t *testing.T) {
		mock := NewMockHTTPClient()
		mock.AddResponse(200, User{
			Login: "testuser",
			ID:    99,
			Name:  "Test User",
			Email: "test@example.com",
		})
		p := newTestPlugin(mock)
		t.Setenv(EnvGitHubToken, "ghp_valid_pat")

		status, err := p.GetStatus(context.Background(), HandlerName)
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Equal(t, "testuser", status.Claims.Subject)
		assert.Equal(t, auth.IdentityTypeUser, status.IdentityType)
	})

	t.Run("pat invalid token", func(t *testing.T) {
		mock := NewMockHTTPClient()
		mock.AddResponse(401, map[string]string{"message": "Bad credentials"})
		p := newTestPlugin(mock)
		t.Setenv(EnvGitHubToken, "ghp_invalid")

		status, err := p.GetStatus(context.Background(), HandlerName)
		require.NoError(t, err)
		assert.False(t, status.Authenticated)
	})
}

func TestGetToken(t *testing.T) {
	t.Run("unknown handler", func(t *testing.T) {
		p := newTestPlugin(nil)
		_, err := p.GetToken(context.Background(), "unknown", sdkplugin.TokenRequest{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown handler")
	})

	t.Run("not authenticated no pat", func(t *testing.T) {
		p := newTestPlugin(nil)
		t.Setenv(EnvGitHubToken, "")
		t.Setenv(EnvGHToken, "")
		_, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{})
		assert.Error(t, err)
	})
}

func TestListCachedTokens(t *testing.T) {
	t.Run("unknown handler", func(t *testing.T) {
		p := newTestPlugin(nil)
		_, err := p.ListCachedTokens(context.Background(), "unknown")
		assert.Error(t, err)
	})

	t.Run("no host client", func(t *testing.T) {
		p := newTestPlugin(nil)
		_, err := p.ListCachedTokens(context.Background(), HandlerName)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "host service not available")
	})
}

func TestPurgeExpiredTokens(t *testing.T) {
	t.Run("unknown handler", func(t *testing.T) {
		p := newTestPlugin(nil)
		_, err := p.PurgeExpiredTokens(context.Background(), "unknown")
		assert.Error(t, err)
	})

	t.Run("no host client", func(t *testing.T) {
		p := newTestPlugin(nil)
		count, err := p.PurgeExpiredTokens(context.Background(), HandlerName)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})
}

func TestDetectAvailableFlows(t *testing.T) {
	t.Run("unknown handler", func(t *testing.T) {
		p := newTestPlugin(nil)
		_, err := p.DetectAvailableFlows(context.Background(), "unknown")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown handler")
	})

	t.Run("no pat env", func(t *testing.T) {
		p := newTestPlugin(nil)
		t.Setenv(EnvGitHubToken, "")
		t.Setenv(EnvGHToken, "")
		t.Setenv(EnvGitHubAppID, "")
		t.Setenv(EnvGitHubAppPrivateKey, "")
		t.Setenv(EnvGitHubAppPrivateKeyPath, "")

		flows, err := p.DetectAvailableFlows(context.Background(), HandlerName)
		require.NoError(t, err)
		require.NotEmpty(t, flows)

		for _, f := range flows {
			if f.Flow == auth.FlowPAT {
				assert.False(t, f.Available)
			}
			if f.Flow == auth.FlowDeviceCode {
				assert.True(t, f.Available)
			}
			if f.Flow == auth.FlowInteractive {
				assert.True(t, f.Available)
			}
		}
	})

	t.Run("pat env set", func(t *testing.T) {
		p := newTestPlugin(nil)
		t.Setenv(EnvGitHubToken, "ghp_test")
		t.Setenv(EnvGitHubAppID, "")
		t.Setenv(EnvGitHubAppPrivateKey, "")
		t.Setenv(EnvGitHubAppPrivateKeyPath, "")

		flows, err := p.DetectAvailableFlows(context.Background(), HandlerName)
		require.NoError(t, err)

		for _, f := range flows {
			if f.Flow == auth.FlowPAT {
				assert.True(t, f.Available)
				assert.Contains(t, f.Reason, "GITHUB_TOKEN is set")
			}
		}
	})
}

func TestStopAuthHandler(t *testing.T) {
	p := newTestPlugin(nil)

	t.Run("known handler", func(t *testing.T) {
		err := p.StopAuthHandler(context.Background(), HandlerName)
		require.NoError(t, err)
	})

	t.Run("unknown handler", func(t *testing.T) {
		err := p.StopAuthHandler(context.Background(), "unknown")
		assert.Error(t, err)
	})
}

func TestBinaryName(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		p := &Plugin{}
		assert.Equal(t, "scafctl", p.binaryName())
	})

	t.Run("custom", func(t *testing.T) {
		p := &Plugin{cfg: sdkplugin.ProviderConfig{BinaryName: "mycli"}}
		assert.Equal(t, "mycli", p.binaryName())
	})
}

func TestConfig(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		cfg := DefaultConfig()
		assert.Equal(t, DefaultClientID, cfg.ClientID)
		assert.Equal(t, DefaultHostname, cfg.Hostname)
	})

	t.Run("validate", func(t *testing.T) {
		cfg := &Config{}
		assert.Error(t, cfg.Validate())

		cfg.ClientID = "test"
		assert.Error(t, cfg.Validate())

		cfg.Hostname = "github.com"
		assert.NoError(t, cfg.Validate())
	})

	t.Run("oauth base url", func(t *testing.T) {
		cfg := &Config{Hostname: "github.com"}
		assert.Equal(t, "https://github.com", cfg.GetOAuthBaseURL())

		cfg.Hostname = "github.example.com"
		assert.Equal(t, "https://github.example.com", cfg.GetOAuthBaseURL())
	})

	t.Run("api base url", func(t *testing.T) {
		cfg := &Config{Hostname: "github.com"}
		assert.Equal(t, "https://api.github.com", cfg.GetAPIBaseURL())

		cfg.Hostname = "github.example.com"
		assert.Equal(t, "https://github.example.com/api/v3", cfg.GetAPIBaseURL())
	})
}

func TestFetchUserClaims(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock := NewMockHTTPClient()
		mock.AddResponse(200, User{
			Login: "octocat",
			ID:    1,
			Name:  "The Octocat",
			Email: "octocat@github.com",
		})
		p := newTestPlugin(mock)

		claims, err := p.fetchUserClaims(context.Background(), "test-token")
		require.NoError(t, err)
		assert.Equal(t, "octocat", claims.Subject)
		assert.Equal(t, "octocat", claims.Username)
		assert.Equal(t, "The Octocat", claims.Name)
		assert.Equal(t, "octocat@github.com", claims.Email)
		assert.Equal(t, "1", claims.ObjectID)
		assert.Equal(t, DefaultHostname, claims.Issuer)
	})

	t.Run("api error", func(t *testing.T) {
		mock := NewMockHTTPClient()
		mock.AddResponse(401, map[string]string{"message": "Bad credentials"})
		p := newTestPlugin(mock)

		_, err := p.fetchUserClaims(context.Background(), "bad-token")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "status 401")
	})
}

func TestHasPATCredentials(t *testing.T) {
	t.Run("no env vars", func(t *testing.T) {
		t.Setenv(EnvGitHubToken, "")
		t.Setenv(EnvGHToken, "")
		assert.False(t, HasPATCredentials())
	})

	t.Run("GITHUB_TOKEN set", func(t *testing.T) {
		t.Setenv(EnvGitHubToken, "ghp_test")
		assert.True(t, HasPATCredentials())
	})

	t.Run("GH_TOKEN set", func(t *testing.T) {
		t.Setenv(EnvGitHubToken, "")
		t.Setenv(EnvGHToken, "ghp_test")
		assert.True(t, HasPATCredentials())
	})

	t.Run("GITHUB_TOKEN takes precedence", func(t *testing.T) {
		t.Setenv(EnvGitHubToken, "token1")
		t.Setenv(EnvGHToken, "token2")
		assert.Equal(t, "token1", GetPATFromEnv())
	})
}

func TestMakeFormData(t *testing.T) {
	data := makeFormData(map[string]string{
		"key1": "value1",
		"key2": "value2",
	})
	assert.Equal(t, []string{"value1"}, data["key1"])
	assert.Equal(t, []string{"value2"}, data["key2"])
}

func TestFingerprintHash(t *testing.T) {
	hash1 := fingerprintHash("test")
	hash2 := fingerprintHash("test")
	hash3 := fingerprintHash("different")
	assert.Equal(t, hash1, hash2)
	assert.NotEqual(t, hash1, hash3)
	assert.Len(t, hash1, 64)
}

func BenchmarkGetToken(b *testing.B) {
	p := newTestPlugin(nil)
	ctx := context.Background()
	req := sdkplugin.TokenRequest{}

	b.Setenv(EnvGitHubToken, "")
	b.Setenv(EnvGHToken, "")

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _ = p.GetToken(ctx, HandlerName, req)
	}
}

func TestConfigureAuthHandler_WithSettings(t *testing.T) {
	p := &Plugin{}
	cfg := Config{
		ClientID: "custom-id",
		Hostname: "github.example.com",
	}
	cfgJSON, err := json.Marshal(cfg) //nolint:gosec // test fixture
	require.NoError(t, err)

	err = p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
		Settings: map[string]json.RawMessage{
			HandlerName: cfgJSON,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "custom-id", p.config.ClientID)
	assert.Equal(t, "github.example.com", p.config.Hostname)
}

func TestConfigureAuthHandler_InvalidSettings(t *testing.T) {
	p := &Plugin{}
	err := p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
		Settings: map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{invalid json`),
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse handler config")
}

func TestConfigureAuthHandler_InvalidConfig(t *testing.T) {
	p := &Plugin{}
	// Send empty clientId which overrides the default
	cfgJSON, err := json.Marshal(Config{ClientID: "", Hostname: ""}) //nolint:gosec // test fixture
	require.NoError(t, err)

	err = p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
		Settings: map[string]json.RawMessage{
			HandlerName: cfgJSON,
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client ID is required")
}

func TestConfigureAuthHandler_PreservesHTTPClient(t *testing.T) {
	mock := NewMockHTTPClient()
	p := &Plugin{httpClient: mock}

	err := p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{})
	require.NoError(t, err)
	assert.Equal(t, mock, p.httpClient, "ConfigureAuthHandler should not overwrite a pre-set httpClient")
}

func TestTokenMigration_ByteIdenticalKeys(t *testing.T) {
	// Verify that secret keys match the built-in handler's keys exactly.
	// This is critical for token migration compatibility.
	assert.Equal(t, "scafctl.auth.github.refresh_token", SecretKeyRefreshToken)
	assert.Equal(t, "scafctl.auth.github.access_token", SecretKeyAccessToken)
	assert.Equal(t, "scafctl.auth.github.metadata", SecretKeyMetadata)
	assert.Equal(t, "scafctl.auth.github.token.", SecretKeyTokenPrefix)
	assert.Equal(t, "scafctl.auth.github.app_metadata", SecretKeyAppJWT)
}

func TestTokenMigration_MetadataDeserialization(t *testing.T) {
	// Verify the plugin can read metadata written by the built-in handler.
	builtinJSON := `{
		"claims": {
			"issuer": "github.com",
			"subject": "testuser",
			"objectId": "12345",
			"email": "test@example.com",
			"name": "Test User",
			"username": "testuser"
		},
		"refreshTokenExpiresAt": "2026-06-08T00:00:00Z",
		"lastRefresh": "2026-05-08T00:00:00Z",
		"hostname": "github.com",
		"clientId": "Ov23li6xn492GhPmt4YG",
		"scopes": ["repo", "read:org"],
		"identityType": "user",
		"sessionId": "abc123"
	}`

	var metadata TokenMetadata
	err := json.Unmarshal([]byte(builtinJSON), &metadata)
	require.NoError(t, err)

	assert.Equal(t, "testuser", metadata.Claims.Subject)
	assert.Equal(t, "github.com", metadata.Hostname)
	assert.Equal(t, DefaultClientID, metadata.ClientID)
	assert.Equal(t, []string{"repo", "read:org"}, metadata.Scopes)
	assert.Equal(t, "user", metadata.IdentityType)
	assert.Equal(t, "abc123", metadata.SessionID)
}

func TestProfileSecretKey(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		profile string
		want    string
		wantErr bool
	}{
		{
			name:    "default profile unchanged",
			key:     SecretKeyRefreshToken,
			profile: "",
			want:    "scafctl.auth.github.refresh_token",
		},
		{
			name:    "named profile namespaced",
			key:     SecretKeyRefreshToken,
			profile: "work",
			want:    "scafctl.auth.github.work.refresh_token",
		},
		{
			name:    "access token namespaced",
			key:     SecretKeyAccessToken,
			profile: "personal",
			want:    "scafctl.auth.github.personal.access_token",
		},
		{
			name:    "metadata namespaced",
			key:     SecretKeyMetadata,
			profile: "corp",
			want:    "scafctl.auth.github.corp.metadata",
		},
		{
			name:    "profile with dot is rejected",
			key:     SecretKeyRefreshToken,
			profile: "a.b",
			wantErr: true,
		},
		{
			name:    "profile with slash is rejected",
			key:     SecretKeyAccessToken,
			profile: "a/b",
			wantErr: true,
		},
		{
			name:    "profile with colon is rejected",
			key:     SecretKeyMetadata,
			profile: "a:b",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := profileSecretKey(tc.key, tc.profile)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestProfileTokenPrefix(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		want    string
		wantErr bool
	}{
		{
			name:    "default profile",
			profile: "",
			want:    SecretKeyTokenPrefix,
		},
		{
			name:    "named profile",
			profile: "work",
			want:    "scafctl.auth.github.work.token.",
		},
		{
			name:    "invalid profile is rejected",
			profile: "a.b",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := profileTokenPrefix(tc.profile)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestProfileIsolation_StoreAndLoad(t *testing.T) {
	mock := NewMockHTTPClient()
	// Two responses for two storeCredentials calls (each fetches user claims).
	mock.AddResponse(200, User{Login: "default-user", ID: 1, Name: "Default"})
	mock.AddResponse(200, User{Login: "work-user", ID: 2, Name: "Work"})

	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)

	defaultCtx := context.Background()
	workCtx := auth.WithProfile(context.Background(), "work")

	// Store credentials under default profile.
	defaultResp := &TokenResponse{AccessToken: "at_default", RefreshToken: "rt_default", TokenType: "bearer", Scope: "repo", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400}
	claims, err := p.storeCredentials(defaultCtx, defaultResp, []string{"repo"}, "sess-default", auth.FlowDeviceCode)
	require.NoError(t, err)
	assert.Equal(t, "default-user", claims.Subject)

	// Store credentials under "work" profile.
	workResp := &TokenResponse{AccessToken: "at_work", RefreshToken: "rt_work", TokenType: "bearer", Scope: "repo read:org", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400}
	claims, err = p.storeCredentials(workCtx, workResp, []string{"repo", "read:org"}, "sess-work", auth.FlowDeviceCode)
	require.NoError(t, err)
	assert.Equal(t, "work-user", claims.Subject)

	// Load from default profile.
	rt, err := p.loadRefreshToken(defaultCtx)
	require.NoError(t, err)
	assert.Equal(t, "rt_default", rt)

	at, err := p.loadAccessToken(defaultCtx)
	require.NoError(t, err)
	assert.Equal(t, "at_default", at)

	meta, err := p.loadMetadata(defaultCtx)
	require.NoError(t, err)
	assert.Equal(t, "default-user", meta.Claims.Subject)

	// Load from work profile — must be isolated.
	rt, err = p.loadRefreshToken(workCtx)
	require.NoError(t, err)
	assert.Equal(t, "rt_work", rt)

	at, err = p.loadAccessToken(workCtx)
	require.NoError(t, err)
	assert.Equal(t, "at_work", at)

	meta, err = p.loadMetadata(workCtx)
	require.NoError(t, err)
	assert.Equal(t, "work-user", meta.Claims.Subject)
}

func TestProfileIsolation_LogoutOnlyAffectsProfile(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, User{Login: "default-user", ID: 1, Name: "Default"})
	mock.AddResponse(200, User{Login: "work-user", ID: 2, Name: "Work"})

	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)

	defaultCtx := context.Background()
	workCtx := auth.WithProfile(context.Background(), "work")

	// Store credentials in both profiles.
	defaultResp := &TokenResponse{AccessToken: "at_default", RefreshToken: "rt_default", TokenType: "bearer", Scope: "repo", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400}
	_, err := p.storeCredentials(defaultCtx, defaultResp, []string{"repo"}, "sess-default", auth.FlowDeviceCode)
	require.NoError(t, err)

	workResp := &TokenResponse{AccessToken: "at_work", RefreshToken: "rt_work", TokenType: "bearer", Scope: "repo", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400}
	_, err = p.storeCredentials(workCtx, workResp, []string{"repo"}, "sess-work", auth.FlowDeviceCode)
	require.NoError(t, err)

	// Logout work profile.
	err = p.Logout(workCtx, HandlerName)
	require.NoError(t, err)

	// Work profile tokens are gone.
	_, err = p.loadRefreshToken(workCtx)
	assert.Error(t, err)

	// Default profile tokens are still present.
	rt, err := p.loadRefreshToken(defaultCtx)
	require.NoError(t, err)
	assert.Equal(t, "rt_default", rt)
}

func TestProfileIsolation_CacheIsolated(t *testing.T) {
	fake := newFakeHostService()
	hc := newFakeHostClient(fake)
	ctx := context.Background()

	tok1 := &auth.Token{AccessToken: "default_tok", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}
	tok2 := &auth.Token{AccessToken: "work_tok", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}

	// Store tokens in different profile namespaces.
	require.NoError(t, cacheSet(ctx, hc, "key1", tok1, ""))
	require.NoError(t, cacheSet(ctx, hc, "key1", tok2, "work"))

	// Retrieve each — they should be different.
	got1, err := cacheGet(ctx, hc, "key1", "")
	require.NoError(t, err)
	require.NotNil(t, got1)
	assert.Equal(t, "default_tok", got1.AccessToken)

	got2, err := cacheGet(ctx, hc, "key1", "work")
	require.NoError(t, err)
	require.NotNil(t, got2)
	assert.Equal(t, "work_tok", got2.AccessToken)

	// Clear only the work profile cache.
	cacheClear(ctx, discardLogger(), hc, "work")

	// Default still exists.
	got1, err = cacheGet(ctx, hc, "key1", "")
	require.NoError(t, err)
	assert.NotNil(t, got1)

	// Work is gone.
	got2, err = cacheGet(ctx, hc, "key1", "work")
	require.NoError(t, err)
	assert.Nil(t, got2)
}

func TestProfileIsolation_GetStatus(t *testing.T) {
	mock := NewMockHTTPClient()
	mock.AddResponse(200, User{Login: "default-user", ID: 1, Name: "Default"})

	fake := newFakeHostService()
	p := newTestPluginWithHost(mock, fake)

	defaultCtx := context.Background()
	workCtx := auth.WithProfile(context.Background(), "work")

	t.Setenv(EnvGitHubToken, "")
	t.Setenv(EnvGHToken, "")

	// Store credentials in default profile only.
	resp := &TokenResponse{AccessToken: "at_default", RefreshToken: "rt_default", TokenType: "bearer", Scope: "repo", ExpiresIn: 3600, RefreshTokenExpiresIn: 86400}
	_, err := p.storeCredentials(defaultCtx, resp, []string{"repo"}, "sess", auth.FlowDeviceCode)
	require.NoError(t, err)

	// Default profile: authenticated.
	status, err := p.GetStatus(defaultCtx, HandlerName)
	require.NoError(t, err)
	assert.True(t, status.Authenticated)

	// Work profile: not authenticated.
	status, err = p.GetStatus(workCtx, HandlerName)
	require.NoError(t, err)
	assert.False(t, status.Authenticated)
}
