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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerConfigValidate(t *testing.T) {
	t.Run("missing serverFlow", func(t *testing.T) {
		sc := &ServerConfig{Credential: CredentialConfig{}}
		err := sc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serverFlow is required")
	})

	t.Run("disallowed serverFlow", func(t *testing.T) {
		sc := &ServerConfig{ServerFlow: auth.FlowDeviceCode}
		err := sc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not allowed")
	})

	t.Run("pat missing token", func(t *testing.T) {
		sc := &ServerConfig{ServerFlow: auth.FlowPAT, Credential: CredentialConfig{}}
		err := sc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credential.pat.token is required")
	})

	t.Run("pat invalid scheme", func(t *testing.T) {
		sc := &ServerConfig{ServerFlow: auth.FlowPAT, Credential: CredentialConfig{
			PAT: &PATCredentialConfig{Token: "plain-value"},
		}}
		err := sc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credential.pat.token")
	})

	t.Run("pat valid env scheme", func(t *testing.T) {
		sc := &ServerConfig{ServerFlow: auth.FlowPAT, Credential: CredentialConfig{
			PAT: &PATCredentialConfig{Token: "env://GITHUB_TOKEN"},
		}}
		err := sc.Validate()
		assert.NoError(t, err)
	})

	t.Run("pat valid file scheme", func(t *testing.T) {
		sc := &ServerConfig{ServerFlow: auth.FlowPAT, Credential: CredentialConfig{
			PAT: &PATCredentialConfig{Token: "file:///var/run/pat"},
		}}
		err := sc.Validate()
		assert.NoError(t, err)
	})

	t.Run("github_app missing app config", func(t *testing.T) {
		sc := &ServerConfig{ServerFlow: auth.FlowGitHubApp, Credential: CredentialConfig{}}
		err := sc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credential.app is required")
	})

	t.Run("github_app missing app ID and client ID", func(t *testing.T) {
		sc := &ServerConfig{ServerFlow: auth.FlowGitHubApp, Credential: CredentialConfig{
			App: &AppCredentialConfig{InstallationID: 123, PrivateKey: "env://KEY"},
		}}
		err := sc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "clientId or credential.app.appId is required")
	})

	t.Run("github_app missing installation ID", func(t *testing.T) {
		sc := &ServerConfig{ServerFlow: auth.FlowGitHubApp, Credential: CredentialConfig{
			App: &AppCredentialConfig{ClientID: "Iv23li", PrivateKey: "env://KEY"},
		}}
		err := sc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credential.app.installationId is required")
	})

	t.Run("github_app missing private key", func(t *testing.T) {
		sc := &ServerConfig{ServerFlow: auth.FlowGitHubApp, Credential: CredentialConfig{
			App: &AppCredentialConfig{ClientID: "Iv23li", InstallationID: 123},
		}}
		err := sc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credential.app.privateKey is required")
	})

	t.Run("github_app invalid private key scheme", func(t *testing.T) {
		sc := &ServerConfig{ServerFlow: auth.FlowGitHubApp, Credential: CredentialConfig{
			App: &AppCredentialConfig{ClientID: "Iv23li", InstallationID: 123, PrivateKey: "plain"},
		}}
		err := sc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credential.app.privateKey")
	})

	t.Run("github_app valid with clientId", func(t *testing.T) {
		t.Setenv("KEY", "test-key")
		sc := &ServerConfig{ServerFlow: auth.FlowGitHubApp, Credential: CredentialConfig{
			App: &AppCredentialConfig{ClientID: "Iv23li", InstallationID: 123, PrivateKey: "env://KEY"},
		}}
		err := sc.Validate()
		assert.NoError(t, err)
	})

	t.Run("github_app valid with appId", func(t *testing.T) {
		tempDir := t.TempDir()
		keyFile, err := os.CreateTemp(tempDir, "key.pem")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(keyFile.Name(), []byte("test-key"), 0o600))
		require.NoError(t, keyFile.Close())

		sc := &ServerConfig{ServerFlow: auth.FlowGitHubApp, Credential: CredentialConfig{
			App: &AppCredentialConfig{AppID: 12345, InstallationID: 123, PrivateKey: sdkplugin.SecretRef("file://" + keyFile.Name())},
		}}
		err = sc.Validate()
		assert.NoError(t, err)
	})

	t.Run("default hostname", func(t *testing.T) {
		sc := &ServerConfig{}
		assert.Equal(t, DefaultHostname, sc.GetHostname())
	})

	t.Run("custom hostname", func(t *testing.T) {
		sc := &ServerConfig{Hostname: "github.example.com"}
		assert.Equal(t, "github.example.com", sc.GetHostname())
	})

	t.Run("API base URL default", func(t *testing.T) {
		sc := &ServerConfig{}
		assert.Equal(t, "https://api.github.com", sc.GetAPIBaseURL())
	})

	t.Run("API base URL GHES", func(t *testing.T) {
		sc := &ServerConfig{Hostname: "github.example.com"}
		assert.Equal(t, "https://github.example.com/api/v3", sc.GetAPIBaseURL())
	})
}

func TestActivateServerMode(t *testing.T) {
	// Helper for a valid PAT server config.
	newPATServerConfig := func(t *testing.T) *ServerConfig {
		t.Helper()
		t.Setenv("TEST_PAT", "ghp_test123")
		return &ServerConfig{
			ServerFlow: auth.FlowPAT,
			Credential: CredentialConfig{
				PAT: &PATCredentialConfig{Token: "env://TEST_PAT"},
			},
		}
	}

	t.Run("succeeds with PAT credential", func(t *testing.T) {
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := newPATServerConfig(t)
		err := p.activateServerMode(context.Background(), sc)
		require.NoError(t, err)
		assert.NotNil(t, p.mode)
	})

	t.Run("registers server strategy", func(t *testing.T) {
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := newPATServerConfig(t)
		err := p.activateServerMode(context.Background(), sc)
		require.NoError(t, err)
		sm := p.mode.(*githubServerMode)
		assert.Contains(t, sm.strategies, auth.ServerContextServer)
	})

	t.Run("registers delegated strategy when enabled", func(t *testing.T) {
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := newPATServerConfig(t)
		sc.Delegated = true
		err := p.activateServerMode(context.Background(), sc)
		require.NoError(t, err)
		sm := p.mode.(*githubServerMode)
		assert.Contains(t, sm.strategies, auth.ServerContextServer)
		assert.Contains(t, sm.strategies, auth.ServerContextDelegated)
	})

	t.Run("no delegated strategy when false", func(t *testing.T) {
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := newPATServerConfig(t)
		err := p.activateServerMode(context.Background(), sc)
		require.NoError(t, err)
		sm := p.mode.(*githubServerMode)
		assert.Contains(t, sm.strategies, auth.ServerContextServer)
		_, hasDelegated := sm.strategies[auth.ServerContextDelegated]
		assert.False(t, hasDelegated)
	})

	t.Run("ActivateServerMode via settings", func(t *testing.T) {
		t.Setenv("TEST_PAT2", "ghp_from_settings")
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		err := p.ActivateServerMode(context.Background(), json.RawMessage(`{
			"serverFlow": "pat",
			"credential": {"pat": {"token": "env://TEST_PAT2"}}
		}`))
		require.NoError(t, err)
		assert.NotNil(t, p.mode)
	})

	t.Run("ActivateServerMode invalid JSON", func(t *testing.T) {
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		err := p.ActivateServerMode(context.Background(), json.RawMessage(`{invalid}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse server config")
	})

	t.Run("ActivateServerMode validation failure", func(t *testing.T) {
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		err := p.ActivateServerMode(context.Background(), json.RawMessage(`{"credential": {}}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serverFlow is required")
	})

	t.Run("PAT flow resolves token via SecretRef", func(t *testing.T) {
		t.Setenv("TEST_PAT3", "ghp_resolved")
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := &ServerConfig{
			ServerFlow: auth.FlowPAT,
			Credential: CredentialConfig{
				PAT: &PATCredentialConfig{Token: "env://TEST_PAT3"},
			},
		}
		err := p.activateServerMode(context.Background(), sc)
		require.NoError(t, err)
		resp, err := p.mode.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextServer,
		})
		require.NoError(t, err)
		assert.Equal(t, "ghp_resolved", resp.AccessToken)
		assert.Equal(t, auth.FlowPAT, resp.Flow)
	})

	t.Run("PAT flow fails on missing env var", func(t *testing.T) {
		t.Setenv("TEST_MISSING", "")
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := &ServerConfig{
			ServerFlow: auth.FlowPAT,
			Credential: CredentialConfig{
				PAT: &PATCredentialConfig{Token: "env://TEST_MISSING"},
			},
		}
		err := p.activateServerMode(context.Background(), sc)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resolving PAT")
	})
}

func TestGithubServerMode_GetToken(t *testing.T) {
	t.Run("PAT flow returns token from SecretRef", func(t *testing.T) {
		t.Setenv("TEST_GET_PAT", "ghp_server_token")
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := &ServerConfig{
			ServerFlow: auth.FlowPAT,
			Credential: CredentialConfig{
				PAT: &PATCredentialConfig{Token: "env://TEST_GET_PAT"},
			},
		}
		require.NoError(t, p.activateServerMode(context.Background(), sc))
		resp, err := p.mode.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextServer,
			Scope:         "repo",
		})
		require.NoError(t, err)
		assert.Equal(t, "ghp_server_token", resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, auth.FlowPAT, resp.Flow)
	})

	t.Run("delegated PAT flow returns token", func(t *testing.T) {
		t.Setenv("TEST_DEL_PAT", "ghp_delegated_token")
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := &ServerConfig{
			ServerFlow: auth.FlowPAT,
			Credential: CredentialConfig{
				PAT: &PATCredentialConfig{Token: "env://TEST_DEL_PAT"},
			},
			Delegated: true,
		}
		require.NoError(t, p.activateServerMode(context.Background(), sc))
		resp, err := p.mode.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextDelegated,
			Scope:         "repo",
		})
		require.NoError(t, err)
		assert.Equal(t, "ghp_delegated_token", resp.AccessToken)
	})

	t.Run("unknown server context returns error", func(t *testing.T) {
		t.Setenv("TEST_UNK_PAT", "ghp_test")
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := &ServerConfig{
			ServerFlow: auth.FlowPAT,
			Credential: CredentialConfig{
				PAT: &PATCredentialConfig{Token: "env://TEST_UNK_PAT"},
			},
		}
		require.NoError(t, p.activateServerMode(context.Background(), sc))
		_, err := p.mode.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContext("unknown"),
			Scope:         "repo",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no strategy configured for context")
	})

	t.Run("delegated returns error when not enabled", func(t *testing.T) {
		t.Setenv("TEST_NODLG", "ghp_test")
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := &ServerConfig{
			ServerFlow: auth.FlowPAT,
			Credential: CredentialConfig{
				PAT: &PATCredentialConfig{Token: "env://TEST_NODLG"},
			},
		}
		require.NoError(t, p.activateServerMode(context.Background(), sc))
		_, err := p.mode.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextDelegated,
			Scope:         "repo",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no strategy configured for context")
	})
}

func TestAllowedServerFlows(t *testing.T) {
	flows := allowedServerFlows()
	assert.Contains(t, flows, auth.FlowPAT)
	assert.Contains(t, flows, auth.FlowGitHubApp)
	assert.NotContains(t, flows, auth.FlowDeviceCode)
	assert.NotContains(t, flows, auth.FlowInteractive)
}

// generateTestPEM creates a real RSA private key in PEM format for tests.
func generateTestPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

func TestInstallationFlow_GetToken(t *testing.T) {
	t.Run("success returns installation token", func(t *testing.T) {
		pemKey := generateTestPEM(t)
		dir := t.TempDir()
		keyFile := filepath.Join(dir, "key.pem")
		require.NoError(t, os.WriteFile(keyFile, []byte(pemKey), 0o600))

		expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)
		mock := NewMockHTTPClient()
		mock.AddResponse(201, InstallationTokenResponse{
			Token:       "ghs_server_mode_token",
			ExpiresAt:   expiresAt,
			Permissions: map[string]string{"contents": "read"},
		})

		p := &Plugin{config: DefaultConfig(), httpClient: mock}
		sc := &ServerConfig{
			ServerFlow: auth.FlowGitHubApp,
			Credential: CredentialConfig{
				App: &AppCredentialConfig{
					ClientID:       "Iv23liABC123",
					InstallationID: 67890,
					PrivateKey:     sdkplugin.SecretRef("file://" + keyFile),
				},
			},
		}
		require.NoError(t, p.activateServerMode(context.Background(), sc))

		resp, err := p.mode.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextServer,
			Scope:         "contents:read",
		})
		require.NoError(t, err)
		assert.Equal(t, "ghs_server_mode_token", resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, auth.FlowGitHubApp, resp.Flow)
	})

	t.Run("delegated installation flow returns token", func(t *testing.T) {
		pemKey := generateTestPEM(t)
		dir := t.TempDir()
		keyFile := filepath.Join(dir, "key.pem")
		require.NoError(t, os.WriteFile(keyFile, []byte(pemKey), 0o600))

		expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)
		mock := NewMockHTTPClient()
		mock.AddResponse(201, InstallationTokenResponse{
			Token:     "ghs_delegated_tok",
			ExpiresAt: expiresAt,
		})

		p := &Plugin{config: DefaultConfig(), httpClient: mock}
		sc := &ServerConfig{
			ServerFlow: auth.FlowGitHubApp,
			Credential: CredentialConfig{
				App: &AppCredentialConfig{
					ClientID:       "Iv23liXYZ",
					InstallationID: 67890,
					PrivateKey:     sdkplugin.SecretRef("file://" + keyFile),
				},
			},
			Delegated: true,
		}
		require.NoError(t, p.activateServerMode(context.Background(), sc))

		// Delegated flow (first call — no prior server call to cache)
		resp, err := p.mode.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextDelegated,
		})
		require.NoError(t, err)
		assert.Equal(t, "ghs_delegated_tok", resp.AccessToken)
	})

	t.Run("cached installation flow deduplicates server and delegated calls", func(t *testing.T) {
		pemKey := generateTestPEM(t)
		dir := t.TempDir()
		keyFile := filepath.Join(dir, "key.pem")
		require.NoError(t, os.WriteFile(keyFile, []byte(pemKey), 0o600))

		expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)
		mock := NewMockHTTPClient()
		// Only one response — cache should serve the second call.
		mock.AddResponse(201, InstallationTokenResponse{
			Token:     "ghs_cached_tok",
			ExpiresAt: expiresAt,
		})

		p := &Plugin{config: DefaultConfig(), httpClient: mock}
		sc := &ServerConfig{
			ServerFlow: auth.FlowGitHubApp,
			Credential: CredentialConfig{
				App: &AppCredentialConfig{
					ClientID:       "Iv23liXYZ",
					InstallationID: 67890,
					PrivateKey:     sdkplugin.SecretRef("file://" + keyFile),
				},
			},
			Delegated: true,
		}
		require.NoError(t, p.activateServerMode(context.Background(), sc))

		// First call — hits the API
		resp1, err := p.mode.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextServer,
		})
		require.NoError(t, err)
		assert.Equal(t, "ghs_cached_tok", resp1.AccessToken)

		// Second call (delegated) — served from cache
		resp2, err := p.mode.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextDelegated,
		})
		require.NoError(t, err)
		assert.Equal(t, "ghs_cached_tok", resp2.AccessToken)

		assert.Len(t, mock.GetRequests(), 1, "cache should deduplicate — only one HTTP call")
	})

	t.Run("fails when GitHub API returns error", func(t *testing.T) {
		pemKey := generateTestPEM(t)
		dir := t.TempDir()
		keyFile := filepath.Join(dir, "key.pem")
		require.NoError(t, os.WriteFile(keyFile, []byte(pemKey), 0o600))

		mock := NewMockHTTPClient()
		mock.AddResponse(401, map[string]string{"message": "Bad credentials"})

		p := &Plugin{config: DefaultConfig(), httpClient: mock}
		sc := &ServerConfig{
			ServerFlow: auth.FlowGitHubApp,
			Credential: CredentialConfig{
				App: &AppCredentialConfig{
					ClientID:       "Iv23li",
					InstallationID: 67890,
					PrivateKey:     sdkplugin.SecretRef("file://" + keyFile),
				},
			},
		}
		require.NoError(t, p.activateServerMode(context.Background(), sc))

		_, err := p.mode.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextServer,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "creating installation token")
	})

	t.Run("fails with invalid private key", func(t *testing.T) {
		dir := t.TempDir()
		keyFile := filepath.Join(dir, "key.pem")
		require.NoError(t, os.WriteFile(keyFile, []byte("not-a-valid-pem"), 0o600))

		mock := NewMockHTTPClient()
		p := &Plugin{config: DefaultConfig(), httpClient: mock}
		sc := &ServerConfig{
			ServerFlow: auth.FlowGitHubApp,
			Credential: CredentialConfig{
				App: &AppCredentialConfig{
					ClientID:       "Iv23li",
					InstallationID: 67890,
					PrivateKey:     sdkplugin.SecretRef("file://" + keyFile),
				},
			},
		}
		require.NoError(t, p.activateServerMode(context.Background(), sc))

		_, err := p.mode.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextServer,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parsing private key")
	})

	t.Run("fails when private key file missing", func(t *testing.T) {
		mock := NewMockHTTPClient()
		p := &Plugin{config: DefaultConfig(), httpClient: mock}
		sc := &ServerConfig{
			ServerFlow: auth.FlowGitHubApp,
			Credential: CredentialConfig{
				App: &AppCredentialConfig{
					ClientID:       "Iv23li",
					InstallationID: 67890,
					PrivateKey:     "file:///nonexistent/key.pem",
				},
			},
		}
		require.NoError(t, p.activateServerMode(context.Background(), sc))

		_, err := p.mode.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextServer,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resolving private key")
	})
}

func TestCreateServerAppJWT(t *testing.T) {
	t.Run("creates valid JWT with string issuer", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		token, err := createServerAppJWT("Iv23liABC123", key)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		parsed, _, err := (&jwt.Parser{}).ParseUnverified(token, &jwt.RegisteredClaims{})
		require.NoError(t, err)

		claims, ok := parsed.Claims.(*jwt.RegisteredClaims)
		require.True(t, ok)
		assert.Equal(t, "Iv23liABC123", claims.Issuer)
		assert.WithinDuration(t, time.Now().Add(-60*time.Second), claims.IssuedAt.Time, 5*time.Second)
		assert.WithinDuration(t, time.Now().Add(10*time.Minute), claims.ExpiresAt.Time, 5*time.Second)
	})

	t.Run("creates valid JWT with numeric issuer", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		token, err := createServerAppJWT("12345", key)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		parsed, _, err := (&jwt.Parser{}).ParseUnverified(token, &jwt.RegisteredClaims{})
		require.NoError(t, err)

		claims, ok := parsed.Claims.(*jwt.RegisteredClaims)
		require.True(t, ok)
		assert.Equal(t, "12345", claims.Issuer)
	})
}
