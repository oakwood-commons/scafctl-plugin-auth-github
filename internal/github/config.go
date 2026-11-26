// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/httpc"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// DefaultClientID is the public OAuth App client ID shipped with scafctl.
// This is a public client (no client secret); it is safe to embed in source.
const DefaultClientID = "Ov23li6xn492GhPmt4YG"

// DefaultHostname is the default GitHub hostname.
const DefaultHostname = "github.com"

// Default HTTP client settings.
const (
	defaultHTTPTimeout         = 30 * time.Second
	defaultHTTPRetryMax        = 3
	defaultHTTPRetryWaitFloor  = 1 * time.Second
	defaultHTTPRetryWaitMax    = 10 * time.Second
	defaultHTTPClientCacheSize = 32
)

// Config holds configuration for the GitHub auth handler.
type Config struct {
	// ClientID is the GitHub OAuth App client ID.
	ClientID string `json:"clientId" yaml:"clientId"`

	// ClientSecret is the GitHub OAuth App client secret.
	// Required for the interactive (authorization code) flow.
	ClientSecret string `json:"clientSecret,omitempty" yaml:"clientSecret,omitempty"` //nolint:gosec // config field, not a hardcoded credential

	// Hostname is the GitHub hostname (e.g. github.com or github.example.com for GHES).
	Hostname string `json:"hostname" yaml:"hostname"`

	// DefaultScopes is the list of OAuth scopes to request by default.
	DefaultScopes []string `json:"defaultScopes" yaml:"defaultScopes"`

	// HTTPClient carries optional HTTP client settings forwarded by the host
	// under auth.github.httpClient or profiles.<name>.httpClient. Nil keeps
	// the plugin's defaults. HTTP response caching is always disabled on auth
	// handler clients regardless of EnableCache to prevent cross-account
	// response reuse.
	HTTPClient *httpc.AppConfig `json:"httpClient,omitempty" yaml:"httpClient,omitempty"`

	// MinPollInterval is the minimum polling interval for device code flow.
	MinPollInterval time.Duration `json:"-" yaml:"-"`

	// SlowDownIncrement is the amount to add to polling interval on slow_down.
	SlowDownIncrement time.Duration `json:"-" yaml:"-"`

	// AppID is the GitHub App ID for the installation token flow.
	AppID int64 `json:"appId,omitempty" yaml:"appId,omitempty"`

	// InstallationID is the GitHub App installation ID.
	InstallationID int64 `json:"installationId,omitempty" yaml:"installationId,omitempty"`

	// PrivateKey is the inline PEM-encoded private key for the GitHub App.
	PrivateKey string `json:"privateKey,omitempty" yaml:"privateKey,omitempty"` //nolint:gosec // field name, not a credential

	// PrivateKeyPath is the file path to the PEM-encoded private key.
	PrivateKeyPath string `json:"privateKeyPath,omitempty" yaml:"privateKeyPath,omitempty"`

	// PrivateKeySecretName is the name of the secret in the host secret store
	// that contains the PEM-encoded private key.
	PrivateKeySecretName string `json:"privateKeySecretName,omitempty" yaml:"privateKeySecretName,omitempty"`

	// hasExplicitHostname records whether Hostname was explicitly configured
	// (via handler/request JSON settings or per-RPC Hostname override) rather
	// than defaulted to DefaultHostname.
	hasExplicitHostname bool `json:"-" yaml:"-"`

	// hasHostnameOverride records whether Hostname was explicitly set via a
	// per-RPC request Hostname field (LoginRequest/StatusRequest/TokenRequest).
	hasHostnameOverride bool `json:"-" yaml:"-"`
}

// clone returns an independent copy of c so per-RPC overrides never mutate a
// shared Config instance.
func (c *Config) clone() *Config {
	if c == nil {
		return DefaultConfig()
	}
	cp := *c
	if c.DefaultScopes != nil {
		cp.DefaultScopes = append([]string(nil), c.DefaultScopes...)
	}
	if c.HTTPClient != nil {
		httpCopy := *c.HTTPClient
		cp.HTTPClient = &httpCopy
	}
	return &cp
}

// DefaultConfig returns the default GitHub auth configuration.
func DefaultConfig() *Config {
	return &Config{
		ClientID:          DefaultClientID,
		Hostname:          DefaultHostname,
		MinPollInterval:   5 * time.Second,
		SlowDownIncrement: 5 * time.Second,
	}
}

// validateHostname checks that h is a safe host or host:port value with no
// control characters, whitespace, or URL path/query/fragment/userinfo delimiters.
func validateHostname(h string) error {
	if h == "" {
		return fmt.Errorf("github auth: hostname is required")
	}
	if !utf8.ValidString(h) {
		return fmt.Errorf("github auth: hostname contains invalid characters")
	}
	for _, r := range h {
		if r <= 0x20 || r == 0x7f || unicode.IsSpace(r) || unicode.IsControl(r) ||
			r == 0x061c || r == 0x200e || r == 0x200f ||
			(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return fmt.Errorf("github auth: hostname contains invalid characters")
		}
	}
	if strings.ContainsAny(h, ";\"'/\\?#@%") {
		return fmt.Errorf("github auth: hostname contains invalid characters")
	}
	if strings.Contains(h, ":") || strings.HasPrefix(h, "[") || strings.HasSuffix(h, "]") {
		host, portStr, err := net.SplitHostPort(h)
		if err != nil {
			return fmt.Errorf("github auth: hostname contains invalid characters")
		}
		if host == "" {
			return fmt.Errorf("github auth: hostname is empty")
		}
		port, pErr := strconv.Atoi(portStr)
		if pErr != nil || port < 1 || port > 65535 {
			return fmt.Errorf("github auth: hostname has invalid port")
		}
	}
	u, err := url.Parse("https://" + h)
	if err != nil || u.Host != h || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("github auth: hostname contains invalid characters")
	}
	return nil
}

// Validate checks the configuration for required fields.
func (c *Config) Validate() error {
	if c.ClientID == "" {
		return fmt.Errorf("github auth: client ID is required")
	}
	return validateHostname(c.Hostname)
}

// GetOAuthBaseURL returns the base URL for GitHub OAuth endpoints.
func (c *Config) GetOAuthBaseURL() string {
	if c.Hostname == DefaultHostname {
		return "https://github.com"
	}
	return fmt.Sprintf("https://%s", c.Hostname)
}

// GetAPIBaseURL returns the base URL for GitHub API endpoints.
func (c *Config) GetAPIBaseURL() string {
	if c.Hostname == DefaultHostname {
		return "https://api.github.com"
	}
	return fmt.Sprintf("https://%s/api/v3", c.Hostname)
}

// GitHub App environment variable names.
const (
	// EnvGitHubAppID is the environment variable for the GitHub App ID.
	EnvGitHubAppID = "GITHUB_APP_ID"

	// EnvGitHubAppInstallationID is the environment variable for the GitHub App installation ID.
	EnvGitHubAppInstallationID = "GITHUB_APP_INSTALLATION_ID"

	// EnvGitHubAppPrivateKey is the environment variable for the inline PEM-encoded private key.
	EnvGitHubAppPrivateKey = "GITHUB_APP_PRIVATE_KEY" //nolint:gosec // env var name, not a credential

	// EnvGitHubAppPrivateKeyPath is the environment variable for the private key file path.
	EnvGitHubAppPrivateKeyPath = "GITHUB_APP_PRIVATE_KEY_PATH" //nolint:gosec // env var name, not a credential
)

// GetPrivateKey resolves the GitHub App private key from (in priority order):
// 1. Inline PrivateKey field / GITHUB_APP_PRIVATE_KEY env var
// 2. PrivateKeyPath field / GITHUB_APP_PRIVATE_KEY_PATH env var (read from file)
// 3. PrivateKeySecretName via the host's secret store
func (c *Config) GetPrivateKey(ctx context.Context, lgr logr.Logger, hostClient *sdkplugin.HostServiceClient) ([]byte, error) {
	// 1. Inline PEM (field or env var)
	key := c.PrivateKey
	if key == "" {
		key = os.Getenv(EnvGitHubAppPrivateKey)
	}
	if key != "" {
		lgr.Info("WARNING: GitHub App private key loaded from inline config or environment variable; " +
			"prefer privateKeySecretName (secret store) or privateKeyPath (file) for better protection",
		)
		return []byte(key), nil
	}

	// 2. File path (field or env var)
	path := c.PrivateKeyPath
	if path == "" {
		path = os.Getenv(EnvGitHubAppPrivateKeyPath)
	}
	if path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // user-provided path to their own private key
		if err != nil {
			return nil, fmt.Errorf("reading private key from %s: %w", path, err)
		}
		return data, nil
	}

	// 3. Host secret store
	if c.PrivateKeySecretName != "" && hostClient != nil {
		value, found, err := hostClient.GetSecret(ctx, c.PrivateKeySecretName)
		if err != nil {
			return nil, fmt.Errorf("reading private key from secret store (%s): %w", c.PrivateKeySecretName, err)
		}
		if !found {
			return nil, fmt.Errorf("private key secret %q not found in secret store", c.PrivateKeySecretName)
		}
		return []byte(value), nil
	}

	return nil, fmt.Errorf("no private key configured: set %s env var, provide --private-key flag, or configure privateKeyPath/privateKeySecretName in config", EnvGitHubAppPrivateKey)
}

// GetAppID returns the App ID from config or the GITHUB_APP_ID environment variable.
func (c *Config) GetAppID() int64 {
	if c.AppID != 0 {
		return c.AppID
	}
	if v := os.Getenv(EnvGitHubAppID); v != "" {
		var id int64
		if _, err := fmt.Sscanf(v, "%d", &id); err == nil {
			return id
		}
	}
	return 0
}

// GetInstallationID returns the Installation ID from config or environment.
func (c *Config) GetInstallationID() int64 {
	if c.InstallationID != 0 {
		return c.InstallationID
	}
	if v := os.Getenv(EnvGitHubAppInstallationID); v != "" {
		var id int64
		if _, err := fmt.Sscanf(v, "%d", &id); err == nil {
			return id
		}
	}
	return 0
}

// ValidateAppConfig checks that all required GitHub App fields are present.
func (c *Config) ValidateAppConfig(ctx context.Context, lgr logr.Logger, hostClient *sdkplugin.HostServiceClient) error {
	if c.GetAppID() == 0 {
		return fmt.Errorf("github app: app ID is required (set %s or configure appId)", EnvGitHubAppID)
	}
	if c.GetInstallationID() == 0 {
		return fmt.Errorf("github app: installation ID is required (set %s or configure installationId)", EnvGitHubAppInstallationID)
	}
	if _, err := c.GetPrivateKey(ctx, lgr, hostClient); err != nil {
		return fmt.Errorf("github app: %w", err)
	}
	return nil
}

// ServerConfig is the standalone configuration for GitHub server mode,
// passed via ActivateServerModeRequest settings.
type ServerConfig struct {
	// Hostname is the GitHub hostname (e.g. github.com or github.example.com for GHES).
	Hostname string `json:"hostname,omitempty"`

	// ServerFlow identifies the credential type: "pat" or "github_app".
	ServerFlow auth.Flow `json:"serverFlow"`

	// Credential holds the credential configuration for the server flow.
	Credential CredentialConfig `json:"credential"`

	// Delegated enables delegated token acquisition using the same server credential.
	Delegated bool `json:"delegated,omitempty"`
}

// CredentialConfig specifies the credential parameters.
type CredentialConfig struct {
	// PAT holds the PAT credential configuration (when ServerFlow is "pat").
	PAT *PATCredentialConfig `json:"pat,omitempty"`

	// App holds the GitHub App credential configuration (when ServerFlow is "github_app").
	App *AppCredentialConfig `json:"app,omitempty"`
}

// PATCredentialConfig holds the PAT credential reference.
type PATCredentialConfig struct {
	// Token is a SecretRef pointing to the PAT value (env://..., file://..., or secret://...).
	Token sdkplugin.SecretRef `json:"token"`
}

// AppCredentialConfig holds the GitHub App credential references.
type AppCredentialConfig struct {
	// ClientID is the GitHub App's Client ID (e.g. "Iv23li...").
	ClientID string `json:"clientId,omitempty"`

	// AppID is the numeric GitHub App ID (legacy, prefer ClientID).
	AppID int64 `json:"appId,omitempty"`

	// InstallationID is the GitHub App installation ID.
	InstallationID int64 `json:"installationId"`

	// PrivateKey is a SecretRef pointing to the PEM-encoded private key.
	PrivateKey sdkplugin.SecretRef `json:"privateKey"`
}

// Validate checks the ServerConfig for required fields.
func (sc *ServerConfig) Validate() error {
	if sc.Hostname != "" {
		if err := validateHostname(sc.Hostname); err != nil {
			return err
		}
	}
	if sc.ServerFlow == "" {
		return fmt.Errorf("serverFlow is required")
	}
	if !isAllowedServerFlow(sc.ServerFlow) {
		return fmt.Errorf("serverFlow %q is not allowed (allowed: pat, github_app)", sc.ServerFlow)
	}

	cc := &sc.Credential
	switch sc.ServerFlow {
	case auth.FlowPAT:
		if cc.PAT == nil || cc.PAT.Token == "" {
			return fmt.Errorf("credential.pat.token is required for pat server flow")
		}
		if err := cc.PAT.Token.Validate(); err != nil {
			return fmt.Errorf("credential.pat.token: %w", err)
		}
	case auth.FlowGitHubApp:
		if cc.App == nil {
			return fmt.Errorf("credential.app is required for github_app server flow")
		}
		if cc.App.ClientID == "" && cc.App.AppID == 0 {
			return fmt.Errorf("credential.app.clientId or credential.app.appId is required")
		}
		if cc.App.InstallationID == 0 {
			return fmt.Errorf("credential.app.installationId is required")
		}
		if cc.App.PrivateKey == "" {
			return fmt.Errorf("credential.app.privateKey is required")
		}

		if err := cc.App.PrivateKey.Validate(); err != nil {
			return fmt.Errorf("credential.app.privateKey: %w", err)
		}

		// Eagerly verify env:// and file:// references during Validate();
		// secret:// references require a HostServiceClient and are verified in
		// activateServerMode.
		if cc.App.PrivateKey.Scheme() != "secret" {
			if _, err := cc.App.PrivateKey.Resolve(); err != nil {
				return fmt.Errorf("resolving private key: %w", err)
			}
		}
	}
	return nil
}

// GetHostname returns the configured hostname or the default.
func (sc *ServerConfig) GetHostname() string {
	if sc.Hostname != "" {
		return sc.Hostname
	}
	return DefaultHostname
}

// GetAPIBaseURL returns the API base URL for the configured hostname.
func (sc *ServerConfig) GetAPIBaseURL() string {
	h := sc.GetHostname()
	if h == DefaultHostname {
		return "https://api.github.com"
	}
	return fmt.Sprintf("https://%s/api/v3", h)
}
