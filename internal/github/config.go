// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"net"
	"strings"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// DefaultClientID is the public OAuth App client ID shipped with scafctl.
// This is a public client (no client secret); it is safe to embed in source.
const DefaultClientID = "Ov23li6xn492GhPmt4YG"

// DefaultHostname is the default GitHub hostname.
const DefaultHostname = "github.com"

// Default HTTP client settings.
const (
	defaultHTTPTimeout      = 30 * time.Second
	defaultHTTPRetryMax     = 3
	defaultHTTPRetryWaitFloor = 1 * time.Second
	defaultHTTPRetryWaitMax = 10 * time.Second
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

// Validate checks the configuration for required fields.
func (c *Config) Validate() error {
	if c.ClientID == "" {
		return fmt.Errorf("github auth: client ID is required")
	}
	if c.Hostname == "" {
		return fmt.Errorf("github auth: hostname is required")
	}
	// Reject hostnames with characters that could cause malformed URLs.
	if strings.ContainsAny(c.Hostname, " \t\n\r;\"'") {
		return fmt.Errorf("github auth: hostname contains invalid characters")
	}
	if host, _, err := net.SplitHostPort(c.Hostname); err == nil {
		if host == "" {
			return fmt.Errorf("github auth: hostname is empty")
		}
	}
	return nil
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
