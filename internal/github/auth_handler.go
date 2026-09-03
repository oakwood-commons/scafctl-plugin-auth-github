// Package github implements the github auth handler plugin.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"

	"github.com/oakwood-commons/scafctl-plugin-auth-github/internal/clock"
)

const (
	// HandlerName is the unique identifier for this auth handler.
	HandlerName = "github"

	// HandlerDisplayName is the human-readable name for the handler.
	HandlerDisplayName = "GitHub"

	// Version is the auth handler version.
	Version = "0.1.0"

	// SecretKeyRefreshToken is the secret key for storing the refresh token.
	SecretKeyRefreshToken = "scafctl.auth.github.refresh_token" //nolint:gosec // key name, not a credential

	// SecretKeyAccessToken is the secret key for storing the access token.
	SecretKeyAccessToken = "scafctl.auth.github.access_token" //nolint:gosec // key name, not a credential

	// SecretKeyMetadata is the secret key for storing token metadata.
	SecretKeyMetadata = "scafctl.auth.github.metadata" //nolint:gosec // key name, not a credential

	// SecretKeyTokenPrefix is the prefix for cached access tokens.
	SecretKeyTokenPrefix = "scafctl.auth.github.token." //nolint:gosec // key prefix, not a credential

	// DefaultTimeout is the default timeout for device code flow.
	DefaultTimeout = 5 * time.Minute

	// DefaultMinPollInterval is the minimum polling interval for device code flow.
	DefaultMinPollInterval = 5 * time.Second

	// defaultCacheKey is the fixed cache key for GitHub tokens.
	defaultCacheKey = "_github"

	// secretKeyBase is the common prefix for all GitHub auth secret keys.
	secretKeyBase = "scafctl.auth.github."
)

// errInvalidProfile is returned when a profile name contains characters that
// would collide with the secret-key namespace structure.
var errInvalidProfile = fmt.Errorf("profile name must not contain '.', '/', '\\', or ':'")

// validateProfile checks that the profile name is safe for use in secret-key
// namespacing. An empty profile (the default) is always valid.
func validateProfile(profile string) error {
	if profile != "" && strings.ContainsAny(profile, "./\\:") {
		return errInvalidProfile
	}
	return nil
}

// profileSecretKey returns the secret key namespaced by profile.
// For the default (empty) profile, the key is unchanged for backward compatibility.
func profileSecretKey(key, profile string) (string, error) {
	if err := validateProfile(profile); err != nil {
		return "", err
	}
	if profile == "" {
		return key, nil
	}
	return secretKeyBase + profile + "." + strings.TrimPrefix(key, secretKeyBase), nil
}

// profileTokenPrefix returns the token cache prefix namespaced by profile.
func profileTokenPrefix(profile string) (string, error) {
	if err := validateProfile(profile); err != nil {
		return "", err
	}
	if profile == "" {
		return SecretKeyTokenPrefix, nil
	}
	return secretKeyBase + profile + ".token.", nil
}

// BrowserOpenFunc is the signature for a function that opens a URL in the browser.
type BrowserOpenFunc func(ctx context.Context, url string) error

var _ sdkplugin.ServerMode = (*Plugin)(nil) // compile-time interface check
// Plugin implements the scafctl AuthHandlerPlugin interface.
type Plugin struct {
	cfg              sdkplugin.ProviderConfig
	config           *Config
	httpClient       HTTPClient
	clock            clock.Clock
	cachedHostClient *sdkplugin.HostServiceClient
	openBrowser      BrowserOpenFunc
	mode             mode
}

// GetAuthHandlers returns the list of auth handlers exposed by this plugin.
//
//nolint:revive // ctx required by interface
func (p *Plugin) GetAuthHandlers(_ context.Context) ([]sdkplugin.AuthHandlerInfo, error) {
	return []sdkplugin.AuthHandlerInfo{
		{
			Name:        HandlerName,
			DisplayName: HandlerDisplayName,
			Flows: []auth.Flow{
				auth.FlowInteractive,
				auth.FlowDeviceCode,
				auth.FlowPAT,
				auth.FlowGitHubApp,
			},
			Capabilities: []auth.Capability{
				auth.CapScopesOnLogin,
				auth.CapHostname,
				auth.CapCallbackPort,
			},
		},
	}, nil
}

// ConfigureAuthHandler stores host-side configuration and initializes the handler.
func (p *Plugin) ConfigureAuthHandler(ctx context.Context, handlerName string, cfg sdkplugin.ProviderConfig) error {
	if handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}

	p.cfg = cfg

	// Initialize config with defaults
	p.config = DefaultConfig()

	// Parse handler-specific settings if provided
	if raw, ok := cfg.Settings[HandlerName]; ok {
		if err := json.Unmarshal(raw, p.config); err != nil {
			return fmt.Errorf("failed to parse handler config: %w", err)
		}
	}

	if err := p.config.Validate(); err != nil {
		return err
	}

	// Initialize clock
	p.clock = clock.Real{}

	// Cache the host client for later use
	p.cachedHostClient = sdkplugin.HostClientFromContext(ctx)

	// Initialize HTTP client only if not already set (e.g. by tests)
	if p.httpClient == nil {
		httpLogger := logr.FromContextOrDiscard(ctx).V(5) // high verbosity for auth HTTP
		p.httpClient = NewDefaultHTTPClient(httpLogger)
	}

	// Initialize browser opener (can be overridden for testing)
	if p.openBrowser == nil {
		p.openBrowser = defaultBrowserOpener
	}

	// Default to CLI mode
	p.mode = &cliMode{p: p}

	return nil
}

// Login performs the authentication flow.
//
// Flow selection precedence:
//  1. Explicit FlowPAT — uses PAT from environment.
//  2. Implicit PAT — when no flow is specified, GITHUB_TOKEN/GH_TOKEN is set,
//     and no explicit scopes are requested, PAT is used automatically.
//  3. Explicit FlowDeviceCode — device code polling flow.
//  4. Explicit FlowGitHubApp — GitHub App installation token flow.
//  5. Explicit FlowInteractive or empty flow — if ClientSecret is configured,
//     uses authorization code + PKCE; otherwise falls back to device code with
//     automatic browser opening.

// activeMode returns the current mode. This guard returns an explicit error
// rather than panicking if the invariant is violated.
func (p *Plugin) activeMode() (mode, error) {
	if p.mode == nil {
		return nil, fmt.Errorf("auth handler not configured: call ConfigureAuthHandler or ActivateServerMode first")
	}
	return p.mode, nil
}

// Login delegates to the active mode (CLI mode by default).
func (p *Plugin) Login(ctx context.Context, handlerName string, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}
	m, err := p.activeMode()
	if err != nil {
		return nil, err
	}
	return m.Login(ctx, req, deviceCodeCb)
}

// Logout revokes the current session.
// Delegates to the active mode (CLI mode by default).
func (p *Plugin) Logout(ctx context.Context, handlerName string, _ sdkplugin.LogoutRequest) error {
	if handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}
	m, err := p.activeMode()
	if err != nil {
		return err
	}
	return m.Logout(ctx)
}

// logoutInternal clears stored credentials and cached tokens.
func (p *Plugin) logoutInternal(ctx context.Context) error {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("logging out", "handler", HandlerName)

	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return fmt.Errorf("host service not available")
	}

	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return err
	}

	// Clear all cached tokens
	cacheClear(ctx, lgr, hostClient, profile)

	// Delete refresh token
	refreshKey, _ := profileSecretKey(SecretKeyRefreshToken, profile)
	if err := hostClient.DeleteSecret(ctx, refreshKey); err != nil {
		lgr.V(1).Info("failed to delete refresh token (may not exist)", "error", err)
	}

	// Delete access token
	accessKey, _ := profileSecretKey(SecretKeyAccessToken, profile)
	if err := hostClient.DeleteSecret(ctx, accessKey); err != nil {
		lgr.V(1).Info("failed to delete access token (may not exist)", "error", err)
	}

	// Delete metadata
	metaKey, _ := profileSecretKey(SecretKeyMetadata, profile)
	if err := hostClient.DeleteSecret(ctx, metaKey); err != nil {
		lgr.V(1).Info("failed to delete metadata (may not exist)", "error", err)
	}

	return nil
}

// GetStatus returns the current authentication status.
// Delegates to the active mode (CLI mode by default).
func (p *Plugin) GetStatus(ctx context.Context, handlerName string, _ sdkplugin.StatusRequest) (*auth.Status, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}
	m, err := p.activeMode()
	if err != nil {
		return nil, err
	}
	return m.GetStatus(ctx)
}

// GetToken returns a valid access token, refreshing if necessary.
// Delegates to the active mode (CLI mode by default).
func (p *Plugin) GetToken(ctx context.Context, handlerName string, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}
	m, err := p.activeMode()
	if err != nil {
		return nil, err
	}
	return m.GetToken(ctx, req)
}

// ListCachedTokens returns metadata for all tokens stored by the GitHub handler.
// Delegates to the active mode (CLI mode by default).
func (p *Plugin) ListCachedTokens(ctx context.Context, handlerName string) ([]*auth.CachedTokenInfo, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}
	m, err := p.activeMode()
	if err != nil {
		return nil, err
	}
	return m.ListCachedTokens(ctx)
}

// PurgeExpiredTokens removes expired access tokens from the cache.
// Delegates to the active mode (CLI mode by default).
func (p *Plugin) PurgeExpiredTokens(ctx context.Context, handlerName string) (int, error) {
	if handlerName != HandlerName {
		return 0, fmt.Errorf("unknown handler: %s", handlerName)
	}
	m, err := p.activeMode()
	if err != nil {
		return 0, err
	}
	return m.PurgeExpiredTokens(ctx)
}

// DetectAvailableFlows reports which auth flows are available based on
// environment credentials or configuration.
// Delegates to the active mode (CLI mode by default).
func (p *Plugin) DetectAvailableFlows(ctx context.Context, handlerName string) ([]sdkplugin.FlowAvailability, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}
	m, err := p.activeMode()
	if err != nil {
		return nil, err
	}
	return m.DetectAvailableFlows(ctx)
}

// StopAuthHandler performs cleanup before plugin unload.
//
//nolint:revive // all params required by interface
func (p *Plugin) StopAuthHandler(_ context.Context, handlerName string) error {
	if handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}
	return nil
}

// farFuture returns a time far in the future for tokens with no defined expiry.
func farFuture() time.Time {
	return time.Now().Add(365 * 24 * time.Hour)
}
