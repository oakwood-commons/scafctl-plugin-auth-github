// Package github implements the github auth handler plugin.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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

// Plugin implements the scafctl AuthHandlerPlugin interface.
type Plugin struct {
	cfg              sdkplugin.ProviderConfig
	config           *Config
	httpClient       HTTPClient
	clock            clock.Clock
	cachedHostClient *sdkplugin.HostServiceClient
	openBrowser      BrowserOpenFunc
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
func (p *Plugin) Login(ctx context.Context, handlerName string, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	// PAT takes priority when explicitly requested or when the environment
	// provides a token and the caller did not ask for specific scopes.
	if req.Flow == auth.FlowPAT || (req.Flow == "" && HasPATCredentials() && len(req.Scopes) == 0) {
		return p.patLogin(ctx, req)
	}

	switch req.Flow { //nolint:exhaustive // Only GitHub-supported flows are handled
	case auth.FlowDeviceCode:
		return p.deviceCodeLogin(ctx, req, deviceCodeCb)
	case auth.FlowGitHubApp:
		return p.appLogin(ctx)
	case auth.FlowInteractive, "":
		if p.config.ClientSecret != "" {
			return p.authCodeLogin(ctx, req, deviceCodeCb)
		}
		return p.interactiveDeviceCodeLogin(ctx, req, deviceCodeCb)
	default:
		return nil, fmt.Errorf("unsupported flow: %s", req.Flow)
	}
}

// Logout revokes the current session.
func (p *Plugin) Logout(ctx context.Context, handlerName string) error {
	if handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}
	return p.logoutInternal(ctx)
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
func (p *Plugin) GetStatus(ctx context.Context, handlerName string) (*auth.Status, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return nil, err
	}

	// Check for PAT credentials first (highest priority)
	if HasPATCredentials() {
		return p.patStatus(ctx)
	}

	// Check if we have stored credentials
	refreshKey, _ := profileSecretKey(SecretKeyRefreshToken, profile)
	accessKey, _ := profileSecretKey(SecretKeyAccessToken, profile)
	hasRefresh := p.secretExists(ctx, refreshKey)
	hasAccess := p.secretExists(ctx, accessKey)

	if !hasRefresh && !hasAccess {
		return &auth.Status{Authenticated: false}, nil
	}

	// Load and validate metadata
	metadata, err := p.loadMetadata(ctx)
	if err != nil {
		return &auth.Status{Authenticated: false}, nil //nolint:nilerr // corrupted metadata = not authenticated
	}

	// Check if refresh token is expired
	if !metadata.RefreshTokenExpiresAt.IsZero() && time.Now().After(metadata.RefreshTokenExpiresAt) {
		return &auth.Status{
			Authenticated: false,
			Reason:        "session expired",
			Claims:        metadata.Claims,
		}, nil
	}

	return &auth.Status{
		Authenticated: true,
		Claims:        metadata.Claims,
		ExpiresAt:     metadata.RefreshTokenExpiresAt,
		LastRefresh:   metadata.LastRefresh,
		IdentityType:  auth.IdentityTypeUser,
		ClientID:      metadata.ClientID,
		Scopes:        metadata.Scopes,
	}, nil
}

// GetToken returns a valid access token, refreshing if necessary.
func (p *Plugin) GetToken(ctx context.Context, handlerName string, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	lgr := logr.FromContextOrDiscard(ctx)

	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return nil, err
	}

	// Use PAT flow if credentials are present (highest priority)
	if HasPATCredentials() {
		return p.getPATToken(ctx, req)
	}

	minValidFor := req.MinValidFor
	if minValidFor == 0 {
		minValidFor = auth.DefaultMinValidFor
	}

	lgr.V(1).Info("getting token",
		"handler", HandlerName,
		"minValidFor", minValidFor,
		"forceRefresh", req.ForceRefresh,
	)

	hostClient := p.hostClient(ctx)
	fp := fingerprintHash(p.config.Hostname)
	cacheKey := fp + ":" + defaultCacheKey

	// Check cache first (unless force refresh)
	if !req.ForceRefresh && hostClient != nil {
		token, err := cacheGet(ctx, hostClient, cacheKey, profile)
		if err == nil && token != nil && token.IsValidFor(minValidFor) {
			lgr.V(1).Info("using cached token",
				"expiresAt", token.ExpiresAt,
				"remainingValidity", token.TimeUntilExpiry(),
			)
			return &sdkplugin.TokenResponse{
				AccessToken: token.AccessToken,
				TokenType:   token.TokenType,
				ExpiresAt:   token.ExpiresAt,
				Scope:       token.Scope,
				Flow:        token.Flow,
				SessionID:   token.SessionID,
			}, nil
		}
		if err != nil {
			lgr.V(1).Info("cache lookup failed, will mint new token", "error", err)
		} else if token != nil {
			lgr.V(1).Info("cached token insufficient validity",
				"expiresAt", token.ExpiresAt,
				"remainingValidity", token.TimeUntilExpiry(),
				"requiredValidity", minValidFor,
			)
		}
	}

	// Check if we have a stored access token (non-expiring OAuth App)
	accessToken, err := p.loadAccessToken(ctx)
	if err == nil && accessToken != "" {
		token := &auth.Token{
			AccessToken: accessToken,
			TokenType:   "Bearer",
			ExpiresAt:   farFuture(),
		}
		if hostClient != nil {
			if cacheErr := cacheSet(ctx, hostClient, cacheKey, token, profile); cacheErr != nil {
				lgr.V(1).Info("failed to cache token", "error", cacheErr)
			}
		}
		return &sdkplugin.TokenResponse{
			AccessToken: token.AccessToken,
			TokenType:   token.TokenType,
			ExpiresAt:   token.ExpiresAt,
		}, nil
	}

	// Try to mint new token using refresh token
	token, err := p.mintToken(ctx)
	if err != nil {
		return nil, err
	}

	// Cache the token
	if hostClient != nil {
		if cacheErr := cacheSet(ctx, hostClient, cacheKey, token, profile); cacheErr != nil {
			lgr.V(1).Info("failed to cache token", "error", cacheErr)
		}
	}

	return &sdkplugin.TokenResponse{
		AccessToken: token.AccessToken,
		TokenType:   token.TokenType,
		ExpiresAt:   token.ExpiresAt,
		Scope:       token.Scope,
		Flow:        token.Flow,
		SessionID:   token.SessionID,
	}, nil
}

// ListCachedTokens returns metadata for all tokens stored by the GitHub handler.
func (p *Plugin) ListCachedTokens(ctx context.Context, handlerName string) ([]*auth.CachedTokenInfo, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return nil, fmt.Errorf("host service not available")
	}

	var results []*auth.CachedTokenInfo

	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return nil, err
	}

	// Refresh token (device code flow with token expiry enabled)
	refreshKey, _ := profileSecretKey(SecretKeyRefreshToken, profile)
	if p.secretExists(ctx, refreshKey) {
		info := &auth.CachedTokenInfo{
			Handler:   HandlerName,
			TokenKind: "refresh",
			Flow:      auth.FlowDeviceCode,
		}
		if metadata, err := p.loadMetadata(ctx); err == nil && metadata != nil {
			info.ExpiresAt = metadata.RefreshTokenExpiresAt
			info.CachedAt = metadata.LastRefresh
			info.SessionID = metadata.SessionID
			if metadata.Flow != "" {
				info.Flow = metadata.Flow
			}
		}
		if !info.ExpiresAt.IsZero() {
			info.IsExpired = time.Now().After(info.ExpiresAt)
		}
		results = append(results, info)
	}

	// Minted access tokens from cache
	entries, _ := cacheListEntries(ctx, hostClient, profile)
	results = append(results, entries...)

	// Direct access token not in cache
	accessKey, _ := profileSecretKey(SecretKeyAccessToken, profile)
	if p.secretExists(ctx, accessKey) {
		fp := fingerprintHash(p.config.Hostname)
		cacheKey := fp + ":" + defaultCacheKey
		cached, cacheErr := cacheGet(ctx, hostClient, cacheKey, profile)
		if cacheErr != nil || cached == nil {
			info := &auth.CachedTokenInfo{
				Handler:   HandlerName,
				TokenKind: "access",
				TokenType: "Bearer",
			}
			if metadata, err := p.loadMetadata(ctx); err == nil && metadata != nil {
				info.CachedAt = metadata.LastRefresh
				info.SessionID = metadata.SessionID
				info.Flow = metadata.Flow
			}
			results = append(results, info)
		}
	}

	return results, nil
}

// PurgeExpiredTokens removes expired access tokens from the cache.
func (p *Plugin) PurgeExpiredTokens(ctx context.Context, handlerName string) (int, error) {
	if handlerName != HandlerName {
		return 0, fmt.Errorf("unknown handler: %s", handlerName)
	}

	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return 0, nil
	}

	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return 0, err
	}

	return cachePurgeExpired(ctx, hostClient, profile)
}

// DetectAvailableFlows reports which auth flows are available based on
// environment credentials or configuration.
func (p *Plugin) DetectAvailableFlows(_ context.Context, handlerName string) ([]sdkplugin.FlowAvailability, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	var flows []sdkplugin.FlowAvailability

	// PAT flow -- check environment variables
	if HasPATCredentials() {
		envVar := EnvGitHubToken
		if GetPATFromEnv() == os.Getenv(EnvGHToken) && os.Getenv(EnvGitHubToken) == "" {
			envVar = EnvGHToken
		}
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowPAT,
			Available: true,
			Reason:    fmt.Sprintf("%s is set", envVar),
		})
	} else {
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowPAT,
			Available: false,
			Reason:    fmt.Sprintf("neither %s nor %s is set", EnvGitHubToken, EnvGHToken),
		})
	}

	// GitHub App flow -- check for app ID and private key indicators
	hasAppID := p.config.GetAppID() != 0
	hasPrivateKey := p.config.PrivateKey != "" || p.config.PrivateKeyPath != "" ||
		p.config.PrivateKeySecretName != "" ||
		os.Getenv(EnvGitHubAppPrivateKey) != "" ||
		os.Getenv(EnvGitHubAppPrivateKeyPath) != ""

	if hasAppID && hasPrivateKey {
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowGitHubApp,
			Available: true,
			Reason:    "GitHub App ID and private key are configured",
		})
	} else {
		reason := "GitHub App credentials not configured"
		if hasAppID && !hasPrivateKey {
			reason = "GitHub App ID is set but private key is missing"
		} else if !hasAppID && hasPrivateKey {
			reason = "private key is set but GitHub App ID is missing"
		}
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowGitHubApp,
			Available: false,
			Reason:    reason,
		})
	}

	// Device code flow -- always available (uses built-in OAuth App client ID)
	flows = append(flows, sdkplugin.FlowAvailability{
		Flow:      auth.FlowDeviceCode,
		Available: true,
		Reason:    "device code flow is always available",
	})

	// Interactive flow -- always available
	flows = append(flows, sdkplugin.FlowAvailability{
		Flow:      auth.FlowInteractive,
		Available: true,
		Reason:    "interactive flow is always available",
	})

	return flows, nil
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
