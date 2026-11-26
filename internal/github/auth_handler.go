// Package github implements the github auth handler plugin.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/httpc"
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

	// defaultCredentialCleanupTimeout bounds detached rollback/cleanup RPCs on
	// the host secret store so a stalled host never blocks Login or callback
	// settlement indefinitely.
	defaultCredentialCleanupTimeout = 5 * time.Second
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

var (
	_ sdkplugin.AuthHandlerPlugin = (*Plugin)(nil)
	_ sdkplugin.ServerMode        = (*Plugin)(nil)
)

type resolvedConfigKeyType struct{}

func withResolvedConfig(ctx context.Context, cfg *Config) context.Context {
	return context.WithValue(ctx, resolvedConfigKeyType{}, cfg)
}

func resolvedConfigFromContext(ctx context.Context) (*Config, bool) {
	cfg, ok := ctx.Value(resolvedConfigKeyType{}).(*Config)
	return cfg, ok && cfg != nil
}

type hostnameOverrideKeyType struct{}

func withHostnameOverride(ctx context.Context, hostname string) context.Context {
	if hostname == "" {
		return ctx
	}
	return context.WithValue(ctx, hostnameOverrideKeyType{}, hostname)
}

func hostnameOverrideFromContext(ctx context.Context) string {
	v, _ := ctx.Value(hostnameOverrideKeyType{}).(string)
	return v
}

func attachRequestSettings(ctx context.Context, reqSettings map[string]json.RawMessage) context.Context {
	if _, ok := sdkplugin.RequestSettingsFromContext(ctx); !ok && reqSettings != nil {
		return sdkplugin.WithRequestSettings(ctx, reqSettings)
	}
	return ctx
}

func parseHandlerConfig(raw []byte) (*Config, error) {
	cfg := DefaultConfig()
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse handler config: %w", err)
		}
		var rawMap map[string]json.RawMessage
		if err := json.Unmarshal(raw, &rawMap); err == nil {
			if hostVal, hasHost := rawMap["hostname"]; hasHost {
				trimmed := bytes.TrimSpace(hostVal)
				if len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) && !bytes.Equal(trimmed, []byte(`""`)) {
					cfg.hasExplicitHostname = true
				}
			}
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func sanitizeCallbackPages(pages *sdkplugin.AuthCallbackPages) *sdkplugin.AuthCallbackPages {
	if pages == nil {
		return nil
	}
	var out sdkplugin.AuthCallbackPages
	if len(pages.SuccessHTML) > 0 && len(pages.SuccessHTML) <= sdkplugin.MaxAuthCallbackPageBytes {
		out.SuccessHTML = append([]byte(nil), pages.SuccessHTML...)
	}
	if len(pages.FailureHTML) > 0 && len(pages.FailureHTML) <= sdkplugin.MaxAuthCallbackPageBytes {
		out.FailureHTML = append([]byte(nil), pages.FailureHTML...)
	}
	if len(out.SuccessHTML) == 0 && len(out.FailureHTML) == 0 {
		return nil
	}
	return &out
}

// Plugin implements the scafctl AuthHandlerPlugin interface.
type Plugin struct {
	mu               sync.RWMutex
	cfg              sdkplugin.ProviderConfig
	config           *Config
	httpClient       HTTPClient
	clock            clock.Clock
	cachedHostClient *sdkplugin.HostServiceClient
	openBrowser      BrowserOpenFunc
	mode             mode
	cleanupTimeout   time.Duration
	baseLogger       logr.Logger
	initHTTPKey      effectiveHTTPConfigKey
	hasInitHTTPKey   bool
	serverModeHTTP   *DefaultHTTPClient

	profileLocks sync.Map
	refreshLocks sync.Map

	clientCacheMu   sync.Mutex
	clientCacheSize int
	cacheStopped    bool
	httpClientCache *boundedClientCache[effectiveHTTPConfigKey, *DefaultHTTPClient]
}

// profileLock returns the profile-scoped RWMutex coordinating in-process
// credential writes, rollbacks, logouts, and session reads.
func (p *Plugin) profileLock(profile string) *sync.RWMutex {
	if v, ok := p.profileLocks.Load(profile); ok {
		return v.(*sync.RWMutex)
	}
	mu := &sync.RWMutex{}
	actual, _ := p.profileLocks.LoadOrStore(profile, mu)
	return actual.(*sync.RWMutex)
}

// refreshSlot returns the profile-scoped 1-buffered channel semaphore that
// coalesces concurrent OAuth refresh-token rotations with context-aware waiting.
func (p *Plugin) refreshSlot(profile string) chan struct{} {
	if v, ok := p.refreshLocks.Load(profile); ok {
		return v.(chan struct{})
	}
	sem := make(chan struct{}, 1)
	actual, _ := p.refreshLocks.LoadOrStore(profile, sem)
	return actual.(chan struct{})
}

func (p *Plugin) acquireRefreshSlot(ctx context.Context, profile string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sem := p.refreshSlot(profile)
	select {
	case sem <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() {
				<-sem
			})
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *Plugin) newCleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	p.mu.RLock()
	timeout := p.cleanupTimeout
	p.mu.RUnlock()
	if timeout <= 0 {
		timeout = defaultCredentialCleanupTimeout
	}
	return context.WithTimeout(context.WithoutCancel(ctx), timeout)
}

func (p *Plugin) baseConfig() *Config {
	p.mu.RLock()
	cfg := p.config
	p.mu.RUnlock()
	if cfg != nil {
		return cfg
	}
	return DefaultConfig()
}

func (p *Plugin) authCallbackPages() *sdkplugin.AuthCallbackPages {
	p.mu.RLock()
	pages := p.cfg.AuthCallbackPages
	p.mu.RUnlock()
	return sanitizeCallbackPages(pages)
}

func (p *Plugin) getClock() clock.Clock {
	p.mu.RLock()
	clk := p.clock
	p.mu.RUnlock()
	if clk != nil {
		return clk
	}
	return clock.Real{}
}

// effectiveConfig returns the handler Config to use for ctx: per-RPC request
// settings from RequestSettingsFromContext(ctx) when present, falling back to
// the ConfigureAuthHandler config without mutating p.config, and applying any
// per-call Hostname override attached to ctx.
func (p *Plugin) effectiveConfig(ctx context.Context) (*Config, error) {
	if cfg, ok := resolvedConfigFromContext(ctx); ok {
		return applyHostnameOverride(cfg, hostnameOverrideFromContext(ctx))
	}
	baseCfg := p.baseConfig()
	if settings, ok := sdkplugin.RequestSettingsFromContext(ctx); ok {
		var raw []byte
		if nested, hasHandler := settings[HandlerName]; hasHandler {
			if !bytes.Equal(bytes.TrimSpace(nested), []byte("null")) {
				raw = nested
			}
		} else if len(settings) > 0 {
			var err error
			raw, err = json.Marshal(settings)
			if err != nil {
				return nil, fmt.Errorf("failed to encode request settings: %w", err)
			}
		}

		reqCfg, err := parseHandlerConfig(raw)
		if err != nil {
			return nil, err
		}
		reqCfg.MinPollInterval = baseCfg.MinPollInterval
		reqCfg.SlowDownIncrement = baseCfg.SlowDownIncrement
		return applyHostnameOverride(reqCfg, hostnameOverrideFromContext(ctx))
	}
	return applyHostnameOverride(baseCfg, hostnameOverrideFromContext(ctx))
}

func applyHostnameOverride(cfg *Config, hostOverride string) (*Config, error) {
	if hostOverride == "" {
		return cfg, nil
	}
	cp := cfg.clone()
	cp.Hostname = hostOverride
	cp.hasExplicitHostname = true
	cp.hasHostnameOverride = true
	if err := cp.Validate(); err != nil {
		return nil, err
	}
	return cp, nil
}

type hostnameMismatchError struct {
	stored    string
	requested string
}

func (e *hostnameMismatchError) Error() string {
	return fmt.Sprintf("stored session is authenticated to %q, not %q", e.stored, e.requested)
}

type appConfigMismatchError struct {
	field     string
	stored    int64
	requested int64
}

func (e *appConfigMismatchError) Error() string {
	return fmt.Sprintf("stored GitHub App session is authenticated for %s %d, not %d", e.field, e.stored, e.requested)
}

func isGitHubAppSession(metadata *TokenMetadata) bool {
	if metadata == nil {
		return false
	}
	return metadata.Flow == auth.FlowGitHubApp ||
		metadata.IdentityType == string(auth.IdentityTypeServicePrincipal)
}

// resolveSessionConfig reconciles cfg against stored session metadata so:
//   - a login performed with --hostname <ghes> continues using metadata.Hostname
//     on subsequent GetStatus/GetToken calls (even when host defaults forward
//     hostname: github.com in settings);
//   - an explicit hostname in config/request that disagrees with stored
//     metadata.Hostname fails closed instead of sending tokens to another host;
//   - a GitHub App session rejects mismatched AppID or InstallationID and pins
//     renewal config to the stored AppID and InstallationID.
func resolveSessionConfig(cfg *Config, metadata *TokenMetadata) (*Config, error) {
	if metadata == nil {
		return cfg, nil
	}
	out := cfg
	cloned := false
	ensureClone := func() *Config {
		if !cloned {
			out = cfg.clone()
			cloned = true
		}
		return out
	}

	if metadata.Hostname != "" {
		if err := validateHostname(metadata.Hostname); err != nil {
			return nil, fmt.Errorf("invalid stored session hostname: %w", err)
		}
		if strings.EqualFold(cfg.Hostname, metadata.Hostname) {
			if cfg.Hostname != metadata.Hostname {
				ensureClone().Hostname = metadata.Hostname
			}
		} else {
			isHostDefaultOverriddenByLogin := !cfg.hasHostnameOverride &&
				strings.EqualFold(cfg.Hostname, DefaultHostname) &&
				metadata.HostnameOverride
			if cfg.hasExplicitHostname && !isHostDefaultOverriddenByLogin {
				return nil, &hostnameMismatchError{
					stored:    metadata.Hostname,
					requested: cfg.Hostname,
				}
			}
			ensureClone().Hostname = metadata.Hostname
		}
	}

	if isGitHubAppSession(metadata) {
		if metadata.AppID != 0 {
			if cfgAppID := out.GetAppID(); cfgAppID != 0 && cfgAppID != metadata.AppID {
				return nil, &appConfigMismatchError{
					field:     "appId",
					stored:    metadata.AppID,
					requested: cfgAppID,
				}
			}
			if out.AppID != metadata.AppID {
				ensureClone().AppID = metadata.AppID
			}
		}
		if metadata.InstallationID != 0 {
			if cfgInstallID := out.GetInstallationID(); cfgInstallID != 0 && cfgInstallID != metadata.InstallationID {
				return nil, &appConfigMismatchError{
					field:     "installationId",
					stored:    metadata.InstallationID,
					requested: cfgInstallID,
				}
			}
			if out.InstallationID != metadata.InstallationID {
				ensureClone().InstallationID = metadata.InstallationID
			}
		}
	}

	return out, nil
}

func pickHTTPLogger(ctx context.Context, baseLogger logr.Logger) logr.Logger {
	if baseLogger.GetSink() != nil {
		return baseLogger.V(5)
	}
	return logr.FromContextOrDiscard(ctx).V(5)
}

func (p *Plugin) ensureHTTPClientCacheLocked() *boundedClientCache[effectiveHTTPConfigKey, *DefaultHTTPClient] {
	if p.httpClientCache == nil {
		p.httpClientCache = newBoundedClientCache[effectiveHTTPConfigKey, *DefaultHTTPClient](p.clientCacheSize)
	}
	return p.httpClientCache
}

func (p *Plugin) httpClientForConfig(ctx context.Context, cfg *Config) (HTTPClient, error) {
	client, release, err := p.acquireHTTPClient(ctx, cfg, false)
	if err != nil {
		return nil, err
	}
	release()
	return client, nil
}

// acquireHTTPClient returns an HTTPClient for cfg along with a release function.
// When holdLease is true, the cache entry stays leased until release() is called
// so LRU eviction defers closing idle connections until the caller finishes.
func (p *Plugin) acquireHTTPClient(ctx context.Context, cfg *Config, holdLease bool) (HTTPClient, func(), error) {
	noopRelease := func() {}
	var appCfg *httpc.AppConfig
	if cfg != nil {
		appCfg = cfg.HTTPClient
	}

	key, clientCfg, err := resolveEffectiveHTTPConfig(appCfg)
	if err != nil {
		return nil, noopRelease, fmt.Errorf("failed to build HTTP client from httpClient config: %w", err)
	}

	p.mu.RLock()
	curHTTP := p.httpClient
	baseCfg := p.config
	hasInit := p.hasInitHTTPKey
	initKey := p.initHTTPKey
	baseLgr := p.baseLogger
	p.mu.RUnlock()

	if curHTTP != nil {
		defHTTP, isDefault := curHTTP.(*DefaultHTTPClient)
		if !isDefault {
			return curHTTP, noopRelease, nil
		}
		if hasInit && key == initKey {
			if holdLease {
				rel, lErr := defHTTP.acquireLease()
				if lErr != nil {
					return nil, noopRelease, lErr
				}
				return defHTTP, rel, nil
			}
			return defHTTP, noopRelease, nil
		}
	} else {
		p.clientCacheMu.Lock()
		stopped := p.cacheStopped
		p.clientCacheMu.Unlock()
		if stopped {
			return nil, noopRelease, fmt.Errorf("HTTP client cache closed: auth handler stopped")
		}
		if cfg == nil || (baseCfg != nil && cfg == baseCfg) {
			return nil, noopRelease, fmt.Errorf("HTTP client not initialized")
		}
	}

	const maxCacheAttempts = 3
	for range maxCacheAttempts {
		p.clientCacheMu.Lock()
		if p.cacheStopped {
			p.clientCacheMu.Unlock()
			return nil, noopRelease, fmt.Errorf("HTTP client cache closed: auth handler stopped")
		}
		cache := p.ensureHTTPClientCacheLocked()
		p.clientCacheMu.Unlock()

		var (
			client   *DefaultHTTPClient
			release  func()
			cacheErr error
		)
		buildFn := func() *DefaultHTTPClient {
			return newDefaultHTTPClientFromResolved(clientCfg, pickHTTPLogger(ctx, baseLgr))
		}
		if holdLease {
			client, release, cacheErr = cache.Acquire(key, buildFn)
		} else {
			client, cacheErr = cache.GetOrCreate(key, buildFn)
			release = noopRelease
		}
		if errors.Is(cacheErr, errClientCacheClosed) {
			continue
		}
		if cacheErr != nil {
			return nil, noopRelease, cacheErr
		}
		return client, release, nil
	}
	return nil, noopRelease, fmt.Errorf("failed to acquire HTTP client: %w", errClientCacheClosed)
}

func (p *Plugin) closeHTTPClients() {
	var defHTTP *DefaultHTTPClient
	p.mu.Lock()
	if dh, ok := p.httpClient.(*DefaultHTTPClient); ok {
		defHTTP = dh
		p.httpClient = nil
		p.hasInitHTTPKey = false
	}
	srvHTTP := p.serverModeHTTP
	p.serverModeHTTP = nil
	p.mu.Unlock()

	p.clientCacheMu.Lock()
	p.cacheStopped = true
	httpCache := p.httpClientCache
	p.httpClientCache = nil
	p.clientCacheMu.Unlock()

	if httpCache != nil {
		httpCache.CloseAll()
	}
	if srvHTTP != nil {
		_ = srvHTTP.Close()
	}
	if defHTTP != nil {
		_ = defHTTP.Close()
	}
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

	var rawSettings []byte
	if raw, ok := cfg.Settings[HandlerName]; ok {
		rawSettings = raw
	}
	parsedCfg, err := parseHandlerConfig(rawSettings)
	if err != nil {
		return err
	}
	if strings.EqualFold(parsedCfg.Hostname, DefaultHostname) {
		// Host startup configuration (pkg/config/defaults.yaml) always forwards
		// hostname: github.com. Treat the default hostname in ConfigureAuthHandler
		// as a default rather than an explicit override constraint.
		parsedCfg.hasExplicitHostname = false
	}

	initKey, initClientCfg, err := resolveEffectiveHTTPConfig(parsedCfg.HTTPClient)
	if err != nil {
		return fmt.Errorf("failed to build HTTP client from httpClient config: %w", err)
	}

	baseLgr := logr.FromContextOrDiscard(ctx)
	httpLogger := baseLgr.V(5) // high verbosity for auth HTTP

	p.mu.RLock()
	needHTTP := p.httpClient == nil
	if !needHTTP {
		_, needHTTP = p.httpClient.(*DefaultHTTPClient)
	}
	p.mu.RUnlock()

	var nextHTTP *DefaultHTTPClient
	if needHTTP {
		nextHTTP = newDefaultHTTPClientFromResolved(initClientCfg, httpLogger)
	}

	cfgCopy := cfg
	cfgCopy.AuthCallbackPages = sanitizeCallbackPages(cfg.AuthCallbackPages)

	p.clientCacheMu.Lock()
	p.cacheStopped = false
	oldHTTPCache := p.httpClientCache
	p.httpClientCache = newBoundedClientCache[effectiveHTTPConfigKey, *DefaultHTTPClient](p.clientCacheSize)
	p.clientCacheMu.Unlock()

	var prevHTTP *DefaultHTTPClient
	p.mu.Lock()
	p.cfg = cfgCopy
	p.config = parsedCfg
	if p.clock == nil {
		p.clock = clock.Real{}
	}
	p.cachedHostClient = sdkplugin.HostClientFromContext(ctx)
	if nextHTTP != nil {
		if defHTTP, isDefault := p.httpClient.(*DefaultHTTPClient); isDefault {
			prevHTTP = defHTTP
		}
		if p.httpClient == nil || prevHTTP != nil {
			p.httpClient = nextHTTP
		} else {
			prevHTTP = nextHTTP
		}
	}
	p.baseLogger = baseLgr
	p.initHTTPKey = initKey
	p.hasInitHTTPKey = true
	if p.openBrowser == nil {
		p.openBrowser = defaultBrowserOpener
	}
	p.mode = &cliMode{p: p}
	p.mu.Unlock()

	if oldHTTPCache != nil {
		oldHTTPCache.CloseAll()
	}
	if prevHTTP != nil {
		_ = prevHTTP.Close()
	}

	return nil
}

// activeMode returns the current mode. This guard returns an explicit error
// rather than panicking if the invariant is violated.
func (p *Plugin) activeMode() (mode, error) {
	p.mu.RLock()
	m := p.mode
	p.mu.RUnlock()
	if m == nil {
		return nil, fmt.Errorf("auth handler not configured: call ConfigureAuthHandler or ActivateServerMode first")
	}
	return m, nil
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
	ctx = attachRequestSettings(ctx, req.Settings)
	ctx = withHostnameOverride(ctx, req.Hostname)
	ctx = withBrowserPreference(ctx, req.Browser)
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

	mu := p.profileLock(profile)
	mu.Lock()
	defer mu.Unlock()

	var firstErr error
	if err := cacheClearErr(ctx, hostClient, profile); err != nil {
		firstErr = err
	}

	refreshKey, _ := profileSecretKey(SecretKeyRefreshToken, profile)
	accessKey, _ := profileSecretKey(SecretKeyAccessToken, profile)
	metaKey, _ := profileSecretKey(SecretKeyMetadata, profile)

	for _, key := range []string{refreshKey, accessKey, metaKey} {
		_, found, getErr := hostClient.GetSecret(ctx, key)
		if getErr != nil && firstErr == nil {
			firstErr = fmt.Errorf("checking secret %q during logout: %w", key, getErr)
		}
		if getErr == nil && !found {
			continue
		}
		if delErr := hostClient.DeleteSecret(ctx, key); delErr != nil && firstErr == nil {
			firstErr = fmt.Errorf("deleting secret %q during logout: %w", key, delErr)
		}
	}

	return firstErr
}

// GetStatus returns the current authentication status.
// Delegates to the active mode (CLI mode by default).
func (p *Plugin) GetStatus(ctx context.Context, handlerName string, req sdkplugin.StatusRequest) (*auth.Status, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}
	m, err := p.activeMode()
	if err != nil {
		return nil, err
	}
	ctx = attachRequestSettings(ctx, req.Settings)
	ctx = withHostnameOverride(ctx, req.Hostname)
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
	ctx = attachRequestSettings(ctx, req.Settings)
	ctx = withHostnameOverride(ctx, req.Hostname)
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
// An empty handlerName stops all handlers exposed by this plugin per plugin.proto.
//
//nolint:revive // all params required by interface
func (p *Plugin) StopAuthHandler(_ context.Context, handlerName string) error {
	if handlerName != "" && handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}
	p.closeHTTPClients()
	return nil
}

// farFuture returns a time far in the future for tokens with no defined expiry.
func farFuture() time.Time {
	return time.Now().Add(365 * 24 * time.Hour)
}
