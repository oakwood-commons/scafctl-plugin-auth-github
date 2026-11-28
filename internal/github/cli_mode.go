// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// cliMode implements mode for interactive CLI usage.
type cliMode struct {
	p *Plugin
}

// Login performs the authentication flow in CLI mode.
//
// Flow selection precedence:
//  1. Explicit FlowPAT -- uses PAT from environment.
//  2. Implicit PAT -- when no flow is specified, GITHUB_TOKEN/GH_TOKEN is set,
//     and no explicit scopes are requested, PAT is used automatically.
//  3. Explicit FlowDeviceCode -- device code polling flow.
//  4. Explicit FlowGitHubApp -- GitHub App installation token flow.
//  5. Explicit FlowInteractive or empty flow -- if ClientSecret is configured,
//     uses authorization code + PKCE; otherwise falls back to device code with
//     automatic browser opening.
func (m *cliMode) Login(ctx context.Context, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	if err := validateProfile(auth.ProfileFromContext(ctx)); err != nil {
		return nil, err
	}

	ctx = withHostnameOverride(ctx, req.Hostname)
	cfg, err := m.p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)
	ctx = withBrowserPreference(ctx, req.Browser)

	// PAT takes priority when explicitly requested or when the environment
	// provides a token and the caller did not ask for specific scopes.
	if req.Flow == auth.FlowPAT || (req.Flow == "" && HasPATCredentials() && len(req.Scopes) == 0) {
		return m.p.patLogin(ctx, req)
	}

	switch req.Flow { //nolint:exhaustive // Only GitHub-supported flows are handled
	case auth.FlowDeviceCode:
		return m.p.deviceCodeLogin(ctx, req, deviceCodeCb)
	case auth.FlowGitHubApp:
		return m.p.appLogin(ctx)
	case auth.FlowInteractive, "":
		if cfg.ClientSecret != "" {
			return m.p.authCodeLogin(ctx, req, deviceCodeCb)
		}
		return m.p.interactiveDeviceCodeLogin(ctx, req, deviceCodeCb)
	default:
		return nil, fmt.Errorf("unsupported flow: %s", req.Flow)
	}
}

// Logout revokes the current session in CLI mode by clearing stored
// credentials and cached tokens.
func (m *cliMode) Logout(ctx context.Context) error {
	return m.p.logoutInternal(ctx)
}

// GetStatus returns the current authentication status in CLI mode.
func (m *cliMode) GetStatus(ctx context.Context) (*auth.Status, error) {
	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return nil, err
	}

	cfg, err := m.p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	// Check for PAT credentials first (highest priority)
	if HasPATCredentials() {
		return m.p.patStatus(ctx)
	}

	mu := m.p.profileLock(profile)
	mu.RLock()
	refreshKey, _ := profileSecretKey(SecretKeyRefreshToken, profile)
	accessKey, _ := profileSecretKey(SecretKeyAccessToken, profile)
	hasRefresh := m.p.secretExists(ctx, refreshKey)
	hasAccess := m.p.secretExists(ctx, accessKey)
	if !hasRefresh && !hasAccess {
		mu.RUnlock()
		return &auth.Status{Authenticated: false}, nil
	}
	metadata, err := m.p.loadMetadataUnlocked(ctx)
	mu.RUnlock()
	if err != nil {
		return &auth.Status{Authenticated: false}, nil //nolint:nilerr // corrupted metadata = not authenticated
	}

	if _, hostErr := resolveSessionConfig(cfg, metadata); hostErr != nil {
		var mismatch *hostnameMismatchError
		if errors.As(hostErr, &mismatch) {
			return &auth.Status{
				Authenticated: false,
				Reason:        fmt.Sprintf("authenticated to %s, not %s", mismatch.stored, mismatch.requested),
				Hostname:      cfg.Hostname,
			}, nil
		}
		var appMismatch *appConfigMismatchError
		if errors.As(hostErr, &appMismatch) {
			return &auth.Status{
				Authenticated: false,
				Reason:        appMismatch.Error(),
				Hostname:      metadata.Hostname,
			}, nil
		}
		return &auth.Status{Authenticated: false}, nil //nolint:nilerr // invalid stored hostname = not authenticated
	}

	expiresAt := metadata.RefreshTokenExpiresAt
	if isGitHubAppSession(metadata) {
		if metadata.AccessTokenExpiresAt.IsZero() {
			return &auth.Status{
				Authenticated: false,
				Reason:        "session expired",
				Claims:        metadata.Claims,
			}, nil
		}
		expiresAt = metadata.AccessTokenExpiresAt
	}

	// Check if session/token is expired
	if !expiresAt.IsZero() && time.Now().After(expiresAt) {
		return &auth.Status{
			Authenticated: false,
			Reason:        "session expired",
			Claims:        metadata.Claims,
		}, nil
	}

	identityType := auth.IdentityTypeUser
	if metadata.IdentityType != "" {
		identityType = auth.IdentityType(metadata.IdentityType)
	}

	return &auth.Status{
		Authenticated: true,
		Claims:        metadata.Claims,
		ExpiresAt:     expiresAt,
		LastRefresh:   metadata.LastRefresh,
		IdentityType:  identityType,
		ClientID:      metadata.ClientID,
		Scopes:        metadata.Scopes,
		Flow:          metadata.Flow,
		Hostname:      metadata.Hostname,
	}, nil
}

// GetToken returns a valid access token in CLI mode, refreshing if necessary.
func (m *cliMode) GetToken(ctx context.Context, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return nil, err
	}

	cfg, err := m.p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	// Use PAT flow if credentials are present (highest priority)
	if HasPATCredentials() {
		return m.p.getPATToken(ctx, req)
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

	hostClient := m.p.hostClient(ctx)
	if hostClient == nil {
		return nil, fmt.Errorf("not authenticated: host service not available")
	}

	refreshKey, _ := profileSecretKey(SecretKeyRefreshToken, profile)
	accessKey, _ := profileSecretKey(SecretKeyAccessToken, profile)
	metaKey, _ := profileSecretKey(SecretKeyMetadata, profile)

	mu := m.p.profileLock(profile)
	mu.RLock()
	refreshToken, refreshFound, refreshGetErr := hostClient.GetSecret(ctx, refreshKey)
	if refreshGetErr != nil {
		mu.RUnlock()
		return nil, fmt.Errorf("failed to inspect refresh token: %w", refreshGetErr)
	}
	hasRefresh := refreshFound && refreshToken != ""

	accessToken, accessFound, accessGetErr := hostClient.GetSecret(ctx, accessKey)
	if accessGetErr != nil {
		mu.RUnlock()
		return nil, fmt.Errorf("failed to inspect access token: %w", accessGetErr)
	}
	hasAccess := accessFound && accessToken != ""

	metaRaw, metaFound, metaGetErr := hostClient.GetSecret(ctx, metaKey)
	var metadata *TokenMetadata
	var metaParseErr error
	if metaGetErr == nil && metaFound {
		var parsed TokenMetadata
		if uErr := decodeMetadata(metaRaw, &parsed); uErr != nil {
			metaParseErr = uErr
		} else {
			metadata = &parsed
		}
	}

	if metaGetErr != nil {
		mu.RUnlock()
		return nil, fmt.Errorf("failed to inspect session metadata: %w", metaGetErr)
	}
	if metaParseErr != nil {
		mu.RUnlock()
		return nil, fmt.Errorf("failed to load metadata: %w", metaParseErr)
	}

	sessionCfg, hostErr := resolveSessionConfig(cfg, metadata)
	if hostErr != nil {
		mu.RUnlock()
		var mismatch *hostnameMismatchError
		if errors.As(hostErr, &mismatch) {
			return nil, fmt.Errorf("not authenticated for hostname %q: %w", cfg.Hostname, hostErr)
		}
		return nil, fmt.Errorf("not authenticated: %w", hostErr)
	}
	ctx = withResolvedConfig(ctx, sessionCfg)

	cacheKey := sessionTokenCacheKey(sessionCfg.Hostname)

	// Handle GitHub App sessions (including legacy service-principal metadata
	// that omitted Flow/AccessTokenExpiresAt) explicitly so 1-hour installation
	// tokens are never wrapped with a 365-day farFuture() expiry.
	if isGitHubAppSession(metadata) {
		if !hasAccess {
			mu.RUnlock()
			return nil, fmt.Errorf("not authenticated: GitHub App installation token not found, please re-authenticate with '%s auth login github --flow github_app'", m.p.binaryName())
		}
		if metadata.Flow != auth.FlowGitHubApp || metadata.AccessTokenExpiresAt.IsZero() {
			mu.RUnlock()
			return nil, fmt.Errorf("not authenticated: legacy GitHub App session is missing expiration metadata, please re-authenticate with '%s auth login github --flow github_app'", m.p.binaryName())
		}
		appID := metadata.AppID
		if appID == 0 {
			appID = sessionCfg.GetAppID()
		}
		installID := metadata.InstallationID
		if installID == 0 {
			installID = sessionCfg.GetInstallationID()
		}
		appCacheKey := appTokenCacheKey(sessionCfg.Hostname, appID, installID)

		if !req.ForceRefresh {
			cached, cErr := cacheGet(ctx, hostClient, appCacheKey, profile)
			if cErr == nil && cached != nil &&
				(metadata.SessionID == "" || cached.SessionID == metadata.SessionID) &&
				cached.IsValidFor(minValidFor) {
				mu.RUnlock()
				return &sdkplugin.TokenResponse{
					AccessToken: cached.AccessToken,
					TokenType:   cached.TokenType,
					ExpiresAt:   cached.ExpiresAt,
					Scope:       cached.Scope,
					Flow:        auth.FlowGitHubApp,
					SessionID:   cached.SessionID,
				}, nil
			}
			if hasAccess && !metadata.AccessTokenExpiresAt.IsZero() &&
				time.Until(metadata.AccessTokenExpiresAt) >= minValidFor {
				resp := &sdkplugin.TokenResponse{
					AccessToken: accessToken,
					TokenType:   "Bearer",
					ExpiresAt:   metadata.AccessTokenExpiresAt,
					Flow:        auth.FlowGitHubApp,
					SessionID:   metadata.SessionID,
				}
				mu.RUnlock()
				return resp, nil
			}
		}
		mu.RUnlock()

		// Re-mint a fresh GitHub App installation token once if credentials are
		// available, pinning renewal to the reconciled stored (appID, installID)
		// and guarding the commit against concurrent Logout/Login.
		if sessionCfg.ValidateAppConfig(ctx, lgr, hostClient) == nil {
			minted, renewErr := m.p.renewAppInstallationToken(ctx, metadata.SessionID, appID, installID)
			if renewErr != nil {
				return nil, renewErr
			}
			if time.Until(minted.ExpiresAt) < minValidFor {
				return nil, fmt.Errorf(
					"freshly minted GitHub App installation token expires in %s, which is shorter than requested minimum validity %s",
					time.Until(minted.ExpiresAt).Round(time.Second),
					minValidFor,
				)
			}
			return minted, nil
		}
		return nil, fmt.Errorf("GitHub App installation token expired, please re-authenticate with '%s auth login github --flow github_app'", m.p.binaryName())
	}

	// Check cache first (unless force refresh) under profile read lock.
	if !req.ForceRefresh && (hasRefresh || hasAccess) {
		token, cErr := cacheGet(ctx, hostClient, cacheKey, profile)
		sessionMatches := metadata == nil || metadata.SessionID == "" || token == nil || token.SessionID == metadata.SessionID
		if cErr == nil && token != nil && sessionMatches && token.IsValidFor(minValidFor) {
			mu.RUnlock()
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
	}

	// Check if we have a stored non-expiring access token (such as a persisted PAT
	// or OAuth App token without a refresh token for this profile).
	if !hasRefresh && hasAccess {
		hadMeta := metadata != nil
		var sessionID string
		var flow auth.Flow
		var scope string
		if metadata != nil {
			sessionID = metadata.SessionID
			flow = metadata.Flow
			scope = strings.Join(metadata.Scopes, " ")
		}
		mu.RUnlock()

		if req.ForceRefresh {
			if _, err := m.p.fetchUserClaims(ctx, accessToken); err != nil {
				var cleanupErr error
				if isUnauthorizedStatusError(err) {
					cleanupErr = m.p.invalidateRejectedAccessToken(ctx, hostClient, profile, refreshKey, accessKey, metaKey, accessToken, hadMeta, sessionID, metaRaw)
				}
				var authErr error
				if flow == auth.FlowPAT {
					authErr = fmt.Errorf("not authenticated: PAT validation failed: %w", err)
				} else {
					authErr = fmt.Errorf("not authenticated: access token validation failed: %w", err)
				}
				if cleanupErr != nil {
					return nil, errors.Join(authErr, cleanupErr)
				}
				return nil, authErr
			}
		}

		token := &auth.Token{
			AccessToken: accessToken,
			TokenType:   "Bearer",
			ExpiresAt:   farFuture(),
			Scope:       scope,
			Flow:        flow,
			SessionID:   sessionID,
		}

		// Re-acquire write lock and verify session continuity before caching or
		// returning the credential so concurrent Logout or replacement Login wins.
		mu.Lock()
		same, contErr := m.p.sameNonRefreshSessionLocked(ctx, hostClient, refreshKey, accessKey, metaKey, accessToken, hadMeta, sessionID, metaRaw)
		if !same {
			mu.Unlock()
			return nil, contErr
		}
		if cacheErr := cacheSet(ctx, hostClient, cacheKey, token, profile); cacheErr != nil {
			lgr.V(1).Info("failed to cache token", "error", cacheErr)
		}
		mu.Unlock()

		return &sdkplugin.TokenResponse{
			AccessToken: token.AccessToken,
			TokenType:   token.TokenType,
			ExpiresAt:   token.ExpiresAt,
			Scope:       token.Scope,
			Flow:        token.Flow,
			SessionID:   token.SessionID,
		}, nil
	}
	mu.RUnlock()

	// Coalesce concurrent OAuth refreshes per profile so expired-cache callers
	// do not submit the same single-use refresh token in parallel.
	token, err := m.p.mintTokenCoalesced(ctx, req.ForceRefresh, minValidFor)
	if err != nil {
		return nil, err
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

// ListCachedTokens returns metadata for all tokens stored by the GitHub handler
// in CLI mode.
func (m *cliMode) ListCachedTokens(ctx context.Context) ([]*auth.CachedTokenInfo, error) {
	hostClient := m.p.hostClient(ctx)
	if hostClient == nil {
		return nil, fmt.Errorf("host service not available")
	}

	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return nil, err
	}

	cfg, err := m.p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}

	var results []*auth.CachedTokenInfo

	mu := m.p.profileLock(profile)
	mu.RLock()
	defer mu.RUnlock()

	metadata, metaErr := m.p.loadMetadataUnlocked(ctx)
	sessionCfg := cfg
	if metaErr == nil && metadata != nil {
		if resolved, rErr := resolveSessionConfig(cfg, metadata); rErr == nil {
			sessionCfg = resolved
		}
	}

	// Refresh token (device code / interactive flow with token expiry enabled)
	refreshKey, _ := profileSecretKey(SecretKeyRefreshToken, profile)
	if m.p.secretExists(ctx, refreshKey) {
		info := &auth.CachedTokenInfo{
			Handler:   HandlerName,
			TokenKind: "refresh",
			Flow:      auth.FlowDeviceCode,
		}
		if metaErr == nil && metadata != nil {
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

	// Direct access token not yet represented in the token cache
	accessKey, _ := profileSecretKey(SecretKeyAccessToken, profile)
	if len(entries) == 0 && m.p.secretExists(ctx, accessKey) {
		cacheKey := sessionTokenCacheKey(sessionCfg.Hostname)
		cached, cacheErr := cacheGet(ctx, hostClient, cacheKey, profile)
		if cacheErr != nil || cached == nil {
			info := &auth.CachedTokenInfo{
				Handler:   HandlerName,
				TokenKind: "access",
				TokenType: "Bearer",
			}
			if metaErr == nil && metadata != nil {
				info.CachedAt = metadata.LastRefresh
				info.SessionID = metadata.SessionID
				info.Flow = metadata.Flow
				info.ExpiresAt = metadata.AccessTokenExpiresAt
				if !info.ExpiresAt.IsZero() {
					info.IsExpired = time.Now().After(info.ExpiresAt)
				}
			}
			results = append(results, info)
		}
	}

	return results, nil
}

// PurgeExpiredTokens removes expired access tokens from the cache in CLI mode.
func (m *cliMode) PurgeExpiredTokens(ctx context.Context) (int, error) {
	hostClient := m.p.hostClient(ctx)
	if hostClient == nil {
		return 0, nil
	}

	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return 0, err
	}

	mu := m.p.profileLock(profile)
	mu.Lock()
	defer mu.Unlock()

	return cachePurgeExpired(ctx, hostClient, profile)
}

// DetectAvailableFlows reports which auth flows are available based on
// environment credentials or configuration in CLI mode.
func (m *cliMode) DetectAvailableFlows(ctx context.Context) ([]sdkplugin.FlowAvailability, error) {
	if err := validateProfile(auth.ProfileFromContext(ctx)); err != nil {
		return nil, err
	}

	cfg, err := m.p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
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
	hasAppID := cfg.GetAppID() != 0
	hasPrivateKey := cfg.PrivateKey != "" || cfg.PrivateKeyPath != "" ||
		cfg.PrivateKeySecretName != "" ||
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

	// Interactive flow -- listed ahead of device_code so bare login opens the browser by default
	flows = append(flows, sdkplugin.FlowAvailability{
		Flow:      auth.FlowInteractive,
		Available: true,
		Reason:    "interactive flow is always available",
	})

	// Device code flow -- always available for headless environments (uses built-in OAuth App client ID)
	flows = append(flows, sdkplugin.FlowAvailability{
		Flow:      auth.FlowDeviceCode,
		Available: true,
		Reason:    "device code flow is always available",
	})

	return flows, nil
}

type continuityReadError struct {
	err error
}

func (e *continuityReadError) Error() string { return e.err.Error() }
func (e *continuityReadError) Unwrap() error { return e.err }

// sameNonRefreshSessionLocked verifies under profileLock that profile still holds
// the exact non-refresh access-token session observed before releasing the lock.
func (p *Plugin) sameNonRefreshSessionLocked(
	ctx context.Context,
	hostClient *sdkplugin.HostServiceClient,
	refreshKey, accessKey, metaKey, expectedAccessToken string,
	hadMeta bool,
	expectedSessionID, expectedMetaRaw string,
) (bool, error) {
	curRefresh, curRefFound, curRefErr := hostClient.GetSecret(ctx, refreshKey)
	if curRefErr != nil {
		return false, &continuityReadError{err: fmt.Errorf("not authenticated: failed to verify refresh token continuity: %w", curRefErr)}
	}
	if curRefFound && curRefresh != "" {
		return false, fmt.Errorf("not authenticated: session changed during token validation")
	}

	curAccess, curFound, curErr := hostClient.GetSecret(ctx, accessKey)
	if curErr != nil {
		return false, &continuityReadError{err: fmt.Errorf("not authenticated: failed to verify access token continuity: %w", curErr)}
	}
	if !curFound || curAccess == "" {
		return false, fmt.Errorf("not authenticated: session ended during token validation")
	}
	if subtle.ConstantTimeCompare([]byte(curAccess), []byte(expectedAccessToken)) != 1 {
		return false, fmt.Errorf("not authenticated: session changed during token validation")
	}

	curMetaRaw, curMetaFound, curMetaErr := hostClient.GetSecret(ctx, metaKey)
	if curMetaErr != nil {
		return false, &continuityReadError{err: fmt.Errorf("not authenticated: failed to verify session metadata continuity: %w", curMetaErr)}
	}
	if !hadMeta {
		if curMetaFound {
			return false, fmt.Errorf("not authenticated: session changed during token validation")
		}
		return true, nil
	}
	if !curMetaFound {
		return false, fmt.Errorf("not authenticated: session ended during token validation")
	}
	var curMeta TokenMetadata
	if uErr := decodeMetadata(curMetaRaw, &curMeta); uErr != nil {
		return false, &continuityReadError{err: fmt.Errorf("not authenticated: failed to load metadata: %w", uErr)}
	}
	if expectedSessionID != "" {
		if curMeta.SessionID != expectedSessionID {
			return false, fmt.Errorf("not authenticated: session changed during token validation")
		}
	} else if curMetaRaw != expectedMetaRaw {
		return false, fmt.Errorf("not authenticated: session changed during token validation")
	}

	return true, nil
}

// invalidateRejectedAccessToken clears stored credentials and cached tokens for
// profile when forced /user validation returns HTTP 401, provided no concurrent
// Logout or replacement Login superseded the rejected session while unlocked.
func (p *Plugin) invalidateRejectedAccessToken(
	ctx context.Context,
	hostClient *sdkplugin.HostServiceClient,
	profile, refreshKey, accessKey, metaKey, expectedAccessToken string,
	hadMeta bool,
	expectedSessionID, expectedMetaRaw string,
) error {
	cleanupCtx, cleanupCancel := p.newCleanupContext(ctx)
	defer cleanupCancel()
	cleanupCtx = auth.WithProfile(cleanupCtx, profile)

	mu := p.profileLock(profile)
	mu.Lock()
	defer mu.Unlock()

	same, contErr := p.sameNonRefreshSessionLocked(cleanupCtx, hostClient, refreshKey, accessKey, metaKey, expectedAccessToken, hadMeta, expectedSessionID, expectedMetaRaw)
	if !same {
		var readErr *continuityReadError
		if errors.As(contErr, &readErr) {
			return readErr.err
		}
		return nil
	}

	var errs []error
	if clearErr := cacheClearErr(cleanupCtx, hostClient, profile); clearErr != nil {
		errs = append(errs, fmt.Errorf("clearing rejected token cache: %w", clearErr))
	}
	if delErr := hostClient.DeleteSecret(cleanupCtx, accessKey); delErr != nil {
		errs = append(errs, fmt.Errorf("deleting rejected access token: %w", delErr))
	} else if hadMeta {
		if metaDelErr := hostClient.DeleteSecret(cleanupCtx, metaKey); metaDelErr != nil {
			errs = append(errs, fmt.Errorf("deleting rejected session metadata: %w", metaDelErr))
		}
	}
	return errors.Join(errs...)
}
