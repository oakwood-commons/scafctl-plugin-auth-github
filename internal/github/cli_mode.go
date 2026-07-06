// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"fmt"
	"os"
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
//  1. Explicit FlowPAT — uses PAT from environment.
//  2. Implicit PAT — when no flow is specified, GITHUB_TOKEN/GH_TOKEN is set,
//     and no explicit scopes are requested, PAT is used automatically.
//  3. Explicit FlowDeviceCode — device code polling flow.
//  4. Explicit FlowGitHubApp — GitHub App installation token flow.
//  5. Explicit FlowInteractive or empty flow — if ClientSecret is configured,
//     uses authorization code + PKCE; otherwise falls back to device code with
//     automatic browser opening.
func (m *cliMode) Login(ctx context.Context, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
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
		if m.p.config.ClientSecret != "" {
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

	// Check for PAT credentials first (highest priority)
	if HasPATCredentials() {
		return m.p.patStatus(ctx)
	}

	// Check if we have stored credentials
	refreshKey, _ := profileSecretKey(SecretKeyRefreshToken, profile)
	accessKey, _ := profileSecretKey(SecretKeyAccessToken, profile)
	hasRefresh := m.p.secretExists(ctx, refreshKey)
	hasAccess := m.p.secretExists(ctx, accessKey)

	if !hasRefresh && !hasAccess {
		return &auth.Status{Authenticated: false}, nil
	}

	// Load and validate metadata
	metadata, err := m.p.loadMetadata(ctx)
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

// GetToken returns a valid access token in CLI mode, refreshing if necessary.
func (m *cliMode) GetToken(ctx context.Context, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return nil, err
	}

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
	fp := fingerprintHash(m.p.config.Hostname)
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
	accessToken, err := m.p.loadAccessToken(ctx)
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
	token, err := m.p.mintToken(ctx)
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

// ListCachedTokens returns metadata for all tokens stored by the GitHub handler
// in CLI mode.
func (m *cliMode) ListCachedTokens(ctx context.Context) ([]*auth.CachedTokenInfo, error) {
	hostClient := m.p.hostClient(ctx)
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
	if m.p.secretExists(ctx, refreshKey) {
		info := &auth.CachedTokenInfo{
			Handler:   HandlerName,
			TokenKind: "refresh",
			Flow:      auth.FlowDeviceCode,
		}
		if metadata, err := m.p.loadMetadata(ctx); err == nil && metadata != nil {
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
	if m.p.secretExists(ctx, accessKey) {
		fp := fingerprintHash(m.p.config.Hostname)
		cacheKey := fp + ":" + defaultCacheKey
		cached, cacheErr := cacheGet(ctx, hostClient, cacheKey, profile)
		if cacheErr != nil || cached == nil {
			info := &auth.CachedTokenInfo{
				Handler:   HandlerName,
				TokenKind: "access",
				TokenType: "Bearer",
			}
			if metadata, err := m.p.loadMetadata(ctx); err == nil && metadata != nil {
				info.CachedAt = metadata.LastRefresh
				info.SessionID = metadata.SessionID
				info.Flow = metadata.Flow
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

	return cachePurgeExpired(ctx, hostClient, profile)
}

// DetectAvailableFlows reports which auth flows are available based on
// environment credentials or configuration in CLI mode.
func (m *cliMode) DetectAvailableFlows(_ context.Context) ([]sdkplugin.FlowAvailability, error) {
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
	hasAppID := m.p.config.GetAppID() != 0
	hasPrivateKey := m.p.config.PrivateKey != "" || m.p.config.PrivateKeyPath != "" ||
		m.p.config.PrivateKeySecretName != "" ||
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
