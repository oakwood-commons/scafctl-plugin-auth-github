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

// PAT environment variable names (following GitHub CLI conventions).
const (
	// EnvGitHubToken is the environment variable for the GitHub token.
	EnvGitHubToken = "GITHUB_TOKEN" //nolint:gosec // env var name, not a credential

	// EnvGHToken is the environment variable used by the GitHub CLI (gh).
	EnvGHToken = "GH_TOKEN" //nolint:gosec // env var name, not a credential
)

// GetPATFromEnv retrieves a personal access token from environment variables.
// GITHUB_TOKEN takes precedence over GH_TOKEN.
func GetPATFromEnv() string {
	if token := os.Getenv(EnvGitHubToken); token != "" {
		return token
	}
	return os.Getenv(EnvGHToken)
}

// HasPATCredentials checks if PAT credentials are configured in environment.
func HasPATCredentials() bool {
	return GetPATFromEnv() != ""
}

// patLogin validates a PAT by calling the GitHub API and persists the validated
// credential in the host secret store scoped to the active profile and target hostname.
func (p *Plugin) patLogin(ctx context.Context, req sdkplugin.LoginRequest) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting PAT login", "handler", HandlerName)

	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return nil, err
	}

	ctx = withHostnameOverride(ctx, req.Hostname)
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	token := GetPATFromEnv()
	if token == "" {
		return nil, fmt.Errorf("personal access token not configured: set %s or %s environment variable",
			EnvGitHubToken, EnvGHToken)
	}

	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return nil, fmt.Errorf("cannot persist PAT credentials: host secret store is not available")
	}

	releaseSlot, slotErr := p.acquireRefreshSlot(ctx, "pat:"+profile)
	if slotErr != nil {
		return nil, slotErr
	}
	defer releaseSlot()

	claims, err := p.fetchUserClaims(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("PAT authentication failed: %w", err)
	}

	mu := p.profileLock(profile)
	mu.Lock()
	persistedClaims, storeErr := p.storeCredentialsLocked(
		ctx,
		cfg,
		hostClient,
		profile,
		&TokenResponse{
			AccessToken: token,
			TokenType:   "Bearer",
		},
		claims,
		nil,
		"",
		auth.FlowPAT,
		false,
	)
	mu.Unlock()
	if storeErr != nil {
		return nil, fmt.Errorf("cannot persist PAT credentials: %w", storeErr)
	}

	lgr.V(1).Info("PAT authentication successful",
		"login", persistedClaims.Subject,
		"name", persistedClaims.Name,
	)

	if len(req.Scopes) > 0 {
		lgr.V(0).Info("WARNING: --scope flags are ignored for PAT authentication; PAT scopes are fixed at token creation time on GitHub")
	}

	return &sdkplugin.LoginResponse{
		Claims: persistedClaims,
	}, nil
}

// patStatus returns auth status when PAT credentials are present.
func (p *Plugin) patStatus(ctx context.Context) (*auth.Status, error) {
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	token := GetPATFromEnv()
	if token == "" {
		return &auth.Status{Authenticated: false}, nil
	}

	claims, err := p.fetchUserClaims(ctx, token)
	if err != nil {
		return &auth.Status{Authenticated: false}, nil //nolint:nilerr // invalid token means not authenticated
	}

	return &auth.Status{
		Authenticated: true,
		Claims:        claims,
		IdentityType:  auth.IdentityTypeUser,
		Scopes:        cfg.DefaultScopes,
		Flow:          auth.FlowPAT,
		Hostname:      cfg.Hostname,
	}, nil
}

// getPATToken returns a token from the PAT environment variable.
func (p *Plugin) getPATToken(ctx context.Context, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return nil, err
	}

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	token := GetPATFromEnv()
	if token == "" {
		return nil, fmt.Errorf("personal access token not configured: set %s or %s environment variable",
			EnvGitHubToken, EnvGHToken)
	}

	hostClient := p.hostClient(ctx)

	cacheKey := patTokenCacheKey(cfg.Hostname, token)

	minValidFor := req.MinValidFor
	if minValidFor == 0 {
		minValidFor = auth.DefaultMinValidFor
	}

	// Check cache unless force refresh
	if !req.ForceRefresh && hostClient != nil {
		cached, cErr := cacheGet(ctx, hostClient, cacheKey, profile)
		if cErr == nil && cached != nil &&
			subtle.ConstantTimeCompare([]byte(cached.AccessToken), []byte(token)) == 1 &&
			cached.IsValidFor(minValidFor) {
			return &sdkplugin.TokenResponse{
				AccessToken: cached.AccessToken,
				TokenType:   cached.TokenType,
				ExpiresAt:   cached.ExpiresAt,
				Scope:       cached.Scope,
				Flow:        cached.Flow,
				SessionID:   cached.SessionID,
			}, nil
		}
	}

	releaseSlot, slotErr := p.acquireRefreshSlot(ctx, "pat:"+profile)
	if slotErr != nil {
		return nil, slotErr
	}
	defer releaseSlot()

	if !req.ForceRefresh && hostClient != nil {
		cached, cErr := cacheGet(ctx, hostClient, cacheKey, profile)
		if cErr == nil && cached != nil &&
			subtle.ConstantTimeCompare([]byte(cached.AccessToken), []byte(token)) == 1 &&
			cached.IsValidFor(minValidFor) {
			return &sdkplugin.TokenResponse{
				AccessToken: cached.AccessToken,
				TokenType:   cached.TokenType,
				ExpiresAt:   cached.ExpiresAt,
				Scope:       cached.Scope,
				Flow:        cached.Flow,
				SessionID:   cached.SessionID,
			}, nil
		}
	}

	// Validate the PAT
	if _, err := p.fetchUserClaims(ctx, token); err != nil {
		var cleanupErr error
		if isUnauthorizedStatusError(err) && hostClient != nil {
			cleanupErr = p.evictRejectedAmbientPAT(ctx, hostClient, cfg, profile, cacheKey, token)
		}
		valErr := fmt.Errorf("PAT validation failed: %w", err)
		if cleanupErr != nil {
			return nil, errors.Join(valErr, cleanupErr)
		}
		return nil, valErr
	}

	result := &sdkplugin.TokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(365 * 24 * time.Hour),
		Flow:        auth.FlowPAT,
	}

	// Cache it while holding the profile's PAT slot.
	if hostClient != nil {
		cacheToken := &auth.Token{
			AccessToken: token,
			TokenType:   "Bearer",
			ExpiresAt:   result.ExpiresAt,
			Flow:        auth.FlowPAT,
		}
		if cacheErr := cacheSet(ctx, hostClient, cacheKey, cacheToken, profile); cacheErr != nil {
			lgr := logr.FromContextOrDiscard(ctx)
			lgr.V(1).Info("failed to cache PAT token", "error", cacheErr)
		}
	}

	return result, nil
}

func (p *Plugin) evictRejectedAmbientPAT(
	ctx context.Context,
	hostClient *sdkplugin.HostServiceClient,
	cfg *Config,
	profile, cacheKey, token string,
) error {
	cleanupCtx, cleanupCancel := p.newCleanupContext(ctx)
	defer cleanupCancel()
	cleanupCtx = auth.WithProfile(cleanupCtx, profile)

	mu := p.profileLock(profile)
	mu.Lock()
	defer mu.Unlock()

	var errs []error
	const maxHostSecretKeyBytes = 255
	if prefix, pErr := profileTokenPrefix(profile); pErr == nil {
		fullKey := prefix + cacheKey
		if len(fullKey) <= maxHostSecretKeyBytes && isProfileTokenCacheSecret(fullKey, prefix, profile) && sdkplugin.ValidateHostSecretName(fullKey) == nil {
			if _, found, getErr := hostClient.GetSecret(cleanupCtx, fullKey); getErr != nil || found {
				if delErr := hostClient.DeleteSecret(cleanupCtx, fullKey); delErr != nil {
					errs = append(errs, fmt.Errorf("evicting rejected PAT cache entry: %w", delErr))
				} else if getErr != nil {
					errs = append(errs, fmt.Errorf("checking rejected PAT cache entry: %w", getErr))
				}
			}
		}
	}

	refreshKey, _ := profileSecretKey(SecretKeyRefreshToken, profile)
	accessKey, _ := profileSecretKey(SecretKeyAccessToken, profile)
	metaKey, _ := profileSecretKey(SecretKeyMetadata, profile)

	curRefresh, curRefFound, curRefErr := hostClient.GetSecret(cleanupCtx, refreshKey)
	if curRefErr != nil {
		errs = append(errs, fmt.Errorf("checking refresh token during PAT cleanup: %w", curRefErr))
		return errors.Join(errs...)
	}
	if curRefFound && curRefresh != "" {
		return errors.Join(errs...)
	}

	curAccess, curFound, curErr := hostClient.GetSecret(cleanupCtx, accessKey)
	if curErr != nil {
		errs = append(errs, fmt.Errorf("checking stored access token during PAT cleanup: %w", curErr))
		return errors.Join(errs...)
	}
	if !curFound || subtle.ConstantTimeCompare([]byte(curAccess), []byte(token)) != 1 {
		return errors.Join(errs...)
	}

	curMetaRaw, curMetaFound, curMetaErr := hostClient.GetSecret(cleanupCtx, metaKey)
	if curMetaErr != nil {
		errs = append(errs, fmt.Errorf("checking session metadata during PAT cleanup: %w", curMetaErr))
		return errors.Join(errs...)
	}
	var metadata *TokenMetadata
	if curMetaFound {
		var parsed TokenMetadata
		if uErr := decodeMetadata(curMetaRaw, &parsed); uErr != nil {
			errs = append(errs, fmt.Errorf("decoding session metadata during PAT cleanup: %w", uErr))
			return errors.Join(errs...)
		}
		metadata = &parsed
	}
	sessionCfg, hostErr := resolveSessionConfig(cfg, metadata)
	if hostErr != nil || !strings.EqualFold(sessionCfg.Hostname, cfg.Hostname) {
		return errors.Join(errs...)
	}

	if clearErr := cacheClearErr(cleanupCtx, hostClient, profile); clearErr != nil {
		errs = append(errs, fmt.Errorf("clearing rejected token cache: %w", clearErr))
	}
	if delErr := hostClient.DeleteSecret(cleanupCtx, accessKey); delErr != nil {
		errs = append(errs, fmt.Errorf("deleting rejected access token: %w", delErr))
	} else if curMetaFound {
		if metaDelErr := hostClient.DeleteSecret(cleanupCtx, metaKey); metaDelErr != nil {
			errs = append(errs, fmt.Errorf("deleting rejected session metadata: %w", metaDelErr))
		}
	}
	return errors.Join(errs...)
}
