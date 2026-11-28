// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// TokenMetadata stores information about the stored credentials.
type TokenMetadata struct {
	Claims                *auth.Claims `json:"claims"`
	RefreshTokenExpiresAt time.Time    `json:"refreshTokenExpiresAt,omitempty"`
	AccessTokenExpiresAt  time.Time    `json:"accessTokenExpiresAt,omitempty"`
	LastRefresh           time.Time    `json:"lastRefresh"`
	Hostname              string       `json:"hostname"`
	HostnameOverride      bool         `json:"hostnameOverride,omitempty"`
	ClientID              string       `json:"clientId,omitempty"`
	Scopes                []string     `json:"scopes,omitempty"`
	IdentityType          string       `json:"identityType,omitempty"`
	SessionID             string       `json:"sessionId,omitempty"`
	Flow                  auth.Flow    `json:"flow,omitempty"`
	AppID                 int64        `json:"appId,omitempty"`
	InstallationID        int64        `json:"installationId,omitempty"`
}

func decodeMetadata(raw string, dst *TokenMetadata) error {
	if err := json.Unmarshal([]byte(raw), dst); err != nil {
		return fmt.Errorf("failed to unmarshal metadata: %w", err)
	}
	return nil
}

// TokenResponse represents the response from the GitHub OAuth token endpoint.
type TokenResponse struct {
	AccessToken           string `json:"access_token"`            //nolint:gosec // Not a hardcoded credential
	RefreshToken          string `json:"refresh_token,omitempty"` //nolint:gosec // Not a hardcoded credential
	TokenType             string `json:"token_type"`
	Scope                 string `json:"scope"`
	ExpiresIn             int    `json:"expires_in,omitempty"`
	RefreshTokenExpiresIn int    `json:"refresh_token_expires_in,omitempty"`
}

// TokenErrorResponse represents an error from the GitHub OAuth token endpoint.
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri,omitempty"`
	Interval         int    `json:"interval,omitempty"`
}

// mintToken creates a new access token using the refresh token.
func (p *Plugin) mintToken(ctx context.Context) (*auth.Token, error) {
	return p.mintTokenCoalesced(ctx, true, 0)
}

// mintTokenCoalesced serializes OAuth refresh-token usage per profile via
// refreshLock (without holding profileLock over HTTP calls), re-checking the
// token cache and active session metadata after acquiring refreshLock so
// concurrent GetToken callers do not submit the same single-use refresh token.
func (p *Plugin) mintTokenCoalesced(ctx context.Context, forceRefresh bool, minValidFor time.Duration) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("minting access token")

	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return nil, err
	}

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}

	releaseRefresh, slotErr := p.acquireRefreshSlot(ctx, profile)
	if slotErr != nil {
		return nil, slotErr
	}
	defer releaseRefresh()

	hostClient := p.hostClient(ctx)

	mu := p.profileLock(profile)
	mu.RLock()
	refreshToken, rtErr := p.loadRefreshTokenUnlocked(ctx)
	if rtErr != nil {
		mu.RUnlock()
		return nil, fmt.Errorf("not authenticated: %w", rtErr)
	}
	metadata, metaErr := p.loadMetadataUnlocked(ctx)
	if metaErr != nil {
		mu.RUnlock()
		return nil, fmt.Errorf("failed to load metadata: %w", metaErr)
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

	cacheKey := sessionTokenCacheKey(sessionCfg.Hostname)

	if !forceRefresh && hostClient != nil {
		cached, cErr := cacheGet(ctx, hostClient, cacheKey, profile)
		sessionMatches := metadata == nil || metadata.SessionID == "" || cached == nil || cached.SessionID == metadata.SessionID
		if cErr == nil && cached != nil && sessionMatches && cached.IsValidFor(minValidFor) {
			mu.RUnlock()
			return cached, nil
		}
	}
	mu.RUnlock()

	ctx = withResolvedConfig(ctx, sessionCfg)

	if metadata.ClientID == "" {
		return nil, fmt.Errorf("stored credentials are missing client ID, please re-authenticate with '%s auth login github'", p.binaryName())
	}

	token, err := p.refreshAccessTokenWithMeta(ctx, refreshToken, metadata.ClientID, metadata, true)
	if err != nil {
		return nil, err
	}

	// Cache the minted token under profileLock before releasing refreshMu so the
	// next coalesced caller observes the updated cache entry immediately.
	if hostClient != nil {
		refreshKey, _ := profileSecretKey(SecretKeyRefreshToken, profile)
		mu.Lock()
		if curRefresh, curRefFound, curRefErr := hostClient.GetSecret(ctx, refreshKey); curRefErr == nil && curRefFound && curRefresh != "" {
			if curMeta, curErr := p.loadMetadataUnlocked(ctx); curErr == nil && curMeta != nil && curMeta.SessionID == token.SessionID {
				if cacheErr := cacheSet(ctx, hostClient, cacheKey, token, profile); cacheErr != nil {
					lgr.V(1).Info("failed to cache token", "error", cacheErr)
				}
			}
		}
		mu.Unlock()
	}

	return token, nil
}

// refreshAccessToken refreshes an access token using the refresh token.
func (p *Plugin) refreshAccessToken(ctx context.Context, refreshToken, clientID string) (*auth.Token, error) {
	return p.refreshAccessTokenWithMeta(ctx, refreshToken, clientID, nil, false)
}

func (p *Plugin) refreshAccessTokenWithMeta(ctx context.Context, refreshToken, clientID string, snapshotMeta *TokenMetadata, hasSnapshot bool) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}

	metadata := snapshotMeta
	var metaErr error
	if !hasSnapshot {
		metadata, metaErr = p.loadMetadata(ctx)
	}

	if metadata != nil {
		resolved, hostErr := resolveSessionConfig(cfg, metadata)
		if hostErr != nil {
			return nil, fmt.Errorf("not authenticated for hostname %q: %w", cfg.Hostname, hostErr)
		}
		cfg = resolved
	}
	ctx = withResolvedConfig(ctx, cfg)

	httpClient, releaseHTTP, err := p.acquireHTTPClient(ctx, cfg, true)
	if err != nil {
		return nil, err
	}
	defer releaseHTTP()

	endpoint := fmt.Sprintf("%s/login/oauth/access_token", cfg.GetOAuthBaseURL())

	params := map[string]string{
		"client_id":     clientID,
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}
	if cfg.ClientSecret != "" {
		params["client_secret"] = cfg.ClientSecret
	}
	data := makeFormData(params)

	resp, err := httpClient.PostForm(ctx, endpoint, data)
	if err != nil {
		return nil, fmt.Errorf("token refresh request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body := struct {
		TokenResponse
		TokenErrorResponse
	}{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("token refresh failed with status %d: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if body.AccessToken == "" {
		if body.Error != "" && body.Error != "bad_refresh_token" {
			return nil, fmt.Errorf("token refresh failed: %s - %s",
				sanitizeControlChars(body.Error), sanitizeControlChars(body.ErrorDescription))
		}
		if resp.StatusCode != http.StatusOK && body.Error == "" {
			return nil, fmt.Errorf("token refresh failed with status %d", resp.StatusCode)
		}
		lgr.V(0).Info("token refresh returned empty access token -- refresh token may be expired or revoked; re-authenticate with login")
		return nil, fmt.Errorf("refresh token expired or revoked, please re-authenticate with '%s auth login github'", p.binaryName())
	}

	tokenResp := body.TokenResponse

	// If we got a new refresh token, update stored credentials unless a
	// concurrent login or logout replaced the session while the HTTP call ran.
	if tokenResp.RefreshToken != "" && tokenResp.RefreshToken != refreshToken {
		lgr.V(1).Info("refresh token rotated, storing new token")
		if metaErr != nil {
			lgr.V(1).Info("failed to load metadata during token rotation, skipping credential update", "error", metaErr)
		} else if metadata != nil {
			if err := p.storeRotatedCredentials(ctx, cfg, refreshToken, &tokenResp, metadata); err != nil {
				lgr.V(1).Info("warning: failed to update refresh token", "error", err)
			}
		}
	}

	var flow auth.Flow
	var sessionID string
	var scopes []string
	if metadata != nil {
		flow = metadata.Flow
		sessionID = metadata.SessionID
		scopes = metadata.Scopes
	}

	scope := tokenResp.Scope
	if scope == "" {
		scope = strings.Join(scopes, " ")
	}

	expiresAt := time.Now().Add(8 * time.Hour)
	if tokenResp.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	return &auth.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresAt:   expiresAt,
		Scope:       scope,
		Flow:        flow,
		SessionID:   sessionID,
	}, nil
}

// storeRotatedCredentials updates stored credentials for a refresh-token
// rotation only if expectedMeta.SessionID AND prevRefreshToken still match the
// active stored session.
func (p *Plugin) storeRotatedCredentials(ctx context.Context, cfg *Config, prevRefreshToken string, tokenResp *TokenResponse, expectedMeta *TokenMetadata) error {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return fmt.Errorf("host service not available")
	}

	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return err
	}

	// Fetch updated user claims outside the profile lock so network I/O never
	// holds the lock. Even if ctx is cancelled during claims lookup, do NOT
	// abort before persisting tokenResp.RefreshToken because GitHub has already
	// consumed prevRefreshToken during the token exchange.
	claims, err := p.fetchUserClaims(ctx, tokenResp.AccessToken)
	if err != nil {
		if expectedMeta.Claims != nil {
			claims = expectedMeta.Claims
		} else {
			claims = &auth.Claims{Issuer: cfg.Hostname}
		}
	}

	persistCtx, persistCancel := p.newCleanupContext(ctx)
	defer persistCancel()
	persistCtx = auth.WithProfile(persistCtx, profile)

	mu := p.profileLock(profile)
	mu.Lock()
	defer mu.Unlock()

	curMeta, curErr := p.loadMetadataUnlocked(persistCtx)
	if curErr != nil || curMeta == nil || curMeta.SessionID != expectedMeta.SessionID {
		return nil
	}
	// Require SecretKeyRefreshToken to exist and match prevRefreshToken before
	// committing rotated credentials so a partial Logout (which deleted tokens
	// before failing on metadata deletion) cannot be resurrected by a late rotation.
	curRT, rtErr := p.loadRefreshTokenUnlocked(persistCtx)
	if rtErr != nil || curRT == "" || curRT != prevRefreshToken {
		return nil
	}

	rotCfg := cfg.clone()
	rotCfg.hasHostnameOverride = expectedMeta.HostnameOverride
	if expectedMeta.ClientID != "" && rotCfg.ClientID != expectedMeta.ClientID {
		rotCfg.ClientID = expectedMeta.ClientID
	}

	_, err = p.storeCredentialsLocked(persistCtx, rotCfg, hostClient, profile, tokenResp, claims, expectedMeta.Scopes, expectedMeta.SessionID, expectedMeta.Flow, true)
	return err
}

// storeCredentials securely stores the refresh token (or access token) and metadata.
func (p *Plugin) storeCredentials(ctx context.Context, tokenResp *TokenResponse, scopes []string, sessionID string, flow auth.Flow) (*auth.Claims, error) {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return nil, fmt.Errorf("host service not available")
	}

	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return nil, err
	}

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	// Fetch user claims before mutating stored secrets or acquiring the profile
	// lock so network I/O never holds the lock or leaves partial state on failure.
	claims, err := p.fetchUserClaims(ctx, tokenResp.AccessToken)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if isUnauthorizedStatusError(err) {
			return nil, fmt.Errorf("access token validation failed: %w", err)
		}
		claims = &auth.Claims{
			Issuer: cfg.Hostname,
		}
	}

	mu := p.profileLock(profile)
	mu.Lock()
	defer mu.Unlock()

	return p.storeCredentialsLocked(ctx, cfg, hostClient, profile, tokenResp, claims, scopes, sessionID, flow, false)
}

func (p *Plugin) storeCredentialsLocked(
	ctx context.Context,
	cfg *Config,
	hostClient *sdkplugin.HostServiceClient,
	profile string,
	tokenResp *TokenResponse,
	claims *auth.Claims,
	scopes []string,
	sessionID string,
	flow auth.Flow,
	isRotation bool,
) (*auth.Claims, error) {
	if sessionID == "" {
		sessionID = uuid.New().String()
	}

	var refreshTokenExpiresAt time.Time
	if tokenResp.RefreshTokenExpiresIn > 0 {
		refreshTokenExpiresAt = time.Now().Add(time.Duration(tokenResp.RefreshTokenExpiresIn) * time.Second)
	}

	clientID := cfg.ClientID
	if flow == auth.FlowPAT {
		clientID = ""
	}

	metadata := &TokenMetadata{
		Claims:                claims,
		RefreshTokenExpiresAt: refreshTokenExpiresAt,
		LastRefresh:           time.Now(),
		Hostname:              cfg.Hostname,
		HostnameOverride:      cfg.hasHostnameOverride,
		ClientID:              clientID,
		Scopes:                scopes,
		IdentityType:          string(auth.IdentityTypeUser),
		SessionID:             sessionID,
		Flow:                  flow,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	refreshKey, _ := profileSecretKey(SecretKeyRefreshToken, profile)
	accessKey, _ := profileSecretKey(SecretKeyAccessToken, profile)
	metaKey, _ := profileSecretKey(SecretKeyMetadata, profile)

	if isRotation {
		// Rotation recovery path: prevRefresh was already consumed by GitHub, so
		// skip rollback-only snapshot reads and never restore prevRefresh. Persist
		// the new refresh token first, then best-effort update accessKey and
		// metadata with a bounded cancellation-independent context so future
		// refreshes remain viable even after transient secret-store errors.
		var firstRotErr error
		if tokenResp.RefreshToken != "" {
			if err := hostClient.SetSecret(ctx, refreshKey, tokenResp.RefreshToken); err != nil {
				return nil, fmt.Errorf("failed to store rotated refresh token: %w", err)
			}
		}
		if tokenResp.AccessToken != "" {
			if err := hostClient.SetSecret(ctx, accessKey, tokenResp.AccessToken); err != nil {
				firstRotErr = fmt.Errorf("failed to store rotated access token: %w", err)
			}
		}
		if err := hostClient.SetSecret(ctx, metaKey, string(metadataBytes)); err != nil && firstRotErr == nil {
			firstRotErr = fmt.Errorf("failed to store rotated metadata: %w", err)
		}
		return claims, firstRotErr
	}

	prevRefresh, hadPrevRefresh, prevRefreshErr := hostClient.GetSecret(ctx, refreshKey)
	if prevRefreshErr != nil {
		return nil, fmt.Errorf("failed to inspect existing refresh token: %w", prevRefreshErr)
	}
	prevAccess, hadPrevAccess, prevAccessErr := hostClient.GetSecret(ctx, accessKey)
	if prevAccessErr != nil {
		return nil, fmt.Errorf("failed to inspect existing access token: %w", prevAccessErr)
	}
	prevMeta, hadPrevMeta, prevMetaErr := hostClient.GetSecret(ctx, metaKey)
	if prevMetaErr != nil {
		return nil, fmt.Errorf("failed to inspect existing metadata: %w", prevMetaErr)
	}

	cacheKey := sessionTokenCacheKey(cfg.Hostname)

	rollbackSecrets := func(mutatedRefresh, wroteAccess, wroteMeta, wroteCache bool) {
		cleanupCtx, cleanupCancel := p.newCleanupContext(ctx)
		defer cleanupCancel()
		if mutatedRefresh {
			if hadPrevRefresh {
				_ = hostClient.SetSecret(cleanupCtx, refreshKey, prevRefresh)
			} else {
				_ = hostClient.DeleteSecret(cleanupCtx, refreshKey)
			}
		}
		if wroteAccess {
			if hadPrevAccess {
				_ = hostClient.SetSecret(cleanupCtx, accessKey, prevAccess)
			} else {
				_ = hostClient.DeleteSecret(cleanupCtx, accessKey)
			}
		}
		if wroteMeta {
			if hadPrevMeta {
				_ = hostClient.SetSecret(cleanupCtx, metaKey, prevMeta)
			} else {
				_ = hostClient.DeleteSecret(cleanupCtx, metaKey)
			}
		}
		if wroteCache && !hadPrevMeta {
			if prefix, pErr := profileTokenPrefix(profile); pErr == nil {
				_ = hostClient.DeleteSecret(cleanupCtx, prefix+cacheKey)
			}
		}
	}

	mutatedRefresh := false
	if tokenResp.RefreshToken != "" {
		if err := hostClient.SetSecret(ctx, refreshKey, tokenResp.RefreshToken); err != nil {
			return nil, fmt.Errorf("failed to store refresh token: %w", err)
		}
		mutatedRefresh = true
	} else if hadPrevRefresh {
		if err := hostClient.DeleteSecret(ctx, refreshKey); err != nil {
			return nil, fmt.Errorf("failed to clear previous refresh token: %w", err)
		}
		mutatedRefresh = true
	}

	wroteAccess := false
	if tokenResp.AccessToken != "" {
		if err := hostClient.SetSecret(ctx, accessKey, tokenResp.AccessToken); err != nil {
			rollbackSecrets(mutatedRefresh, false, false, false)
			return nil, fmt.Errorf("failed to store access token: %w", err)
		}
		wroteAccess = true
	}

	if err := hostClient.SetSecret(ctx, metaKey, string(metadataBytes)); err != nil {
		rollbackSecrets(mutatedRefresh, wroteAccess, false, false)
		return nil, fmt.Errorf("failed to store metadata: %w", err)
	}

	lgr := logr.FromContextOrDiscard(ctx)
	// Drop cached access tokens from any prior session/flow/hostname on this
	// profile using the caller's context so login-path cache cleanup stays
	// bounded by the flow deadline.
	cacheClear(ctx, lgr, hostClient, profile)
	if err := ctx.Err(); err != nil {
		rollbackSecrets(mutatedRefresh, wroteAccess, true, false)
		return nil, fmt.Errorf("credential storage cancelled during cache cleanup: %w", err)
	}

	// Cache the access token so ListCachedTokens can report it with full
	// metadata (ExpiresAt, Flow, etc.) immediately after login without
	// requiring a separate GetToken call.
	wroteCache := false
	if tokenResp.AccessToken != "" {
		var expiresAt time.Time
		if tokenResp.ExpiresIn > 0 {
			expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		} else if tokenResp.RefreshToken != "" {
			expiresAt = time.Now().Add(8 * time.Hour)
		} else {
			expiresAt = farFuture() // non-expiring PAT or OAuth App token without refresh token
		}
		cacheScope := tokenResp.Scope
		if cacheScope == "" {
			cacheScope = strings.Join(scopes, " ")
		}
		cacheToken := &auth.Token{
			AccessToken: tokenResp.AccessToken,
			TokenType:   tokenResp.TokenType,
			ExpiresAt:   expiresAt,
			Scope:       cacheScope,
			Flow:        flow,
			SessionID:   sessionID,
		}
		// Best-effort for non-cancellation errors: prior cached entries were already cleared above.
		if err := cacheSet(ctx, hostClient, cacheKey, cacheToken, profile); err != nil {
			lgr.V(1).Info("failed to cache token after login", "error", err)
		} else {
			wroteCache = true
		}
	}

	if err := ctx.Err(); err != nil {
		rollbackSecrets(mutatedRefresh, wroteAccess, true, wroteCache)
		return nil, fmt.Errorf("credential storage cancelled before completion: %w", err)
	}

	return claims, nil
}

// loadRefreshToken loads the stored refresh token from the host secret store.
func (p *Plugin) loadRefreshToken(ctx context.Context) (string, error) {
	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return "", err
	}
	mu := p.profileLock(profile)
	mu.RLock()
	defer mu.RUnlock()
	return p.loadRefreshTokenUnlocked(ctx)
}

func (p *Plugin) loadRefreshTokenUnlocked(ctx context.Context) (string, error) {
	profile := auth.ProfileFromContext(ctx)
	key, err := profileSecretKey(SecretKeyRefreshToken, profile)
	if err != nil {
		return "", err
	}
	return p.getSecret(ctx, key)
}

// loadAccessToken loads the stored access token from the host secret store.
func (p *Plugin) loadAccessToken(ctx context.Context) (string, error) {
	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return "", err
	}
	mu := p.profileLock(profile)
	mu.RLock()
	defer mu.RUnlock()

	key, err := profileSecretKey(SecretKeyAccessToken, profile)
	if err != nil {
		return "", err
	}
	return p.getSecret(ctx, key)
}

// loadMetadata loads the stored token metadata from the host secret store.
func (p *Plugin) loadMetadata(ctx context.Context) (*TokenMetadata, error) {
	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return nil, err
	}
	mu := p.profileLock(profile)
	mu.RLock()
	defer mu.RUnlock()
	return p.loadMetadataUnlocked(ctx)
}

func (p *Plugin) loadMetadataUnlocked(ctx context.Context) (*TokenMetadata, error) {
	profile := auth.ProfileFromContext(ctx)
	key, err := profileSecretKey(SecretKeyMetadata, profile)
	if err != nil {
		return nil, err
	}
	data, err := p.getSecret(ctx, key)
	if err != nil {
		return nil, err
	}

	var metadata TokenMetadata
	if err := decodeMetadata(data, &metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

// getSecret is a helper that retrieves a secret from the host service.
func (p *Plugin) getSecret(ctx context.Context, name string) (string, error) {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return "", fmt.Errorf("host service not available")
	}
	value, found, err := hostClient.GetSecret(ctx, name)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("secret %q not found", name)
	}
	return value, nil
}

// secretExists checks if a secret exists in the host secret store.
func (p *Plugin) secretExists(ctx context.Context, name string) bool {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return false
	}
	_, found, err := hostClient.GetSecret(ctx, name)
	return err == nil && found
}

// hostClient returns the HostServiceClient from context or the cached one.
func (p *Plugin) hostClient(ctx context.Context) *sdkplugin.HostServiceClient {
	if client := sdkplugin.HostClientFromContext(ctx); client != nil {
		return client
	}
	p.mu.RLock()
	cached := p.cachedHostClient
	p.mu.RUnlock()
	return cached
}

// binaryName returns the configured binary name or a default.
func (p *Plugin) binaryName() string {
	p.mu.RLock()
	name := p.cfg.BinaryName
	p.mu.RUnlock()
	if name != "" {
		return name
	}
	return "scafctl"
}

// makeFormData is a helper to create url.Values from a string map.
func makeFormData(params map[string]string) url.Values {
	data := make(url.Values, len(params))
	for k, v := range params {
		data[k] = []string{v}
	}
	return data
}
