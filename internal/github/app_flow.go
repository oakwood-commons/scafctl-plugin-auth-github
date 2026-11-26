// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// AppInfo represents the response from the GET /app endpoint.
type AppInfo struct {
	ID          int64  `json:"id"`
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Owner       struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
	} `json:"owner"`
}

// InstallationTokenResponse represents the response from
// POST /app/installations/{id}/access_tokens.
type InstallationTokenResponse struct {
	Token       string            `json:"token"`      //nolint:gosec // Not a hardcoded credential
	ExpiresAt   time.Time         `json:"expires_at"` //nolint:gosec // Not a hardcoded credential
	Permissions map[string]string `json:"permissions"`
}

// installationTokenCacheKey is the fixed cache key for GitHub App installation tokens.
const installationTokenCacheKey = "_github_app" //nolint:gosec // Not a credential

// SecretKeyAppJWT is the secret key for storing the GitHub App JWT metadata.
const SecretKeyAppJWT = "scafctl.auth.github.app_metadata" //nolint:gosec // Key name, not a credential

type acquiredAppToken struct {
	cfg            *Config
	hostClient     *sdkplugin.HostServiceClient
	appID          int64
	installationID int64
	claims         *auth.Claims
	installToken   *InstallationTokenResponse
}

// acquireAppInstallationToken validates GitHub App configuration and performs
// the JWT validation + installation token HTTP calls without holding profileLock.
func (p *Plugin) acquireAppInstallationToken(ctx context.Context) (*acquiredAppToken, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	hostClient := p.hostClient(ctx)

	if err := cfg.ValidateAppConfig(ctx, lgr, hostClient); err != nil {
		return nil, fmt.Errorf("github: app_config: %w", err)
	}

	appID := cfg.GetAppID()
	installationID := cfg.GetInstallationID()

	keyBytes, err := cfg.GetPrivateKey(ctx, lgr, hostClient)
	if err != nil {
		return nil, fmt.Errorf("github: private_key: %w", err)
	}

	privateKey, err := parseRSAPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("github: private_key_parse: %w", err)
	}

	appJWT, err := createAppJWT(appID, privateKey)
	if err != nil {
		return nil, fmt.Errorf("github: jwt_create: %w", err)
	}

	lgr.V(1).Info("created GitHub App JWT", "appId", appID)

	appInfo, err := p.getAppInfo(ctx, appJWT)
	if err != nil {
		return nil, fmt.Errorf("github: app_validate: failed to validate GitHub App: %w", err)
	}

	slug := sanitizeControlChars(appInfo.Slug)
	name := sanitizeControlChars(appInfo.Name)

	lgr.V(1).Info("validated GitHub App",
		"appId", appInfo.ID,
		"slug", slug,
		"name", name,
	)

	installToken, err := p.createInstallationToken(ctx, appJWT, installationID)
	if err != nil {
		return nil, fmt.Errorf("github: installation_token: %w", err)
	}

	lgr.V(1).Info("acquired installation token",
		"installationId", installationID,
		"expiresAt", installToken.ExpiresAt,
	)

	claims := &auth.Claims{
		Issuer:   cfg.Hostname,
		Subject:  fmt.Sprintf("app/%s", slug),
		ObjectID: strconv.FormatInt(appInfo.ID, 10),
		Name:     name,
		Username: slug,
		IssuedAt: time.Now(),
	}

	return &acquiredAppToken{
		cfg:            cfg,
		hostClient:     hostClient,
		appID:          appID,
		installationID: installationID,
		claims:         claims,
		installToken:   installToken,
	}, nil
}

// appLogin performs the GitHub App installation token flow for an explicit login.
func (p *Plugin) appLogin(ctx context.Context) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting GitHub App installation token flow")

	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return nil, err
	}

	acq, err := p.acquireAppInstallationToken(ctx)
	if err != nil {
		return nil, err
	}

	sessionID := uuid.New().String()

	metadata := &TokenMetadata{
		Claims:               acq.claims,
		AccessTokenExpiresAt: acq.installToken.ExpiresAt,
		LastRefresh:          time.Now(),
		Hostname:             acq.cfg.Hostname,
		HostnameOverride:     acq.cfg.hasHostnameOverride,
		IdentityType:         string(auth.IdentityTypeServicePrincipal),
		SessionID:            sessionID,
		Flow:                 auth.FlowGitHubApp,
		AppID:                acq.appID,
		InstallationID:       acq.installationID,
	}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("github: store_metadata: failed to marshal metadata: %w", err)
	}

	hostClient := acq.hostClient
	if hostClient != nil {
		mu := p.profileLock(profile)
		mu.Lock()
		defer mu.Unlock()

		refreshKey, _ := profileSecretKey(SecretKeyRefreshToken, profile)
		accessKey, _ := profileSecretKey(SecretKeyAccessToken, profile)
		metaKey, _ := profileSecretKey(SecretKeyMetadata, profile)

		prevRefresh, hadPrevRefresh, prevRefreshErr := hostClient.GetSecret(ctx, refreshKey)
		if prevRefreshErr != nil {
			return nil, fmt.Errorf("github: store_token: failed to inspect existing refresh token: %w", prevRefreshErr)
		}
		prevAccess, hadPrevAccess, prevAccessErr := hostClient.GetSecret(ctx, accessKey)
		if prevAccessErr != nil {
			return nil, fmt.Errorf("github: store_token: failed to inspect existing token: %w", prevAccessErr)
		}
		prevMeta, hadPrevMeta, prevMetaErr := hostClient.GetSecret(ctx, metaKey)
		if prevMetaErr != nil {
			return nil, fmt.Errorf("github: store_metadata: failed to inspect existing metadata: %w", prevMetaErr)
		}

		appFingerprint := fingerprintHash(fmt.Sprintf("%s:%d:%d", acq.cfg.Hostname, acq.appID, acq.installationID))
		cacheKey := appFingerprint + ":" + installationTokenCacheKey

		rollbackAppSecrets := func(removedRefresh, wroteAccess, wroteMeta, wroteCache bool) {
			cleanupCtx, cleanupCancel := p.newCleanupContext(ctx)
			defer cleanupCancel()
			if removedRefresh && hadPrevRefresh {
				_ = hostClient.SetSecret(cleanupCtx, refreshKey, prevRefresh)
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

		removedRefresh := false
		if hadPrevRefresh {
			if err := hostClient.DeleteSecret(ctx, refreshKey); err != nil {
				return nil, fmt.Errorf("github: store_token: failed to clear previous refresh token: %w", err)
			}
			removedRefresh = true
		}

		if err := hostClient.SetSecret(ctx, accessKey, acq.installToken.Token); err != nil {
			rollbackAppSecrets(removedRefresh, false, false, false)
			return nil, fmt.Errorf("github: store_token: failed to store installation token: %w", err)
		}

		if err := hostClient.SetSecret(ctx, metaKey, string(metadataBytes)); err != nil {
			rollbackAppSecrets(removedRefresh, true, false, false)
			return nil, fmt.Errorf("github: store_metadata: failed to store metadata: %w", err)
		}

		cacheClear(ctx, lgr, hostClient, profile)
		if err := ctx.Err(); err != nil {
			rollbackAppSecrets(removedRefresh, true, true, false)
			return nil, fmt.Errorf("github: store_metadata: %w", err)
		}

		token := &auth.Token{
			AccessToken: acq.installToken.Token,
			TokenType:   "Bearer",
			ExpiresAt:   acq.installToken.ExpiresAt,
			Flow:        auth.FlowGitHubApp,
			SessionID:   sessionID,
		}
		wroteCache := false
		if cacheErr := cacheSet(ctx, hostClient, cacheKey, token, profile); cacheErr != nil {
			lgr.V(1).Info("failed to cache installation token", "error", cacheErr)
		} else {
			wroteCache = true
		}
		if err := ctx.Err(); err != nil {
			rollbackAppSecrets(removedRefresh, true, true, wroteCache)
			return nil, fmt.Errorf("github: store_metadata: %w", err)
		}
	}

	return &sdkplugin.LoginResponse{
		Claims:    acq.claims,
		ExpiresAt: acq.installToken.ExpiresAt,
	}, nil
}

// renewAppInstallationToken mints a fresh GitHub App installation token during
// GetToken while keeping HTTP I/O outside profileLock, pinned to expectedAppID
// and expectedInstallationID, and commits the renewed token/metadata/cache ONLY
// if expectedSessionID and the stored app/installation identity still match.
func (p *Plugin) renewAppInstallationToken(ctx context.Context, expectedSessionID string, expectedAppID, expectedInstallationID int64) (*sdkplugin.TokenResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return nil, err
	}

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	pinnedCfg := cfg.clone()
	if expectedAppID != 0 {
		pinnedCfg.AppID = expectedAppID
	}
	if expectedInstallationID != 0 {
		pinnedCfg.InstallationID = expectedInstallationID
	}
	ctx = withResolvedConfig(ctx, pinnedCfg)

	acq, err := p.acquireAppInstallationToken(ctx)
	if err != nil {
		return nil, err
	}

	hostClient := acq.hostClient
	if hostClient == nil {
		return nil, fmt.Errorf("not authenticated: host service not available")
	}

	mu := p.profileLock(profile)
	mu.Lock()
	defer mu.Unlock()

	accessKey, _ := profileSecretKey(SecretKeyAccessToken, profile)
	metaKey, _ := profileSecretKey(SecretKeyMetadata, profile)

	prevAccess, hadPrevAccess, prevAccessErr := hostClient.GetSecret(ctx, accessKey)
	if prevAccessErr != nil {
		return nil, fmt.Errorf("github: store_token: failed to inspect existing token: %w", prevAccessErr)
	}
	curMeta, curMetaErr := p.loadMetadataUnlocked(ctx)
	if curMetaErr != nil || curMeta == nil || !hadPrevAccess || prevAccess == "" {
		return nil, fmt.Errorf("not authenticated: GitHub App session ended during token renewal")
	}
	if curMeta.Flow != auth.FlowGitHubApp || curMeta.SessionID != expectedSessionID {
		return nil, fmt.Errorf("GitHub App session changed during token renewal")
	}
	if (curMeta.AppID != 0 && curMeta.AppID != acq.appID) ||
		(curMeta.InstallationID != 0 && curMeta.InstallationID != acq.installationID) {
		return nil, fmt.Errorf("GitHub App session identity changed during token renewal")
	}

	updatedMeta := *curMeta
	updatedMeta.Claims = acq.claims
	updatedMeta.AccessTokenExpiresAt = acq.installToken.ExpiresAt
	updatedMeta.LastRefresh = time.Now()
	updatedMeta.Hostname = acq.cfg.Hostname
	updatedMeta.AppID = acq.appID
	updatedMeta.InstallationID = acq.installationID

	metadataBytes, err := json.Marshal(&updatedMeta)
	if err != nil {
		return nil, fmt.Errorf("github: store_metadata: failed to marshal metadata: %w", err)
	}

	if err := hostClient.SetSecret(ctx, accessKey, acq.installToken.Token); err != nil {
		return nil, fmt.Errorf("github: store_token: failed to store installation token: %w", err)
	}
	if err := hostClient.SetSecret(ctx, metaKey, string(metadataBytes)); err != nil {
		cleanupCtx, cleanupCancel := p.newCleanupContext(ctx)
		_ = hostClient.SetSecret(cleanupCtx, accessKey, prevAccess)
		cleanupCancel()
		return nil, fmt.Errorf("github: store_metadata: failed to store metadata: %w", err)
	}

	token := &auth.Token{
		AccessToken: acq.installToken.Token,
		TokenType:   "Bearer",
		ExpiresAt:   acq.installToken.ExpiresAt,
		Flow:        auth.FlowGitHubApp,
		SessionID:   expectedSessionID,
	}
	appFingerprint := fingerprintHash(fmt.Sprintf("%s:%d:%d", acq.cfg.Hostname, acq.appID, acq.installationID))
	cacheKey := appFingerprint + ":" + installationTokenCacheKey
	if cacheErr := cacheSet(ctx, hostClient, cacheKey, token, profile); cacheErr != nil {
		lgr.V(1).Info("failed to cache installation token", "error", cacheErr)
	}

	return &sdkplugin.TokenResponse{
		AccessToken: acq.installToken.Token,
		TokenType:   "Bearer",
		ExpiresAt:   acq.installToken.ExpiresAt,
		Flow:        auth.FlowGitHubApp,
		SessionID:   expectedSessionID,
	}, nil
}

// getAppInfo calls GET /app to validate the JWT and retrieve app information.
func (p *Plugin) getAppInfo(ctx context.Context, appJWT string) (*AppInfo, error) {
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	httpClient, releaseHTTP, err := p.acquireHTTPClient(ctx, cfg, true)
	if err != nil {
		return nil, err
	}
	defer releaseHTTP()

	endpoint := fmt.Sprintf("%s/app", cfg.GetAPIBaseURL())
	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", appJWT),
	}

	resp, err := httpClient.Get(ctx, endpoint, headers)
	if err != nil {
		return nil, fmt.Errorf("GET /app failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET /app returned status %d -- verify app ID and private key are correct", resp.StatusCode)
	}

	var appInfo AppInfo
	if err := json.NewDecoder(resp.Body).Decode(&appInfo); err != nil {
		return nil, fmt.Errorf("failed to parse app info response: %w", err)
	}

	return &appInfo, nil
}

// createInstallationToken exchanges a GitHub App JWT for an installation access token.
func (p *Plugin) createInstallationToken(ctx context.Context, appJWT string, installationID int64) (*InstallationTokenResponse, error) {
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	httpClient, releaseHTTP, err := p.acquireHTTPClient(ctx, cfg, true)
	if err != nil {
		return nil, err
	}
	defer releaseHTTP()
	return createInstallationTokenHTTP(ctx, httpClient, cfg.GetAPIBaseURL(), appJWT, installationID)
}

// createInstallationTokenHTTP exchanges a GitHub App JWT for an installation access token
// using the provided HTTP client and API base URL.
func createInstallationTokenHTTP(ctx context.Context, httpClient HTTPClient, apiBaseURL string, appJWT string, installationID int64) (*InstallationTokenResponse, error) {
	endpoint := fmt.Sprintf("%s/app/installations/%d/access_tokens", apiBaseURL, installationID)
	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", appJWT),
	}

	resp, err := httpClient.PostJSON(ctx, endpoint, nil, headers)
	if err != nil {
		return nil, fmt.Errorf("create installation token failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 201 {
		return nil, fmt.Errorf("create installation token returned status %d -- verify installation ID %d is correct", resp.StatusCode, installationID)
	}

	var tokenResp InstallationTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse installation token response: %w", err)
	}

	return &tokenResp, nil
}

// parseRSAPrivateKey parses a PEM-encoded RSA private key.
func parseRSAPrivateKey(keyBytes []byte) (*rsa.PrivateKey, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}
	return key, nil
}

// createAppJWT creates a JWT for a GitHub App.
func createAppJWT(appID int64, privateKey *rsa.PrivateKey) (string, error) {
	now := time.Now()

	claims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
		Issuer:    strconv.FormatInt(appID, 10),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	return signedToken, nil
}
