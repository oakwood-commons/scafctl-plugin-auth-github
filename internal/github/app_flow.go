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

// appLogin performs the GitHub App installation token flow.
func (p *Plugin) appLogin(ctx context.Context) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting GitHub App installation token flow")

	hostClient := p.hostClient(ctx)

	// Validate required config
	if err := p.config.ValidateAppConfig(ctx, lgr, hostClient); err != nil {
		return nil, fmt.Errorf("github: app_config: %w", err)
	}

	appID := p.config.GetAppID()
	installationID := p.config.GetInstallationID()

	// Load and parse private key
	keyBytes, err := p.config.GetPrivateKey(ctx, lgr, hostClient)
	if err != nil {
		return nil, fmt.Errorf("github: private_key: %w", err)
	}

	privateKey, err := parseRSAPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("github: private_key_parse: %w", err)
	}

	// Create JWT
	appJWT, err := createAppJWT(appID, privateKey)
	if err != nil {
		return nil, fmt.Errorf("github: jwt_create: %w", err)
	}

	lgr.V(1).Info("created GitHub App JWT", "appId", appID)

	// Validate JWT by calling GET /app
	appInfo, err := p.getAppInfo(ctx, appJWT)
	if err != nil {
		return nil, fmt.Errorf("github: app_validate: failed to validate GitHub App: %w", err)
	}

	lgr.V(1).Info("validated GitHub App",
		"appId", appInfo.ID,
		"slug", appInfo.Slug,
		"name", appInfo.Name,
	)

	// Exchange JWT for installation access token
	installToken, err := p.createInstallationToken(ctx, appJWT, installationID)
	if err != nil {
		return nil, fmt.Errorf("github: installation_token: %w", err)
	}

	lgr.V(1).Info("acquired installation token",
		"installationId", installationID,
		"expiresAt", installToken.ExpiresAt,
	)

	// Cache the token
	profile := auth.ProfileFromContext(ctx)
	if err := validateProfile(profile); err != nil {
		return nil, err
	}
	token := &auth.Token{
		AccessToken: installToken.Token,
		TokenType:   "Bearer",
		ExpiresAt:   installToken.ExpiresAt,
		Flow:        auth.FlowGitHubApp,
	}
	if hostClient != nil {
		appFingerprint := fingerprintHash(fmt.Sprintf("%d:%d", appID, installationID))
		cacheKey := appFingerprint + ":" + installationTokenCacheKey
		if cacheErr := cacheSet(ctx, hostClient, cacheKey, token, profile); cacheErr != nil {
			lgr.V(1).Info("failed to cache installation token", "error", cacheErr)
		}
	}

	// Store as primary access token
	if hostClient != nil {
		accessKey, _ := profileSecretKey(SecretKeyAccessToken, profile)
		if err := hostClient.SetSecret(ctx, accessKey, installToken.Token); err != nil {
			return nil, fmt.Errorf("github: store_token: failed to store installation token: %w", err)
		}
	}

	// Build claims from app info
	claims := &auth.Claims{
		Issuer:   p.config.Hostname,
		Subject:  fmt.Sprintf("app/%s", appInfo.Slug),
		ObjectID: strconv.FormatInt(appInfo.ID, 10),
		Name:     appInfo.Name,
		Username: appInfo.Slug,
		IssuedAt: time.Now(),
	}

	// Store metadata
	metadata := &TokenMetadata{
		Claims:       claims,
		LastRefresh:  time.Now(),
		Hostname:     p.config.Hostname,
		IdentityType: string(auth.IdentityTypeServicePrincipal),
	}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("github: store_metadata: failed to marshal metadata: %w", err)
	}
	if hostClient != nil {
		metaKey, _ := profileSecretKey(SecretKeyMetadata, profile)
		if err := hostClient.SetSecret(ctx, metaKey, string(metadataBytes)); err != nil {
			return nil, fmt.Errorf("github: store_metadata: failed to store metadata: %w", err)
		}
	}

	return &sdkplugin.LoginResponse{
		Claims:    claims,
		ExpiresAt: installToken.ExpiresAt,
	}, nil
}

// getAppInfo calls GET /app to validate the JWT and retrieve app information.
func (p *Plugin) getAppInfo(ctx context.Context, appJWT string) (*AppInfo, error) {
	endpoint := fmt.Sprintf("%s/app", p.config.GetAPIBaseURL())
	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", appJWT),
	}

	resp, err := p.httpClient.Get(ctx, endpoint, headers)
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
	endpoint := fmt.Sprintf("%s/app/installations/%d/access_tokens", p.config.GetAPIBaseURL(), installationID)
	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", appJWT),
	}

	resp, err := p.httpClient.PostJSON(ctx, endpoint, nil, headers)
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
