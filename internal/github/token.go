// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"net/url"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// TokenMetadata stores information about the stored credentials.
type TokenMetadata struct {
	Claims                *auth.Claims `json:"claims"`
	RefreshTokenExpiresAt time.Time    `json:"refreshTokenExpiresAt,omitempty"`
	LastRefresh           time.Time    `json:"lastRefresh"`
	Hostname              string       `json:"hostname"`
	ClientID              string       `json:"clientId,omitempty"`
	Scopes                []string     `json:"scopes,omitempty"`
	IdentityType          string       `json:"identityType,omitempty"`
	SessionID             string       `json:"sessionId,omitempty"`
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
}

// mintToken creates a new access token using the refresh token.
func (p *Plugin) mintToken(ctx context.Context) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("minting access token")

	refreshToken, err := p.loadRefreshToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("not authenticated: %w", err)
	}

	metadata, err := p.loadMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load metadata: %w", err)
	}

	if metadata.ClientID == "" {
		return nil, fmt.Errorf("stored credentials are missing client ID, please re-authenticate with '%s auth login github'", p.binaryName())
	}

	return p.refreshAccessToken(ctx, refreshToken, metadata.ClientID)
}

// refreshAccessToken refreshes an access token using the refresh token.
func (p *Plugin) refreshAccessToken(ctx context.Context, refreshToken, clientID string) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	endpoint := fmt.Sprintf("%s/login/oauth/access_token", p.config.GetOAuthBaseURL())

	data := makeFormData(map[string]string{
		"client_id":     clientID,
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	})

	resp, err := p.httpClient.PostForm(ctx, endpoint, data)
	if err != nil {
		return nil, fmt.Errorf("token refresh request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		lgr.V(0).Info("token refresh returned empty access token -- refresh token may be expired or revoked; re-authenticate with login")
		return nil, fmt.Errorf("refresh token expired or revoked, please re-authenticate with '%s auth login github'", p.binaryName())
	}

	// If we got a new refresh token, update stored credentials
	if tokenResp.RefreshToken != "" && tokenResp.RefreshToken != refreshToken {
		lgr.V(1).Info("refresh token rotated, storing new token")
		metadata, metaErr := p.loadMetadata(ctx)
		if metaErr != nil {
			lgr.V(1).Info("failed to load metadata during token rotation, skipping credential update", "error", metaErr)
		} else {
			var scopes []string
			var sessionID string
			if metadata != nil {
				scopes = metadata.Scopes
				sessionID = metadata.SessionID
			}
			if _, err := p.storeCredentials(ctx, &tokenResp, scopes, sessionID); err != nil {
				lgr.V(1).Info("warning: failed to update refresh token", "error", err)
			}
		}
	}

	expiresAt := time.Now().Add(8 * time.Hour)
	if tokenResp.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	return &auth.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresAt:   expiresAt,
		Scope:       tokenResp.Scope,
		Flow:        auth.FlowDeviceCode,
	}, nil
}

// storeCredentials securely stores the refresh token (or access token) and metadata.
func (p *Plugin) storeCredentials(ctx context.Context, tokenResp *TokenResponse, scopes []string, sessionID string) (*auth.Claims, error) {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return nil, fmt.Errorf("host service not available")
	}

	if tokenResp.RefreshToken != "" {
		if err := hostClient.SetSecret(ctx, SecretKeyRefreshToken, tokenResp.RefreshToken); err != nil {
			return nil, fmt.Errorf("failed to store refresh token: %w", err)
		}
	}

	if tokenResp.AccessToken != "" {
		if err := hostClient.SetSecret(ctx, SecretKeyAccessToken, tokenResp.AccessToken); err != nil {
			return nil, fmt.Errorf("failed to store access token: %w", err)
		}
	}

	claims, err := p.fetchUserClaims(ctx, tokenResp.AccessToken)
	if err != nil {
		claims = &auth.Claims{
			Issuer: p.config.Hostname,
		}
	}

	if sessionID == "" {
		sessionID = uuid.New().String()
	}

	var refreshTokenExpiresAt time.Time
	if tokenResp.RefreshTokenExpiresIn > 0 {
		refreshTokenExpiresAt = time.Now().Add(time.Duration(tokenResp.RefreshTokenExpiresIn) * time.Second)
	}

	metadata := &TokenMetadata{
		Claims:                claims,
		RefreshTokenExpiresAt: refreshTokenExpiresAt,
		LastRefresh:           time.Now(),
		Hostname:              p.config.Hostname,
		ClientID:              p.config.ClientID,
		Scopes:                scopes,
		IdentityType:          string(auth.IdentityTypeUser),
		SessionID:             sessionID,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := hostClient.SetSecret(ctx, SecretKeyMetadata, string(metadataBytes)); err != nil {
		return nil, fmt.Errorf("failed to store metadata: %w", err)
	}

	return claims, nil
}

// loadRefreshToken loads the stored refresh token from the host secret store.
func (p *Plugin) loadRefreshToken(ctx context.Context) (string, error) {
	return p.getSecret(ctx, SecretKeyRefreshToken)
}

// loadAccessToken loads the stored access token from the host secret store.
func (p *Plugin) loadAccessToken(ctx context.Context) (string, error) {
	return p.getSecret(ctx, SecretKeyAccessToken)
}

// loadMetadata loads the stored token metadata from the host secret store.
func (p *Plugin) loadMetadata(ctx context.Context) (*TokenMetadata, error) {
	data, err := p.getSecret(ctx, SecretKeyMetadata)
	if err != nil {
		return nil, err
	}

	var metadata TokenMetadata
	if err := json.Unmarshal([]byte(data), &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
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
	return p.cachedHostClient
}

// binaryName returns the configured binary name or a default.
func (p *Plugin) binaryName() string {
	if p.cfg.BinaryName != "" {
		return p.cfg.BinaryName
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
