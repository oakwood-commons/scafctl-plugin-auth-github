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

// patLogin validates a PAT by calling the GitHub API.
func (p *Plugin) patLogin(ctx context.Context, req sdkplugin.LoginRequest) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting PAT login", "handler", HandlerName)

	token := GetPATFromEnv()
	if token == "" {
		return nil, fmt.Errorf("personal access token not configured: set %s or %s environment variable",
			EnvGitHubToken, EnvGHToken)
	}

	claims, err := p.fetchUserClaims(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("PAT authentication failed: %w", err)
	}

	lgr.V(1).Info("PAT authentication successful",
		"login", claims.Subject,
		"name", claims.Name,
	)

	if len(req.Scopes) > 0 {
		lgr.V(0).Info("WARNING: --scope flags are ignored for PAT authentication; PAT scopes are fixed at token creation time on GitHub")
	}

	return &sdkplugin.LoginResponse{
		Claims: claims,
	}, nil
}

// patStatus returns auth status when PAT credentials are present.
func (p *Plugin) patStatus(ctx context.Context) (*auth.Status, error) {
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
		Scopes:        p.config.DefaultScopes,
	}, nil
}

// getPATToken returns a token from the PAT environment variable.
func (p *Plugin) getPATToken(ctx context.Context, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	token := GetPATFromEnv()
	if token == "" {
		return nil, fmt.Errorf("personal access token not configured: set %s or %s environment variable",
			EnvGitHubToken, EnvGHToken)
	}

	hostClient := p.hostClient(ctx)
	profile := auth.ProfileFromContext(ctx)

	// Use hostname-based cache key to avoid passing the raw token through
	// more code paths than necessary.
	fp := fingerprintHash(p.config.Hostname)
	cacheKey := fp + ":pat:" + defaultCacheKey

	// Check cache unless force refresh
	if !req.ForceRefresh && hostClient != nil {
		cached, err := cacheGet(ctx, hostClient, cacheKey, profile)
		if err == nil && cached != nil {
			minValidFor := req.MinValidFor
			if minValidFor == 0 {
				minValidFor = auth.DefaultMinValidFor
			}
			if cached.IsValidFor(minValidFor) {
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
	}

	// Validate the PAT
	_, err := p.fetchUserClaims(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("PAT validation failed: %w", err)
	}

	result := &sdkplugin.TokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(365 * 24 * time.Hour),
		Flow:        auth.FlowPAT,
	}

	// Cache it
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
