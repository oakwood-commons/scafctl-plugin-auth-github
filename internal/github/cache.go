// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// tokenCacheEntry is the JSON representation stored in the host secret store.
type tokenCacheEntry struct {
	AccessToken string    `json:"accessToken"` //nolint:gosec // Not a credential, JSON field name
	TokenType   string    `json:"tokenType"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Scope       string    `json:"scope,omitempty"`
	CachedAt    time.Time `json:"cachedAt"`
	Flow        auth.Flow `json:"flow,omitempty"`
	SessionID   string    `json:"sessionId,omitempty"`
}

// isProfileTokenCacheSecret reports whether fullKey belongs to profile's
// cached-token namespace.
//
// Default-profile cached tokens use the prefix "scafctl.auth.github.token.",
// which overlaps with secrets owned by a named profile literally called "token"
// ("scafctl.auth.github.token.{refresh_token,access_token,metadata,app_metadata}"
// and "scafctl.auth.github.token.token.<cacheKey>"). Rejecting those reserved
// suffixes keeps default-profile cache operations isolated from the "token"
// profile while preserving existing secret names.
func isProfileTokenCacheSecret(fullKey, prefix, profile string) bool {
	if !strings.HasPrefix(fullKey, prefix) {
		return false
	}
	rest := strings.TrimPrefix(fullKey, prefix)
	if rest == "" {
		return false
	}
	if profile == "" {
		switch rest {
		case strings.TrimPrefix(SecretKeyRefreshToken, secretKeyBase),
			strings.TrimPrefix(SecretKeyAccessToken, secretKeyBase),
			strings.TrimPrefix(SecretKeyMetadata, secretKeyBase),
			strings.TrimPrefix(SecretKeyAppJWT, secretKeyBase):
			return false
		}
		if strings.HasPrefix(rest, "token.") {
			return false
		}
	}
	return true
}

// cacheGet retrieves a cached token from the host secret store.
func cacheGet(ctx context.Context, hostClient *sdkplugin.HostServiceClient, cacheKey, profile string) (*auth.Token, error) {
	prefix, err := profileTokenPrefix(profile)
	if err != nil {
		return nil, err
	}
	fullKey := prefix + cacheKey
	if !isProfileTokenCacheSecret(fullKey, prefix, profile) {
		return nil, nil
	}
	value, found, err := hostClient.GetSecret(ctx, fullKey)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}

	var entry tokenCacheEntry
	if err := json.Unmarshal([]byte(value), &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cached token: %w", err)
	}

	return &auth.Token{
		AccessToken: entry.AccessToken,
		TokenType:   entry.TokenType,
		ExpiresAt:   entry.ExpiresAt,
		Scope:       entry.Scope,
		CachedAt:    entry.CachedAt,
		Flow:        entry.Flow,
		SessionID:   entry.SessionID,
	}, nil
}

// cacheSet stores a token in the host secret store cache.
func cacheSet(ctx context.Context, hostClient *sdkplugin.HostServiceClient, cacheKey string, token *auth.Token, profile string) error {
	entry := tokenCacheEntry{
		AccessToken: token.AccessToken,
		TokenType:   token.TokenType,
		ExpiresAt:   token.ExpiresAt,
		Scope:       token.Scope,
		CachedAt:    time.Now(),
		Flow:        token.Flow,
		SessionID:   token.SessionID,
	}

	data, err := json.Marshal(entry) //nolint:gosec // intentional: caching token data in host secret store
	if err != nil {
		return fmt.Errorf("failed to marshal token for caching: %w", err)
	}

	prefix, err := profileTokenPrefix(profile)
	if err != nil {
		return err
	}
	fullKey := prefix + cacheKey
	if !isProfileTokenCacheSecret(fullKey, prefix, profile) {
		return fmt.Errorf("cache key %q collides with reserved profile namespace", cacheKey)
	}
	return hostClient.SetSecret(ctx, fullKey, string(data))
}

// cacheClear removes all cached tokens from the host secret store, logging errors.
func cacheClear(ctx context.Context, lgr logr.Logger, hostClient *sdkplugin.HostServiceClient, profile string) {
	if err := cacheClearErr(ctx, hostClient, profile); err != nil {
		lgr.V(1).Info("failed to clear cached tokens", "error", err)
	}
}

// cacheClearErr removes all cached tokens for profile and returns the first error encountered.
func cacheClearErr(ctx context.Context, hostClient *sdkplugin.HostServiceClient, profile string) error {
	prefix, err := profileTokenPrefix(profile)
	if err != nil {
		return err
	}
	keys, err := hostClient.ListSecretsByPrefix(ctx, prefix)
	if err != nil {
		return fmt.Errorf("listing cached tokens: %w", err)
	}
	var firstErr error
	for _, key := range keys {
		if !isProfileTokenCacheSecret(key, prefix, profile) {
			continue
		}
		if delErr := hostClient.DeleteSecret(ctx, key); delErr != nil && firstErr == nil {
			firstErr = fmt.Errorf("deleting cached token %q: %w", key, delErr)
		}
	}
	return firstErr
}

// cacheListEntries lists all cached token entries.
func cacheListEntries(ctx context.Context, hostClient *sdkplugin.HostServiceClient, profile string) ([]*auth.CachedTokenInfo, error) {
	prefix, err := profileTokenPrefix(profile)
	if err != nil {
		return nil, err
	}
	keys, err := hostClient.ListSecretsByPrefix(ctx, prefix)
	if err != nil {
		return nil, err
	}

	var results []*auth.CachedTokenInfo
	for _, key := range keys {
		if !isProfileTokenCacheSecret(key, prefix, profile) {
			continue
		}
		value, found, err := hostClient.GetSecret(ctx, key)
		if err != nil || !found {
			continue
		}

		var entry tokenCacheEntry
		if err := json.Unmarshal([]byte(value), &entry); err != nil {
			continue
		}

		results = append(results, &auth.CachedTokenInfo{
			Handler:   HandlerName,
			TokenKind: "access",
			TokenType: entry.TokenType,
			Scope:     entry.Scope,
			Flow:      entry.Flow,
			ExpiresAt: entry.ExpiresAt,
			CachedAt:  entry.CachedAt,
			IsExpired: !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt),
			SessionID: entry.SessionID,
		})
	}

	return results, nil
}

// cachePurgeExpired removes expired tokens and returns the count removed.
func cachePurgeExpired(ctx context.Context, hostClient *sdkplugin.HostServiceClient, profile string) (int, error) {
	prefix, err := profileTokenPrefix(profile)
	if err != nil {
		return 0, err
	}
	keys, err := hostClient.ListSecretsByPrefix(ctx, prefix)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, key := range keys {
		if !isProfileTokenCacheSecret(key, prefix, profile) {
			continue
		}
		value, found, err := hostClient.GetSecret(ctx, key)
		if err != nil || !found {
			continue
		}

		var entry tokenCacheEntry
		if err := json.Unmarshal([]byte(value), &entry); err != nil {
			continue
		}

		if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
			if err := hostClient.DeleteSecret(ctx, key); err == nil {
				count++
			}
		}
	}

	return count, nil
}

// buildTokenCacheKey joins non-empty cache-key segments with '.' so the
// resulting secret name satisfies host secret-store character rules.
func buildTokenCacheKey(parts ...string) string {
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			filtered = append(filtered, part)
		}
	}
	return strings.Join(filtered, ".")
}

// sessionTokenCacheKey builds the host-secret cache key suffix for user or PAT sessions on hostname.
func sessionTokenCacheKey(hostname string) string {
	return buildTokenCacheKey(fingerprintHash(hostname), defaultCacheKey)
}

// appTokenCacheKey builds the host-secret cache key suffix for a GitHub App installation session.
func appTokenCacheKey(hostname string, appID, installID int64) string {
	fp := fingerprintHash(fmt.Sprintf("%s:%d:%d", hostname, appID, installID))
	return buildTokenCacheKey(fp, installationTokenCacheKey)
}

// patTokenCacheKey builds the host-secret cache key suffix for an ambient environment PAT.
// Including a SHA-256 digest over hostname and token ensures rotating GITHUB_TOKEN or GH_TOKEN
// in the environment never matches a stale cache entry.
func patTokenCacheKey(hostname, token string) string {
	fp := fingerprintHash(hostname + "\x00" + token)
	return buildTokenCacheKey(fp, "pat", defaultCacheKey)
}

// fingerprintHash returns a SHA-256 hash of the input, used for cache keys.
func fingerprintHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
