// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"time"

	manager "github.com/oakwood-commons/go-flight/cache"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// DefaultExpiryThreshold is the minimum remaining TTL to consider a cached token valid.
// GitHub installation tokens expire after 1 hour; refresh when under 10 minutes remain.
const DefaultExpiryThreshold = 10 * time.Minute

// DefaultStoreBuffer is the early-expiry buffer subtracted from the token's remaining
// TTL when checking cache freshness, ensuring tokens are refreshed before actual expiry.
const DefaultStoreBuffer = 5 * time.Minute

// installationCacheKey is the fixed cache key — there's only ever one installation token.
const installationCacheKey = "install"

// cachedFlow wraps a FlowFn with the go-flight Manager for deduplication and caching.
// If mgr is nil, it passes through to inner directly.
func cachedFlow(inner FlowFn, mgr *manager.Manager[string, *sdkplugin.TokenResponse], hooks *manager.Hooks) FlowFn {
	if mgr == nil {
		return inner
	}
	return func(ctx context.Context, params FlowParams) (*sdkplugin.TokenResponse, error) {
		return mgr.Do(ctx, installationCacheKey, func(ctx context.Context) (manager.FetchResult[*sdkplugin.TokenResponse], error) {
			resp, err := inner(ctx, params)
			if err != nil {
				return manager.FetchResult[*sdkplugin.TokenResponse]{}, err
			}
			ttl := time.Until(resp.ExpiresAt)
			return manager.FetchResult[*sdkplugin.TokenResponse]{
				Value:  resp,
				TTL:    ttl,
				Policy: manager.CacheWithTTL,
			}, nil
		}, hooks)
	}
}

// newInstallationCacheManager creates a Manager configured for a single installation token.
func newInstallationCacheManager() *manager.Manager[string, *sdkplugin.TokenResponse] {
	return manager.NewManager(
		manager.WithExpiryThreshold[string, *sdkplugin.TokenResponse](DefaultExpiryThreshold),
		manager.WithStore("default", &singleStore{expiryBuffer: DefaultStoreBuffer}),
	)
}
