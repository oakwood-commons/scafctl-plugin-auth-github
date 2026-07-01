// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"sync"
	"time"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// singleStore is a manager.Store that holds exactly one cached value.
// GitHub App installation tokens are singletons — one per app+installation —
// so there is no need for a multi-entry container.
type singleStore struct {
	mu           sync.RWMutex
	nowFunc      func() time.Time
	expiryBuffer time.Duration
	key          string
	value        *sdkplugin.TokenResponse
	expiresAt    time.Time
}

func (s *singleStore) now() time.Time {
	if s.nowFunc != nil {
		return s.nowFunc()
	}
	return time.Now()
}

func (s *singleStore) Get(_ context.Context, key string) (*sdkplugin.TokenResponse, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.key != key || s.value == nil {
		return nil, false
	}
	if !s.expiresAt.IsZero() && s.now().After(s.expiresAt.Add(-s.expiryBuffer)) {
		return nil, false
	}
	return s.value, true
}

func (s *singleStore) Set(_ context.Context, key string, value *sdkplugin.TokenResponse, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key = key
	s.value = value
	if ttl == 0 {
		// Zero TTL means no expiry.
		s.expiresAt = time.Time{}
	} else {
		// Positive TTL sets future expiry; negative TTL (already expired) sets past expiresAt
		// so Get() correctly returns a miss.
		s.expiresAt = s.now().Add(ttl)
	}
}
