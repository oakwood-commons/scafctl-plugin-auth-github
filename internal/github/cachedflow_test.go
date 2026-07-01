// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	manager "github.com/oakwood-commons/go-flight/cache"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeTestFlow(token string, calls *atomic.Int64) FlowFn {
	return func(_ context.Context, _ FlowParams) (*sdkplugin.TokenResponse, error) {
		calls.Add(1)
		return &sdkplugin.TokenResponse{
			AccessToken: token,
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	}
}

func TestCachedFlow_NilManager_PassesThrough(t *testing.T) {
	var calls atomic.Int64
	inner := makeTestFlow("tok", &calls)

	wrapped := cachedFlow(inner, nil, nil)
	resp, err := wrapped(context.Background(), FlowParams{})
	require.NoError(t, err)
	assert.Equal(t, "tok", resp.AccessToken)
	assert.Equal(t, int64(1), calls.Load())
}

func TestCachedFlow_CacheHit(t *testing.T) {
	var calls atomic.Int64
	inner := makeTestFlow("cached", &calls)
	mgr := newInstallationCacheManager()

	wrapped := cachedFlow(inner, mgr, nil)

	resp1, err := wrapped(context.Background(), FlowParams{})
	require.NoError(t, err)
	assert.Equal(t, "cached", resp1.AccessToken)

	resp2, err := wrapped(context.Background(), FlowParams{})
	require.NoError(t, err)
	assert.Equal(t, "cached", resp2.AccessToken)

	assert.Equal(t, int64(1), calls.Load(), "inner should only be called once")
}

func TestCachedFlow_InnerError_NotCached(t *testing.T) {
	var calls atomic.Int64
	failing := func(_ context.Context, _ FlowParams) (*sdkplugin.TokenResponse, error) {
		calls.Add(1)
		return nil, fmt.Errorf("transient failure")
	}
	mgr := newInstallationCacheManager()

	wrapped := cachedFlow(failing, mgr, nil)

	_, err := wrapped(context.Background(), FlowParams{})
	require.Error(t, err)

	_, err = wrapped(context.Background(), FlowParams{})
	require.Error(t, err)

	assert.Equal(t, int64(2), calls.Load(), "errors should not be cached — inner called each time")
}

func TestCachedFlow_Hooks_OnCacheHit(t *testing.T) {
	var calls atomic.Int64
	inner := makeTestFlow("tok", &calls)
	mgr := newInstallationCacheManager()

	var hits atomic.Int64
	hooks := &manager.Hooks{
		OnCacheHit: func(_ string) { hits.Add(1) },
	}

	wrapped := cachedFlow(inner, mgr, hooks)

	_, err := wrapped(context.Background(), FlowParams{})
	require.NoError(t, err)

	_, err = wrapped(context.Background(), FlowParams{})
	require.NoError(t, err)

	assert.Equal(t, int64(1), hits.Load(), "OnCacheHit should fire on second call")
}

func TestCachedFlow_ConcurrentDedup(t *testing.T) {
	var calls atomic.Int64
	slow := func(_ context.Context, _ FlowParams) (*sdkplugin.TokenResponse, error) {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
		return &sdkplugin.TokenResponse{
			AccessToken: "deduped",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	}
	mgr := newInstallationCacheManager()
	wrapped := cachedFlow(slow, mgr, nil)

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make([]error, n)
	resps := make([]*sdkplugin.TokenResponse, n)
	for i := range n {
		go func() {
			defer wg.Done()
			resps[i], errs[i] = wrapped(context.Background(), FlowParams{})
		}()
	}
	wg.Wait()
	for i := range n {
		require.NoError(t, errs[i])
		assert.Equal(t, "deduped", resps[i].AccessToken)
	}

	assert.Equal(t, int64(1), calls.Load(), "concurrent calls should collapse to one inner call")
}
