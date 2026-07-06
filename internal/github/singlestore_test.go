// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/stretchr/testify/assert"
)

func TestSingleStore_GetEmpty(t *testing.T) {
	s := &singleStore{}
	val, ok := s.Get(context.Background(), "any")
	assert.False(t, ok)
	assert.Nil(t, val)
}

func TestSingleStore_SetThenGet(t *testing.T) {
	s := &singleStore{}
	tok := &sdkplugin.TokenResponse{AccessToken: "abc"}
	s.Set(context.Background(), "k", tok, time.Hour)

	val, ok := s.Get(context.Background(), "k")
	assert.True(t, ok)
	assert.Equal(t, "abc", val.AccessToken)
}

func TestSingleStore_WrongKey(t *testing.T) {
	s := &singleStore{}
	tok := &sdkplugin.TokenResponse{AccessToken: "abc"}
	s.Set(context.Background(), "k1", tok, time.Hour)

	val, ok := s.Get(context.Background(), "k2")
	assert.False(t, ok)
	assert.Nil(t, val)
}

func TestSingleStore_Expired(t *testing.T) {
	fakeNow := time.Now()
	s := &singleStore{
		nowFunc: func() time.Time { return fakeNow },
	}
	tok := &sdkplugin.TokenResponse{AccessToken: "abc"}
	s.Set(context.Background(), "k", tok, time.Millisecond)

	// Advance past expiry.
	fakeNow = fakeNow.Add(2 * time.Millisecond)

	val, ok := s.Get(context.Background(), "k")
	assert.False(t, ok)
	assert.Nil(t, val)
}

func TestSingleStore_ZeroTTL_NoExpiry(t *testing.T) {
	s := &singleStore{}
	tok := &sdkplugin.TokenResponse{AccessToken: "forever"}
	s.Set(context.Background(), "k", tok, 0)

	val, ok := s.Get(context.Background(), "k")
	assert.True(t, ok)
	assert.Equal(t, "forever", val.AccessToken)
}

func TestSingleStore_ExpiryBuffer(t *testing.T) {
	fakeNow := time.Now()
	s := &singleStore{
		expiryBuffer: 5 * time.Minute,
		nowFunc:      func() time.Time { return fakeNow },
	}
	ctx := context.Background()
	tok := &sdkplugin.TokenResponse{AccessToken: "buffered"}

	// Set token with 60m TTL. Effective lifetime = 60m - 5m buffer = 55m.
	s.Set(ctx, "k", tok, time.Hour)

	// At T+0: available.
	val, ok := s.Get(ctx, "k")
	assert.True(t, ok)
	assert.Equal(t, "buffered", val.AccessToken)

	// Advance to T+54m (within effective lifetime): still available.
	fakeNow = fakeNow.Add(54 * time.Minute)
	val, ok = s.Get(ctx, "k")
	assert.True(t, ok)
	assert.Equal(t, "buffered", val.AccessToken)

	// Advance to T+56m (past effective 55m lifetime): expired early due to buffer.
	fakeNow = fakeNow.Add(2 * time.Minute) // total T+56m
	val, ok = s.Get(ctx, "k")
	assert.False(t, ok, "entry should be expired early due to buffer")
	assert.Nil(t, val)
}

func TestSingleStore_Overwrite(t *testing.T) {
	s := &singleStore{}
	s.Set(context.Background(), "k", &sdkplugin.TokenResponse{AccessToken: "first"}, time.Hour)
	s.Set(context.Background(), "k", &sdkplugin.TokenResponse{AccessToken: "second"}, time.Hour)

	val, ok := s.Get(context.Background(), "k")
	assert.True(t, ok)
	assert.Equal(t, "second", val.AccessToken)
}

func TestSingleStore_ConcurrentSetGet(t *testing.T) {
	s := &singleStore{}
	ctx := context.Background()
	const n = 100

	var wg sync.WaitGroup
	wg.Add(n * 2)

	// Concurrent writers
	for i := range n {
		go func(i int) {
			defer wg.Done()
			assert.NotPanics(t, func() {
				tok := &sdkplugin.TokenResponse{AccessToken: fmt.Sprintf("tok-%d", i)}
				s.Set(ctx, "k", tok, time.Hour)
			})
		}(i)
	}

	// Concurrent readers
	for range n {
		go func() {
			defer wg.Done()
			assert.NotPanics(t, func() {
				val, ok := s.Get(ctx, "k")
				// Either no value yet or a valid token — never a partial/corrupt state.
				if ok {
					assert.NotEmpty(t, val.AccessToken)
				}
			})
		}()
	}

	wg.Wait()

	// After all writes, a final Get should succeed.
	val, ok := s.Get(ctx, "k")
	assert.True(t, ok)
	assert.NotEmpty(t, val.AccessToken)
}
