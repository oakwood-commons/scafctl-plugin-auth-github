// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"encoding/json"
	"testing"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

func BenchmarkEffectiveConfig(b *testing.B) {
	p := &Plugin{}
	_ = p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
		BinaryName: "scafctl",
		Settings: map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{"clientId":"bench-cid","hostname":"github.example.com","defaultScopes":["repo"]}`),
		},
	})
	b.Cleanup(func() { _ = p.StopAuthHandler(context.Background(), HandlerName) })

	ctx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
		HandlerName: json.RawMessage(`{"clientId":"rpc-cid","hostname":"ghes.example.com","defaultScopes":["read:org"]}`),
	})

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		cfg, err := p.effectiveConfig(ctx)
		if err != nil || cfg == nil {
			b.Fatalf("effectiveConfig failed: %v", err)
		}
	}
}

func BenchmarkHTTPClientForConfig(b *testing.B) {
	p := &Plugin{}
	_ = p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
		BinaryName: "scafctl",
	})
	b.Cleanup(func() { _ = p.StopAuthHandler(context.Background(), HandlerName) })

	cfg, err := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"10s","retryMax":2}}`))
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	_, _ = p.httpClientForConfig(ctx, cfg)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		hc, cErr := p.httpClientForConfig(ctx, cfg)
		if cErr != nil || hc == nil {
			b.Fatalf("httpClientForConfig failed: %v", cErr)
		}
	}
}

func BenchmarkSanitizeControlChars(b *testing.B) {
	clean := "The Octocat (octocat@example.com)"
	dirty := "bad\x1b[31m-token\x07-value\u202e"

	b.Run("clean", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = sanitizeControlChars(clean)
		}
	})

	b.Run("dirty", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = sanitizeControlChars(dirty)
		}
	})
}
