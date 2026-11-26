// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"bytes"
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/httpc"
)

var (
	errClientCacheClosed = errors.New("HTTP client cache closed")
	errHTTPClientClosed  = errors.New("HTTP client closed")
)

// HTTPClient abstracts HTTP calls for testability.
type HTTPClient interface {
	// PostForm sends a POST request with form-encoded body and returns the response.
	PostForm(ctx context.Context, url string, data url.Values) (*http.Response, error)

	// PostJSON sends a POST request with JSON body and custom headers.
	PostJSON(ctx context.Context, url string, body any, headers map[string]string) (*http.Response, error)

	// Get sends a GET request with the given headers and returns the response.
	Get(ctx context.Context, url string, headers map[string]string) (*http.Response, error)
}

func boolPtr(b bool) *bool { return &b }

// mergeHTTPClientDefaults returns the plugin's HTTP defaults as an
// httpc.AppConfig with any host-forwarded overrides applied on top.
// HTTP response caching is always forced off in resolveEffectiveHTTPConfig so
// Authorization-bearing API responses (/user, /app) are never shared across
// tokens or accounts.
func mergeHTTPClientDefaults(cfg *httpc.AppConfig) *httpc.AppConfig {
	base := &httpc.AppConfig{
		Timeout:           defaultHTTPTimeout.String(),
		RetryMax:          defaultHTTPRetryMax,
		RetryWaitMin:      defaultHTTPRetryWaitFloor.String(),
		RetryWaitMax:      defaultHTTPRetryWaitMax.String(),
		EnableCache:       boolPtr(false),
		EnableCompression: boolPtr(false),
	}
	return httpc.MergeAppConfig(base, cfg)
}

// effectiveHTTPConfigKey is a comparable canonical representation of a merged
// httpc.ClientConfig so semantically equivalent per-RPC httpClient settings
// share a single cached client (preserving connection pools and circuit-breaker
// state across RPCs).
type effectiveHTTPConfigKey struct {
	timeout                           time.Duration
	retryMax                          int
	retryWaitMin                      time.Duration
	retryWaitMax                      time.Duration
	enableCircuitBreaker              bool
	circuitBreakerMaxFailures         int
	circuitBreakerOpenTimeout         time.Duration
	circuitBreakerHalfOpenMaxRequests int
	enableCompression                 bool
	allowPrivateIPs                   bool
	allowedPrivateCIDRs               string
	trustProxyResolution              bool
	maxResponseBodySize               int64
}

func effectiveHTTPConfigKeyFromClientConfig(cfg *httpc.ClientConfig) effectiveHTTPConfigKey {
	k := effectiveHTTPConfigKey{
		timeout:              cfg.Timeout,
		retryMax:             cfg.RetryMax,
		retryWaitMin:         cfg.RetryWaitMin,
		retryWaitMax:         cfg.RetryWaitMax,
		enableCircuitBreaker: cfg.EnableCircuitBreaker,
		enableCompression:    cfg.EnableCompression,
		maxResponseBodySize:  cfg.MaxResponseBodySize,
	}
	if cfg.IPPolicy != nil {
		k.allowPrivateIPs = cfg.IPPolicy.AllowPrivate
		if len(cfg.IPPolicy.AllowedCIDRs) > 0 {
			cidrs := make([]string, 0, len(cfg.IPPolicy.AllowedCIDRs))
			for _, n := range cfg.IPPolicy.AllowedCIDRs {
				if n != nil {
					cidrs = append(cidrs, n.String())
				}
			}
			k.allowedPrivateCIDRs = strings.Join(cidrs, ",")
		}
		k.trustProxyResolution = cfg.IPPolicy.TrustProxyResolution
	}
	if cfg.EnableCircuitBreaker && cfg.CircuitBreakerConfig != nil {
		k.circuitBreakerMaxFailures = cfg.CircuitBreakerConfig.MaxFailures
		k.circuitBreakerOpenTimeout = cfg.CircuitBreakerConfig.OpenTimeout
		k.circuitBreakerHalfOpenMaxRequests = cfg.CircuitBreakerConfig.HalfOpenMaxRequests
	}
	return k
}

// resolveEffectiveHTTPConfig merges plugin defaults with cfg, validates all
// duration and enum fields using the same rules as httpc.NewClientFromAppConfig,
// forces EnableCache = false for auth security, and returns both the canonical
// cache key and the resolved ClientConfig.
func resolveEffectiveHTTPConfig(cfg *httpc.AppConfig) (effectiveHTTPConfigKey, *httpc.ClientConfig, error) {
	merged := mergeHTTPClientDefaults(cfg)
	clientCfg := httpc.DefaultConfig()

	if merged.Timeout != "" {
		d, err := time.ParseDuration(merged.Timeout)
		if err != nil {
			return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid timeout duration %q: %w", merged.Timeout, err)
		}
		clientCfg.Timeout = d
	}
	if merged.RetryMax > 0 {
		clientCfg.RetryMax = merged.RetryMax
	}
	if merged.RetryWaitMin != "" {
		d, err := time.ParseDuration(merged.RetryWaitMin)
		if err != nil {
			return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid retryWaitMin duration %q: %w", merged.RetryWaitMin, err)
		}
		clientCfg.RetryWaitMin = d
	}
	if merged.RetryWaitMax != "" {
		d, err := time.ParseDuration(merged.RetryWaitMax)
		if err != nil {
			return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid retryWaitMax duration %q: %w", merged.RetryWaitMax, err)
		}
		clientCfg.RetryWaitMax = d
	}
	if merged.CacheType != "" {
		ct := httpc.CacheType(merged.CacheType)
		if ct != httpc.CacheTypeMemory && ct != httpc.CacheTypeFilesystem {
			return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid cacheType %q: must be %q or %q", merged.CacheType, httpc.CacheTypeMemory, httpc.CacheTypeFilesystem)
		}
		clientCfg.CacheType = ct
	}
	if merged.CacheTTL != "" {
		d, err := time.ParseDuration(merged.CacheTTL)
		if err != nil {
			return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid cacheTTL duration %q: %w", merged.CacheTTL, err)
		}
		clientCfg.CacheTTL = d
	}
	// Never enable HTTP response caching on auth handler clients: httpc's
	// transport cache keys GET responses by URL without Authorization headers.
	clientCfg.EnableCache = false

	if merged.EnableCircuitBreaker != nil {
		clientCfg.EnableCircuitBreaker = *merged.EnableCircuitBreaker
	}
	if merged.CircuitBreakerMaxFailures > 0 || merged.CircuitBreakerOpenTimeout != "" || merged.CircuitBreakerHalfOpenMaxRequests > 0 {
		clientCfg.CircuitBreakerConfig = httpc.DefaultCircuitBreakerConfig()
		if merged.CircuitBreakerMaxFailures > 0 {
			clientCfg.CircuitBreakerConfig.MaxFailures = merged.CircuitBreakerMaxFailures
		}
		if merged.CircuitBreakerOpenTimeout != "" {
			d, err := time.ParseDuration(merged.CircuitBreakerOpenTimeout)
			if err != nil {
				return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid circuitBreakerOpenTimeout duration %q: %w", merged.CircuitBreakerOpenTimeout, err)
			}
			clientCfg.CircuitBreakerConfig.OpenTimeout = d
		}
		if merged.CircuitBreakerHalfOpenMaxRequests > 0 {
			clientCfg.CircuitBreakerConfig.HalfOpenMaxRequests = merged.CircuitBreakerHalfOpenMaxRequests
		}
	}
	if merged.EnableCompression != nil {
		clientCfg.EnableCompression = *merged.EnableCompression
	}
	var policy *httpc.IPPolicy
	if merged.AllowPrivateIPs != nil && *merged.AllowPrivateIPs { //nolint:staticcheck // support deprecated AppConfig.AllowPrivateIPs alongside AllowedPrivateCIDRs
		policy = httpc.AllowAllPrivateIPs()
	}
	if merged.AllowedPrivateCIDRs != nil {
		p, err := httpc.NewIPPolicy(merged.AllowedPrivateCIDRs...)
		if err != nil {
			return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid allowedPrivateCIDRs: %w", err)
		}
		policy = p
	}
	if merged.TrustProxyResolution != nil {
		if policy == nil {
			policy = &httpc.IPPolicy{}
		}
		policy.TrustProxyResolution = *merged.TrustProxyResolution
	}
	clientCfg.IPPolicy = policy
	if merged.MaxResponseBodySize > 0 {
		clientCfg.MaxResponseBodySize = merged.MaxResponseBodySize
	}

	return effectiveHTTPConfigKeyFromClientConfig(clientCfg), clientCfg, nil
}

func newIsolatedTransport() *http.Transport {
	if dt, ok := http.DefaultTransport.(*http.Transport); ok && dt != nil {
		return dt.Clone()
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func cloneResolvedClientConfig(baseCfg *httpc.ClientConfig, logger logr.Logger, tr *http.Transport) *httpc.ClientConfig {
	cfgCopy := *baseCfg
	if baseCfg.CircuitBreakerConfig != nil {
		cbCopy := *baseCfg.CircuitBreakerConfig
		cfgCopy.CircuitBreakerConfig = &cbCopy
	}
	if baseCfg.IPPolicy != nil {
		policyCopy := *baseCfg.IPPolicy
		if baseCfg.IPPolicy.AllowedCIDRs != nil {
			policyCopy.AllowedCIDRs = append([]*net.IPNet(nil), baseCfg.IPPolicy.AllowedCIDRs...)
		}
		cfgCopy.IPPolicy = &policyCopy
	}
	cfgCopy.Logger = logger
	cfgCopy.Transport = tr
	return &cfgCopy
}

// boundedClientCache is a concurrency-safe, size-bounded LRU cache of closable
// HTTP clients. Evicted entries with active leases are moved to a retired set
// and closed once their last lease is released (or when CloseAll runs).
type boundedClientCache[K comparable, V io.Closer] struct {
	mu       sync.Mutex
	capacity int
	closed   bool
	store    map[K]*list.Element
	order    *list.List
	retired  map[*clientCacheEntry[K, V]]struct{}
}

type clientCacheEntry[K comparable, V io.Closer] struct {
	key     K
	value   V
	refs    int
	evicted bool
}

type cacheHookable interface {
	setCacheLeaseHooks(acquire, release func())
}

func newBoundedClientCache[K comparable, V io.Closer](capacity int) *boundedClientCache[K, V] {
	if capacity <= 0 {
		capacity = defaultHTTPClientCacheSize
	}
	return &boundedClientCache[K, V]{
		capacity: capacity,
		store:    make(map[K]*list.Element, capacity),
		order:    list.New(),
		retired:  make(map[*clientCacheEntry[K, V]]struct{}),
	}
}

func (c *boundedClientCache[K, V]) releaseEntry(entry *clientCacheEntry[K, V]) {
	var toClose V
	var shouldClose bool

	c.mu.Lock()
	if entry.refs > 0 {
		entry.refs--
	}
	if entry.refs == 0 && (entry.evicted || c.closed) {
		delete(c.retired, entry)
		toClose = entry.value
		shouldClose = true
	}
	c.mu.Unlock()

	if shouldClose {
		_ = toClose.Close()
	}
}

func (c *boundedClientCache[K, V]) acquireEntry(entry *clientCacheEntry[K, V]) {
	c.mu.Lock()
	entry.refs++
	if entry.evicted && !c.closed {
		c.retired[entry] = struct{}{}
	}
	c.mu.Unlock()
}

func (c *boundedClientCache[K, V]) getOrCreateEntry(key K, build func() V, holdLease bool) (V, func(), error) {
	noopRelease := func() {}
	makeRelease := func(entry *clientCacheEntry[K, V]) func() {
		if !holdLease {
			return noopRelease
		}
		var once sync.Once
		return func() {
			once.Do(func() {
				c.releaseEntry(entry)
			})
		}
	}

	c.mu.Lock()
	if c.closed {
		var zero V
		c.mu.Unlock()
		return zero, noopRelease, errClientCacheClosed
	}
	if elem, ok := c.store[key]; ok {
		c.order.MoveToFront(elem)
		entry := elem.Value.(*clientCacheEntry[K, V])
		if holdLease {
			entry.refs++
		}
		val := entry.value
		c.mu.Unlock()
		return val, makeRelease(entry), nil
	}
	c.mu.Unlock()

	candidate := build()

	c.mu.Lock()
	if c.closed {
		var zero V
		c.mu.Unlock()
		_ = candidate.Close()
		return zero, noopRelease, errClientCacheClosed
	}
	if elem, ok := c.store[key]; ok {
		c.order.MoveToFront(elem)
		entry := elem.Value.(*clientCacheEntry[K, V])
		if holdLease {
			entry.refs++
		}
		winner := entry.value
		c.mu.Unlock()
		_ = candidate.Close()
		return winner, makeRelease(entry), nil
	}

	newEntry := &clientCacheEntry[K, V]{key: key, value: candidate}
	if holdLease {
		newEntry.refs = 1
	}
	if hookable, ok := any(candidate).(cacheHookable); ok {
		hookable.setCacheLeaseHooks(
			func() { c.acquireEntry(newEntry) },
			func() { c.releaseEntry(newEntry) },
		)
	}
	elem := c.order.PushFront(newEntry)
	c.store[key] = elem

	var evicted V
	var shouldCloseEvicted bool
	if c.order.Len() > c.capacity {
		if oldest := c.order.Back(); oldest != nil {
			oldEntry := oldest.Value.(*clientCacheEntry[K, V])
			delete(c.store, oldEntry.key)
			c.order.Remove(oldest)
			oldEntry.evicted = true
			if oldEntry.refs > 0 {
				c.retired[oldEntry] = struct{}{}
			} else {
				evicted = oldEntry.value
				shouldCloseEvicted = true
			}
		}
	}
	c.mu.Unlock()

	if shouldCloseEvicted {
		_ = evicted.Close()
	}
	return candidate, makeRelease(newEntry), nil
}

func (c *boundedClientCache[K, V]) GetOrCreate(key K, build func() V) (V, error) {
	val, _, err := c.getOrCreateEntry(key, build, false)
	return val, err
}

func (c *boundedClientCache[K, V]) Acquire(key K, build func() V) (V, func(), error) {
	return c.getOrCreateEntry(key, build, true)
}

func (c *boundedClientCache[K, V]) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

func (c *boundedClientCache[K, V]) CloseAll() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	toClose := make([]V, 0, c.order.Len()+len(c.retired))
	for elem := c.order.Front(); elem != nil; elem = elem.Next() {
		entry := elem.Value.(*clientCacheEntry[K, V])
		entry.evicted = true
		toClose = append(toClose, entry.value)
	}
	for entry := range c.retired {
		toClose = append(toClose, entry.value)
	}
	c.store = make(map[K]*list.Element, c.capacity)
	c.order.Init()
	clear(c.retired)
	c.mu.Unlock()

	for _, client := range toClose {
		_ = client.Close()
	}
}

// DefaultHTTPClient is the standard HTTP client implementation.
type DefaultHTTPClient struct {
	client    *httpc.Client
	transport *http.Transport
	hookMu    sync.Mutex
	active    int
	closed    bool
	onAcquire func()
	onRelease func()
}

func (c *DefaultHTTPClient) setCacheLeaseHooks(acquire, release func()) {
	c.hookMu.Lock()
	c.onAcquire = acquire
	c.onRelease = release
	c.hookMu.Unlock()
}

func (c *DefaultHTTPClient) closeUnderlying() error {
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

func (c *DefaultHTTPClient) acquireLease() (func(), error) {
	if c == nil {
		return nil, errHTTPClientClosed
	}
	c.hookMu.Lock()
	if c.closed {
		c.hookMu.Unlock()
		return nil, errHTTPClientClosed
	}
	c.active++
	c.hookMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			c.hookMu.Lock()
			if c.active > 0 {
				c.active--
			}
			shouldClose := c.closed && c.active == 0
			c.hookMu.Unlock()
			if shouldClose {
				_ = c.closeUnderlying()
			}
		})
	}, nil
}

func (c *DefaultHTTPClient) enterRequest() (func(), error) {
	if c == nil {
		return nil, errHTTPClientClosed
	}
	c.hookMu.Lock()
	if c.closed {
		c.hookMu.Unlock()
		return nil, errHTTPClientClosed
	}
	c.active++
	acq := c.onAcquire
	rel := c.onRelease
	c.hookMu.Unlock()

	if acq != nil {
		acq()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			if rel != nil {
				rel()
			}
			c.hookMu.Lock()
			if c.active > 0 {
				c.active--
			}
			shouldClose := c.closed && c.active == 0
			c.hookMu.Unlock()
			if shouldClose {
				_ = c.closeUnderlying()
			}
		})
	}, nil
}

type releaseBody struct {
	io.ReadCloser
	done func()
}

func (b *releaseBody) Close() error {
	err := b.ReadCloser.Close()
	b.done()
	return err
}

func (c *DefaultHTTPClient) doAdmitted(req *http.Request, done func()) (*http.Response, error) {
	resp, err := c.client.Do(req)
	if err != nil || resp == nil || resp.Body == nil || resp.Body == http.NoBody {
		done()
		return resp, err
	}
	resp.Body = &releaseBody{
		ReadCloser: resp.Body,
		done:       done,
	}
	return resp, nil
}

func newDefaultHTTPClientFromResolved(baseCfg *httpc.ClientConfig, logger logr.Logger) *DefaultHTTPClient {
	tr := newIsolatedTransport()
	return &DefaultHTTPClient{
		client:    httpc.NewClient(cloneResolvedClientConfig(baseCfg, logger, tr)),
		transport: tr,
	}
}

// NewDefaultHTTPClient creates a new DefaultHTTPClient backed by httpc using
// the plugin's default HTTP configuration (with caching and compression disabled).
func NewDefaultHTTPClient(logger logr.Logger) *DefaultHTTPClient {
	_, clientCfg, _ := resolveEffectiveHTTPConfig(nil)
	return newDefaultHTTPClientFromResolved(clientCfg, logger)
}

// NewDefaultHTTPClientFromAppConfig creates a DefaultHTTPClient with optional
// host-forwarded httpClient settings overlaid on the plugin's defaults.
func NewDefaultHTTPClientFromAppConfig(cfg *httpc.AppConfig, logger logr.Logger) (*DefaultHTTPClient, error) {
	_, clientCfg, err := resolveEffectiveHTTPConfig(cfg)
	if err != nil {
		return nil, err
	}
	return newDefaultHTTPClientFromResolved(clientCfg, logger), nil
}

// Close releases idle HTTP connections and any underlying cache resources,
// and marks the client closed so subsequent requests fail closed instead of
// reopening connections on a retired transport.
func (c *DefaultHTTPClient) Close() error {
	if c == nil {
		return nil
	}
	c.hookMu.Lock()
	c.closed = true
	c.hookMu.Unlock()
	return c.closeUnderlying()
}

// PostForm sends a POST request with form-encoded body.
func (c *DefaultHTTPClient) PostForm(ctx context.Context, reqURL string, data url.Values) (*http.Response, error) {
	done, err := c.enterRequest()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(data.Encode()))
	if err != nil {
		done()
		return nil, fmt.Errorf("creating POST request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.doAdmitted(req, done)
}

// Get sends a GET request with custom headers.
func (c *DefaultHTTPClient) Get(ctx context.Context, reqURL string, headers map[string]string) (*http.Response, error) {
	done, err := c.enterRequest()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		done()
		return nil, fmt.Errorf("creating GET request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.doAdmitted(req, done)
}

// PostJSON sends a POST request with a JSON body and custom headers.
func (c *DefaultHTTPClient) PostJSON(ctx context.Context, reqURL string, body any, headers map[string]string) (*http.Response, error) {
	done, err := c.enterRequest()
	if err != nil {
		return nil, err
	}
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			done()
			return nil, fmt.Errorf("marshaling JSON body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bodyReader)
	if err != nil {
		done()
		return nil, fmt.Errorf("creating POST request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.doAdmitted(req, done)
}
