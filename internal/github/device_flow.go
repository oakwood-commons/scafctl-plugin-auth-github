// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-logr/logr"
	oauth "github.com/oakwood-commons/oauth-helpers"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// DeviceCodeResponse represents the response from GitHub's device code endpoint.
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type browserPreferenceKeyType struct{}

func withBrowserPreference(ctx context.Context, browser string) context.Context {
	if browser == "" {
		if existing := browserPreferenceFromContext(ctx); existing != "" {
			return ctx
		}
	}
	return context.WithValue(ctx, browserPreferenceKeyType{}, browser)
}

func browserPreferenceFromContext(ctx context.Context) string {
	v, _ := ctx.Value(browserPreferenceKeyType{}).(string)
	return v
}

// defaultBrowserOpener opens a URL in the user's preferred or system browser
// using the oauth-helpers package, logging fallback warnings when a configured
// browser preference or $BROWSER cannot be launched.
func defaultBrowserOpener(ctx context.Context, rawURL string) error {
	return oauth.OpenBrowserWithPreference(
		ctx,
		rawURL,
		browserPreferenceFromContext(ctx),
		oauth.WithWarningHandler(func(msg string) {
			logr.FromContextOrDiscard(ctx).V(0).Info(msg)
		}),
	)
}

// browserOpener returns the configured browser opener or the default.
func (p *Plugin) browserOpener() BrowserOpenFunc {
	p.mu.RLock()
	opener := p.openBrowser
	p.mu.RUnlock()
	if opener != nil {
		return opener
	}
	return defaultBrowserOpener
}

// deviceCodeLogin performs the device code authentication flow.
func (p *Plugin) deviceCodeLogin(ctx context.Context, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting GitHub device code authentication flow")

	if err := validateProfile(auth.ProfileFromContext(ctx)); err != nil {
		return nil, err
	}

	ctx = withHostnameOverride(ctx, req.Hostname)
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)
	ctx = withBrowserPreference(ctx, req.Browser)

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = cfg.DefaultScopes
	}

	timeout := req.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return p.performDeviceCodeFlow(ctx, scopes, false, deviceCodeCb)
}

// interactiveDeviceCodeLogin runs the device code flow but automatically opens
// the browser -- matching 'gh auth login' behaviour.
func (p *Plugin) interactiveDeviceCodeLogin(ctx context.Context, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting GitHub interactive flow (device code with browser auto-open)")

	if err := validateProfile(auth.ProfileFromContext(ctx)); err != nil {
		return nil, err
	}

	ctx = withHostnameOverride(ctx, req.Hostname)
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)
	ctx = withBrowserPreference(ctx, req.Browser)

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = cfg.DefaultScopes
	}
	timeout := req.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return p.performDeviceCodeFlow(ctx, scopes, true, deviceCodeCb)
}

// performDeviceCodeFlow executes the device code authentication flow.
// When openBrowser is true, the browser is opened automatically before notifying
// the callback.
func (p *Plugin) performDeviceCodeFlow(ctx context.Context, scopes []string, openBrowser bool, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	deviceCode, err := p.requestDeviceCode(ctx, scopes)
	if err != nil {
		return nil, fmt.Errorf("github: device_code_request: %w", err)
	}

	lgr.V(1).Info("device code obtained",
		"userCode", deviceCode.UserCode,
		"verificationURI", deviceCode.VerificationURI,
	)

	if openBrowser {
		lgr.V(1).Info("opening browser for device code authentication",
			"url", deviceCode.VerificationURI,
			"browser", browserPreferenceFromContext(ctx),
		)
		if err := p.browserOpener()(ctx, deviceCode.VerificationURI); err != nil {
			lgr.V(0).Info("could not open browser automatically", "url", deviceCode.VerificationURI)
		}
	}

	if deviceCodeCb != nil {
		deviceCodeCb(sdkplugin.DeviceCodePrompt{
			UserCode:        deviceCode.UserCode,
			VerificationURI: deviceCode.VerificationURI,
		})
	}

	tokenResp, err := p.pollForToken(ctx, deviceCode)
	if err != nil {
		return nil, fmt.Errorf("github: token_poll: %w", err)
	}

	claims, err := p.storeCredentials(ctx, tokenResp, scopes, "", auth.FlowDeviceCode)
	if err != nil {
		return nil, fmt.Errorf("github: store_credentials: %w", err)
	}

	lgr.V(1).Info("authentication successful",
		"subject", claims.Subject,
		"name", claims.Name,
	)

	expiresAt := time.Now().Add(8 * time.Hour)
	if tokenResp.RefreshTokenExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(tokenResp.RefreshTokenExpiresIn) * time.Second)
	}

	return &sdkplugin.LoginResponse{
		Claims:    claims,
		ExpiresAt: expiresAt,
	}, nil
}

func validateVerificationURI(rawURI, expectedHostname string) (string, error) {
	trimmed := strings.TrimSpace(rawURI)
	if trimmed == "" || !utf8.ValidString(trimmed) {
		return "", fmt.Errorf("invalid verification_uri in device code response")
	}
	for _, r := range trimmed {
		if r <= 0x20 || r == 0x7f || unicode.IsSpace(r) || unicode.IsControl(r) ||
			r == 0x061c || r == 0x200e || r == 0x200f ||
			(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return "", fmt.Errorf("verification_uri contains disallowed characters")
		}
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.User != nil || parsed.Hostname() == "" {
		return "", fmt.Errorf("verification_uri must be a valid https URL")
	}
	expectedHost := expectedHostname
	if expParsed, pErr := url.Parse("https://" + expectedHostname); pErr == nil && expParsed.Hostname() != "" {
		expectedHost = expParsed.Hostname()
	}
	uriHost := strings.ToLower(parsed.Hostname())
	wantHost := strings.ToLower(expectedHost)
	if uriHost != wantHost && !strings.HasSuffix(uriHost, "."+wantHost) {
		return "", fmt.Errorf("verification_uri host %q does not match configured hostname %q", parsed.Hostname(), expectedHostname)
	}
	return trimmed, nil
}

// requestDeviceCode requests a device code from GitHub.
func (p *Plugin) requestDeviceCode(ctx context.Context, scopes []string) (*DeviceCodeResponse, error) {
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	httpClient, releaseHTTP, err := p.acquireHTTPClient(ctx, cfg, true)
	if err != nil {
		return nil, err
	}
	defer releaseHTTP()

	endpoint := fmt.Sprintf("%s/login/device/code", cfg.GetOAuthBaseURL())

	data := makeFormData(map[string]string{
		"client_id": cfg.ClientID,
		"scope":     strings.Join(scopes, " "),
	})

	resp, err := httpClient.PostForm(ctx, endpoint, data)
	if err != nil {
		return nil, fmt.Errorf("device code request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, fmt.Errorf("device code request failed with status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("device code request failed: %s - %s",
			sanitizeControlChars(errResp.Error), sanitizeControlChars(errResp.ErrorDescription))
	}

	var deviceCode DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceCode); err != nil {
		return nil, fmt.Errorf("failed to parse device code response: %w", err)
	}

	deviceCode.UserCode = sanitizeControlChars(deviceCode.UserCode)
	if deviceCode.DeviceCode == "" || deviceCode.UserCode == "" {
		return nil, fmt.Errorf("device code response missing required fields")
	}
	validURI, err := validateVerificationURI(deviceCode.VerificationURI, cfg.Hostname)
	if err != nil {
		return nil, err
	}
	deviceCode.VerificationURI = validURI

	return &deviceCode, nil
}

// pollForToken polls GitHub's token endpoint until the user completes authentication.
func (p *Plugin) pollForToken(ctx context.Context, deviceCode *DeviceCodeResponse) (*TokenResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	httpClient, releaseHTTP, err := p.acquireHTTPClient(ctx, cfg, true)
	if err != nil {
		return nil, err
	}
	defer releaseHTTP()

	endpoint := fmt.Sprintf("%s/login/oauth/access_token", cfg.GetOAuthBaseURL())

	minPollInterval := cfg.MinPollInterval
	if minPollInterval == 0 {
		minPollInterval = DefaultMinPollInterval
	}

	interval := time.Duration(deviceCode.Interval) * time.Second
	if interval < minPollInterval {
		interval = minPollInterval
	}

	ticker := p.getClock().NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("authentication timed out")
		case <-ticker.C():
			data := makeFormData(map[string]string{
				"client_id":   cfg.ClientID,
				"device_code": deviceCode.DeviceCode,
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
			})

			resp, err := httpClient.PostForm(ctx, endpoint, data)
			if err != nil {
				if ctx.Err() != nil {
					return nil, fmt.Errorf("authentication timed out")
				}
				lgr.V(1).Info("transient network error during token poll, continuing", "error", err)
				continue
			}

			body := struct {
				TokenResponse
				TokenErrorResponse
			}{}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				_ = resp.Body.Close()
				return nil, fmt.Errorf("failed to parse token response: %w", err)
			}
			_ = resp.Body.Close()

			if body.AccessToken != "" {
				return &TokenResponse{
					AccessToken:           body.AccessToken,
					RefreshToken:          body.RefreshToken,
					TokenType:             body.TokenType,
					Scope:                 body.Scope,
					ExpiresIn:             body.ExpiresIn,
					RefreshTokenExpiresIn: body.RefreshTokenExpiresIn,
				}, nil
			}

			switch body.Error {
			case "authorization_pending":
				continue
			case "slow_down":
				slowDownIncr := cfg.SlowDownIncrement
				if slowDownIncr == 0 {
					slowDownIncr = 5 * time.Second
				}
				interval += slowDownIncr
				ticker.Reset(interval)
				lgr.V(1).Info("slow_down received, increasing poll interval", "newInterval", interval)
				continue
			case "expired_token":
				return nil, fmt.Errorf("authentication timed out")
			case "access_denied":
				return nil, fmt.Errorf("user cancelled authentication")
			default:
				return nil, fmt.Errorf("token request failed: %s - %s",
					sanitizeControlChars(body.Error), sanitizeControlChars(body.ErrorDescription))
			}
		}
	}
}
