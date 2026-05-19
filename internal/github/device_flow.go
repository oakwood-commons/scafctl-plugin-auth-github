// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
	oauth "github.com/oakwood-commons/oauth-helpers"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
)

// DeviceCodeResponse represents the response from GitHub's device code endpoint.
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// defaultBrowserOpener opens a URL in the system browser using the oauth-helpers package.
func defaultBrowserOpener(ctx context.Context, url string) error {
	return oauth.OpenBrowser(ctx, url)
}

// browserOpener returns the configured browser opener or the default.
func (p *Plugin) browserOpener() BrowserOpenFunc {
	if p.openBrowser != nil {
		return p.openBrowser
	}
	return defaultBrowserOpener
}

// deviceCodeLogin performs the device code authentication flow.
func (p *Plugin) deviceCodeLogin(ctx context.Context, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting GitHub device code authentication flow")

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = p.config.DefaultScopes
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

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = p.config.DefaultScopes
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

// requestDeviceCode requests a device code from GitHub.
func (p *Plugin) requestDeviceCode(ctx context.Context, scopes []string) (*DeviceCodeResponse, error) {
	endpoint := fmt.Sprintf("%s/login/device/code", p.config.GetOAuthBaseURL())

	data := makeFormData(map[string]string{
		"client_id": p.config.ClientID,
		"scope":     strings.Join(scopes, " "),
	})

	resp, err := p.httpClient.PostForm(ctx, endpoint, data)
	if err != nil {
		return nil, fmt.Errorf("device code request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, fmt.Errorf("device code request failed with status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("device code request failed: %s - %s", errResp.Error, errResp.ErrorDescription)
	}

	var deviceCode DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceCode); err != nil {
		return nil, fmt.Errorf("failed to parse device code response: %w", err)
	}

	return &deviceCode, nil
}

// pollForToken polls GitHub's token endpoint until the user completes authentication.
func (p *Plugin) pollForToken(ctx context.Context, deviceCode *DeviceCodeResponse) (*TokenResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	endpoint := fmt.Sprintf("%s/login/oauth/access_token", p.config.GetOAuthBaseURL())

	minPollInterval := p.config.MinPollInterval
	if minPollInterval == 0 {
		minPollInterval = DefaultMinPollInterval
	}

	interval := time.Duration(deviceCode.Interval) * time.Second
	if interval < minPollInterval {
		interval = minPollInterval
	}

	ticker := p.clock.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("authentication timed out")
		case <-ticker.C():
			data := makeFormData(map[string]string{
				"client_id":   p.config.ClientID,
				"device_code": deviceCode.DeviceCode,
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
			})

			resp, err := p.httpClient.PostForm(ctx, endpoint, data)
			if err != nil {
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
				slowDownIncr := p.config.SlowDownIncrement
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
				return nil, fmt.Errorf("token request failed: %s - %s", body.Error, body.ErrorDescription)
			}
		}
	}
}
