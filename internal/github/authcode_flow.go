// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-logr/logr"
	oauth "github.com/oakwood-commons/oauth-helpers"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// callbackShutdownTimeout bounds graceful draining of the localhost callback
// HTTP response after a callback result is settled.
const callbackShutdownTimeout = 5 * time.Second

// sanitizeControlChars strips C0, DEL, C1, and Unicode bidi control characters
// from untrusted OAuth error and profile strings before returning them to callers.
func sanitizeControlChars(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, width := utf8.DecodeRuneInString(s[i:])
		i += width
		if r == utf8.RuneError && width == 1 {
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
			r == 0x061c || r == 0x200e || r == 0x200f ||
			(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			if r == '\t' || r == '\n' || r == '\r' {
				b.WriteByte(' ')
			}
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// authCodeLogin performs the OAuth 2.0 authorization code + PKCE flow.
func (p *Plugin) authCodeLogin(ctx context.Context, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting GitHub authorization code + PKCE flow")

	if err := validateProfile(auth.ProfileFromContext(ctx)); err != nil {
		return nil, err
	}

	ctx = withHostnameOverride(ctx, req.Hostname)
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = cfg.DefaultScopes
	}

	timeout := req.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	// Bound the entire flow (callback wait + token exchange + secret storage)
	// by timeout. Register defer cancel() BEFORE defer drainCallbackServer() so
	// LIFO execution settles and drains the callback response before cancelling
	// flowCtx on normal return.
	flowCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Generate PKCE code verifier and challenge
	codeVerifier, err := oauth.GenerateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("github: pkce_generate: generating PKCE code verifier: %w", err)
	}
	codeChallenge := oauth.GenerateCodeChallenge(codeVerifier)

	// Generate random state for CSRF protection
	state, err := oauth.GenerateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("github: state_generate: generating state parameter: %w", err)
	}

	// Start local callback server for OAuth redirect.
	// Honor unprivileged CallbackPort (1024-65535); treat out-of-range values as ephemeral (0).
	callbackPort := req.CallbackPort
	if callbackPort < 1024 || callbackPort > 65535 {
		callbackPort = 0
	}

	callbackOpts := []oauth.CallbackOption{oauth.WithDeferredCompletion()}
	if pages := p.authCallbackPages(); pages != nil {
		callbackOpts = append(callbackOpts, oauth.WithCallbackPages(oauth.CallbackPages{
			SuccessHTML: pages.SuccessHTML,
			FailureHTML: pages.FailureHTML,
		}))
	}

	callbackServer, err := oauth.StartCallbackServer(flowCtx, callbackPort, state, callbackOpts...)
	if err != nil {
		return nil, fmt.Errorf("github: callback_server: starting callback server: %w", err)
	}

	drained := false
	drainCallbackServer := func() {
		if drained {
			return
		}
		drained = true
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), callbackShutdownTimeout)
		defer shutdownCancel()
		_ = callbackServer.Shutdown(shutdownCtx)
	}
	defer drainCallbackServer()

	redirectURI := callbackServer.RedirectURI

	// Build authorization URL
	scopeStr := strings.Join(scopes, " ")
	params := url.Values{}
	params.Set("client_id", cfg.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", scopeStr)
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")

	authURL := fmt.Sprintf("%s/login/oauth/authorize?%s", cfg.GetOAuthBaseURL(), params.Encode())

	// Open browser, forwarding any caller-requested browser preference.
	lgr.V(1).Info("opening browser for authentication", "url", authURL, "browser", req.Browser)
	browserOpenErr := p.browserOpener()(withBrowserPreference(flowCtx, req.Browser), authURL)
	if browserOpenErr != nil {
		lgr.V(0).Info("failed to open browser, please open this URL manually", "url", authURL)
	}

	// Notify callback so the CLI can show a "Re-open in browser" action
	if deviceCodeCb != nil {
		deviceCodeCb(sdkplugin.DeviceCodePrompt{
			VerificationURI: authURL,
			Message:         "Open this URL in your browser to authenticate",
		})
	}

	var authCode string
	select {
	case result := <-callbackServer.ResultChan():
		if result.Err != nil {
			drainCallbackServer()
			return nil, fmt.Errorf("github: auth_code: %s", sanitizeControlChars(result.Err.Error()))
		}
		authCode = result.Code
		lgr.V(1).Info("received authorization code")
	case <-flowCtx.Done():
		if ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("github: auth_code: authentication cancelled")
		}
		return nil, fmt.Errorf("github: auth_code: no response received from browser within %s; "+
			"if running over SSH or in a headless environment, use '--flow device-code' instead", timeout)
	}

	settleCallback := func(success bool) {
		callbackServer.Complete(success)
		drainCallbackServer()
	}

	// Exchange authorization code for tokens
	tokenResp, err := p.exchangeAuthCode(flowCtx, authCode, redirectURI, codeVerifier)
	if err != nil {
		settleCallback(false)
		return nil, fmt.Errorf("github: token_exchange: %w", err)
	}

	claims, err := p.storeCredentials(flowCtx, tokenResp, scopes, "", auth.FlowInteractive)
	if err != nil {
		settleCallback(false)
		return nil, fmt.Errorf("github: store_credentials: %w", err)
	}

	settleCallback(true)

	lgr.V(1).Info("authorization code flow completed successfully",
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

// exchangeAuthCode exchanges an authorization code for tokens.
func (p *Plugin) exchangeAuthCode(ctx context.Context, code, redirectURI, codeVerifier string) (*TokenResponse, error) {
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

	params := map[string]string{
		"client_id":     cfg.ClientID,
		"code":          code,
		"redirect_uri":  redirectURI,
		"code_verifier": codeVerifier,
	}
	if cfg.ClientSecret != "" {
		params["client_secret"] = cfg.ClientSecret
	}

	data := makeFormData(params)

	resp, err := httpClient.PostForm(ctx, endpoint, data)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body := struct {
		TokenResponse
		TokenErrorResponse
	}{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("token exchange failed with status %d: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if body.AccessToken == "" {
		if body.Error != "" {
			return nil, fmt.Errorf("token exchange failed: %s - %s",
				sanitizeControlChars(body.Error), sanitizeControlChars(body.ErrorDescription))
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("token exchange failed with status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("token exchange returned empty access token")
	}

	return &TokenResponse{
		AccessToken:           body.AccessToken,
		RefreshToken:          body.RefreshToken,
		TokenType:             body.TokenType,
		Scope:                 body.Scope,
		ExpiresIn:             body.ExpiresIn,
		RefreshTokenExpiresIn: body.RefreshTokenExpiresIn,
	}, nil
}
