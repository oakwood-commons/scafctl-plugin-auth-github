// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
	oauth "github.com/oakwood-commons/oauth-helpers"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
)

// authCodeLogin performs the OAuth 2.0 authorization code + PKCE flow.
func (p *Plugin) authCodeLogin(ctx context.Context, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting GitHub authorization code + PKCE flow")

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = p.config.DefaultScopes
	}

	timeout := req.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

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

	// Start local callback server for OAuth redirect
	// LoginRequest doesn't have CallbackPort, use 0 for ephemeral
	callbackServer, err := oauth.StartCallbackServer(ctx, 0, state)
	if err != nil {
		return nil, fmt.Errorf("github: callback_server: starting callback server: %w", err)
	}
	defer func() { _ = callbackServer.Close() }()

	redirectURI := callbackServer.RedirectURI

	// Build authorization URL
	scopeStr := strings.Join(scopes, " ")
	params := url.Values{}
	params.Set("client_id", p.config.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", scopeStr)
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")

	authURL := fmt.Sprintf("%s/login/oauth/authorize?%s", p.config.GetOAuthBaseURL(), params.Encode())

	// Open browser
	lgr.V(1).Info("opening browser for authentication", "url", authURL)
	browserOpenErr := p.browserOpener()(ctx, authURL)
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

	// Wait for authorization code or timeout
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	var authCode string
	select {
	case result := <-callbackServer.ResultChan():
		if result.Err != nil {
			return nil, fmt.Errorf("github: auth_code: %w", result.Err)
		}
		authCode = result.Code
		lgr.V(1).Info("received authorization code")
	case <-timer.C:
		return nil, fmt.Errorf("github: auth_code: no response received from browser within %s; "+
			"if running over SSH or in a headless environment, use '--flow device-code' instead", timeout)
	case <-ctx.Done():
		return nil, fmt.Errorf("github: auth_code: authentication cancelled")
	}

	// Exchange authorization code for tokens
	tokenResp, err := p.exchangeAuthCode(ctx, authCode, redirectURI, codeVerifier)
	if err != nil {
		return nil, fmt.Errorf("github: token_exchange: %w", err)
	}

	claims, err := p.storeCredentials(ctx, tokenResp, scopes, "", auth.FlowInteractive)
	if err != nil {
		return nil, fmt.Errorf("github: store_credentials: %w", err)
	}

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
	endpoint := fmt.Sprintf("%s/login/oauth/access_token", p.config.GetOAuthBaseURL())

	params := map[string]string{
		"client_id":     p.config.ClientID,
		"code":          code,
		"redirect_uri":  redirectURI,
		"code_verifier": codeVerifier,
	}
	if p.config.ClientSecret != "" {
		params["client_secret"] = p.config.ClientSecret
	}

	data := makeFormData(params)

	resp, err := p.httpClient.PostForm(ctx, endpoint, data)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body := struct {
		TokenResponse
		TokenErrorResponse
	}{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if body.AccessToken == "" {
		if body.Error != "" {
			return nil, fmt.Errorf("token exchange failed: %s - %s", body.Error, body.ErrorDescription)
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
