// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	manager "github.com/oakwood-commons/go-flight/cache"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// unimplementedServerMode provides default "not supported" responses for
// operations that are invalid in server mode. Embed this in concrete server
// mode implementations to inherit safe defaults for CLI-only methods.
type unimplementedServerMode struct{}

func (unimplementedServerMode) Login(context.Context, sdkplugin.LoginRequest, func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	return nil, fmt.Errorf("login is not supported in server mode")
}

func (unimplementedServerMode) Logout(context.Context) error {
	return fmt.Errorf("logout is not supported in server mode")
}

func (unimplementedServerMode) GetStatus(context.Context) (*auth.Status, error) {
	return nil, fmt.Errorf("get status is not supported in server mode")
}

func (unimplementedServerMode) ListCachedTokens(context.Context) ([]*auth.CachedTokenInfo, error) {
	return nil, fmt.Errorf("list cached tokens is not supported in server mode")
}

func (unimplementedServerMode) PurgeExpiredTokens(context.Context) (int, error) {
	return 0, fmt.Errorf("purge expired tokens is not supported in server mode")
}

func (unimplementedServerMode) DetectAvailableFlows(context.Context) ([]sdkplugin.FlowAvailability, error) {
	return nil, fmt.Errorf("detect available flows is not supported in server mode")
}

// FlowFn is a function that executes a token flow given params.
type FlowFn func(ctx context.Context, params FlowParams) (*sdkplugin.TokenResponse, error)

// FlowParams contains the inputs for a server-mode token flow.
type FlowParams struct {
	Scope string // optional scope/permissions hint
}

// patFlow returns a FlowFn that returns a pre-resolved PAT.
func patFlow(token string) FlowFn {
	return func(ctx context.Context, _ FlowParams) (*sdkplugin.TokenResponse, error) {
		lgr := logr.FromContextOrDiscard(ctx)
		lgr.V(1).Info("returning PAT token")

		return &sdkplugin.TokenResponse{
			AccessToken: token,
			TokenType:   "Bearer",
			ExpiresAt:   farFuture(),
			Flow:        auth.FlowPAT,
		}, nil
	}
}

// createServerAppJWT creates a JWT for a GitHub App using an explicit issuer string.
// This supports both the numeric App ID and the newer Client ID as the issuer.
func createServerAppJWT(issuer string, privateKey *rsa.PrivateKey) (string, error) {
	now := time.Now()

	claims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
		Issuer:    issuer,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	return signedToken, nil
}

// serverInstallationFlow returns a FlowFn that mints a GitHub App installation token
// using the standalone AppCredentialConfig with SecretRef for the private key.
func serverInstallationFlow(app *AppCredentialConfig, apiBaseURL string, httpClient HTTPClient) FlowFn {
	return func(ctx context.Context, _ FlowParams) (*sdkplugin.TokenResponse, error) {
		lgr := logr.FromContextOrDiscard(ctx)

		// Determine issuer: prefer AppClientID over numeric AppID.
		issuer := app.ClientID
		if issuer == "" {
			issuer = fmt.Sprintf("%d", app.AppID)
		}

		keyPEM, err := app.PrivateKey.Resolve()
		if err != nil {
			return nil, fmt.Errorf("resolving private key: %w", err)
		}

		privateKey, err := parseRSAPrivateKey([]byte(keyPEM))
		if err != nil {
			return nil, fmt.Errorf("parsing private key: %w", err)
		}

		appJWT, err := createServerAppJWT(issuer, privateKey)
		if err != nil {
			return nil, fmt.Errorf("creating app JWT: %w", err)
		}

		installToken, err := createInstallationTokenHTTP(ctx, httpClient, apiBaseURL, appJWT, app.InstallationID)
		if err != nil {
			return nil, fmt.Errorf("creating installation token: %w", err)
		}

		lgr.V(1).Info("installation token acquired",
			"issuer", issuer,
			"installationId", app.InstallationID,
			"expiresAt", installToken.ExpiresAt,
		)

		return &sdkplugin.TokenResponse{
			AccessToken: installToken.Token,
			TokenType:   "Bearer",
			ExpiresAt:   installToken.ExpiresAt,
			Flow:        auth.FlowGitHubApp,
		}, nil
	}
}

// githubServerMode implements mode for server-mode token acquisition.
// It embeds unimplementedServerMode to reject CLI-only operations.
type githubServerMode struct {
	unimplementedServerMode
	strategies   map[auth.ServerContext]FlowFn
	cacheManager *manager.Manager[string, *sdkplugin.TokenResponse]
}

// Compile-time check that githubServerMode satisfies the mode interface.
var _ mode = (*githubServerMode)(nil)

func (s *githubServerMode) GetToken(ctx context.Context, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("GetToken called", "serverContext", req.ServerContext, "scope", req.Scope)

	flow, ok := s.strategies[auth.ServerContext(req.ServerContext)]
	if !ok {
		return nil, fmt.Errorf("no strategy configured for context %q", req.ServerContext)
	}

	resp, err := flow(ctx, FlowParams{Scope: req.Scope})
	if err != nil {
		lgr.V(1).Info("GetToken failed", "serverContext", req.ServerContext, "error", err)
		return nil, err
	}

	lgr.V(1).Info("GetToken succeeded", "serverContext", req.ServerContext, "flow", resp.Flow, "expiresAt", resp.ExpiresAt)
	return resp, nil
}

// ActivateServerMode validates configuration and initializes server-mode token strategies.
// It receives settings from the host via the ActivateServerModeRequest RPC.
func (p *Plugin) ActivateServerMode(ctx context.Context, settings json.RawMessage) error {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.Info("activating server mode")

	dec := json.NewDecoder(bytes.NewReader(settings))
	dec.DisallowUnknownFields()
	var sc ServerConfig
	if err := dec.Decode(&sc); err != nil {
		return fmt.Errorf("failed to parse server config: %w", err)
	}
	if trailing := bytes.TrimSpace(settings[dec.InputOffset():]); len(trailing) > 0 {
		return fmt.Errorf("failed to parse server config: unexpected trailing data")
	}

	if err := sc.Validate(); err != nil {
		return err
	}

	return p.activateServerMode(ctx, &sc)
}

func (p *Plugin) activateServerMode(ctx context.Context, sc *ServerConfig) error {
	lgr := logr.FromContextOrDiscard(ctx)
	strategies := make(map[auth.ServerContext]FlowFn)

	httpClient := p.httpClient
	if httpClient == nil {
		httpClient = NewDefaultHTTPClient(logr.FromContextOrDiscard(ctx))
	}

	serverFlowFn, err := buildServerFlowFn(sc.ServerFlow, &sc.Credential, sc.GetAPIBaseURL(), httpClient)
	if err != nil {
		return fmt.Errorf("server flow: %w", err)
	}

	// Wrap GitHub App flow with cache+dedup. PAT tokens are static and don't need caching.
	var mgr *manager.Manager[string, *sdkplugin.TokenResponse]
	if sc.ServerFlow == auth.FlowGitHubApp {
		mgr = newInstallationCacheManager()
		serverFlowFn = cachedFlow(serverFlowFn, mgr, nil)
	}

	strategies[auth.ServerContextServer] = serverFlowFn

	// Delegated flow — uses the same (cached) server credential
	if sc.Delegated {
		lgr.V(1).Info("delegated mode enabled, reusing server credential")
		strategies[auth.ServerContextDelegated] = serverFlowFn
	}

	lgr.Info("server mode activated",
		"serverFlow", sc.ServerFlow,
		"hostname", sc.GetHostname(),
		"delegated", sc.Delegated,
	)

	p.mode = &githubServerMode{strategies: strategies, cacheManager: mgr}
	return nil
}

// buildServerFlowFn returns the appropriate FlowFn based on the server flow.
func buildServerFlowFn(serverFlow auth.Flow, cc *CredentialConfig, apiBaseURL string, httpClient HTTPClient) (FlowFn, error) {
	switch serverFlow {
	case auth.FlowPAT:
		// Resolve eagerly — PAT is a static secret, fail fast if missing.
		val, err := cc.PAT.Token.Resolve()
		if err != nil {
			return nil, fmt.Errorf("resolving PAT: %w", err)
		}
		return patFlow(val), nil
	case auth.FlowGitHubApp:
		return serverInstallationFlow(cc.App, apiBaseURL, httpClient), nil
	default:
		return nil, fmt.Errorf("unsupported server flow: %s", serverFlow)
	}
}

// allowedServerFlows returns the set of flows permitted as the top-level server flow.
func allowedServerFlows() map[auth.Flow]struct{} {
	return map[auth.Flow]struct{}{
		auth.FlowPAT:       {},
		auth.FlowGitHubApp: {},
	}
}

func isAllowedServerFlow(flow auth.Flow) bool {
	_, ok := allowedServerFlows()[flow]
	return ok
}
