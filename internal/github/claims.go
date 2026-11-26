// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
)

// User represents the relevant fields from the GitHub /user API response.
type User struct {
	Login     string `json:"login"`
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// fetchUserClaims calls the GitHub /user API and returns normalized auth.Claims.
func (p *Plugin) fetchUserClaims(ctx context.Context, accessToken string) (*auth.Claims, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("fetching user claims from GitHub API")

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	httpClient, releaseHTTP, err := p.acquireHTTPClient(ctx, cfg, true)
	if err != nil {
		return nil, err
	}
	defer releaseHTTP()

	endpoint := fmt.Sprintf("%s/user", cfg.GetAPIBaseURL())
	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", accessToken),
	}

	resp, err := httpClient.Get(ctx, endpoint, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to parse user response: %w", err)
	}

	login := sanitizeControlChars(user.Login)
	name := sanitizeControlChars(user.Name)
	email := sanitizeControlChars(user.Email)

	lgr.V(1).Info("user claims fetched",
		"login", login,
		"name", name,
		"id", user.ID,
	)

	return &auth.Claims{
		Issuer:   cfg.Hostname,
		Subject:  login,
		ObjectID: strconv.FormatInt(user.ID, 10),
		Email:    email,
		Name:     name,
		Username: login,
		IssuedAt: time.Now(),
	}, nil
}
