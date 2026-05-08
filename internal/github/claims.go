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

	endpoint := fmt.Sprintf("%s/user", p.config.GetAPIBaseURL())
	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", accessToken),
	}

	resp, err := p.httpClient.Get(ctx, endpoint, headers)
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

	lgr.V(1).Info("user claims fetched",
		"login", user.Login,
		"name", user.Name,
		"id", user.ID,
	)

	return &auth.Claims{
		Issuer:   p.config.Hostname,
		Subject:  user.Login,
		ObjectID: strconv.FormatInt(user.ID, 10),
		Email:    user.Email,
		Name:     user.Name,
		Username: user.Login,
		IssuedAt: time.Now(),
	}, nil
}
