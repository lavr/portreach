package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// githubProvider implements Provider against github.com or a GitHub Enterprise
// instance using the OAuth authorization-code flow.
type githubProvider struct {
	id          string
	displayName string
	apiBase     string // e.g. https://api.github.com or https://ghe.corp/api/v3
	oauth       *oauth2.Config

	// httpClient overrides the client used for API calls in tests; nil uses
	// the token-authenticated client from the exchange.
	httpClient *http.Client
}

// newGitHubProvider builds a GitHub provider from a ProviderConfig. redirectURL
// is the top-level OAuth callback URL. baseURL distinguishes github.com from an
// Enterprise install and determines both the OAuth and REST API endpoints.
func newGitHubProvider(pc ProviderConfig, redirectURL string) *githubProvider {
	base := strings.TrimRight(pc.BaseURL, "/")
	if base == "" {
		base = defaultBaseURL[TypeGitHub]
	}

	var apiBase string
	if base == defaultBaseURL[TypeGitHub] {
		apiBase = "https://api.github.com"
	} else {
		apiBase = base + "/api/v3"
	}

	return &githubProvider{
		id:          pc.ID,
		displayName: pc.DisplayName,
		apiBase:     apiBase,
		oauth: &oauth2.Config{
			ClientID:     pc.ClientID,
			ClientSecret: pc.ClientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"read:org", "read:user"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  base + "/login/oauth/authorize",
				TokenURL: base + "/login/oauth/access_token",
			},
		},
	}
}

func (p *githubProvider) ID() string          { return p.id }
func (p *githubProvider) DisplayName() string { return p.displayName }
func (p *githubProvider) Type() string        { return TypeGitHub }

// AuthCodeURL returns the GitHub authorization URL for the given state.
func (p *githubProvider) AuthCodeURL(state string) string {
	return p.oauth.AuthCodeURL(state)
}

// Exchange swaps the authorization code for a token, then fetches the user and
// their org memberships, mapping them into an Identity (Groups = org logins).
func (p *githubProvider) Exchange(ctx context.Context, code string) (Identity, error) {
	tok, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return Identity{}, fmt.Errorf("auth: github token exchange: %w", err)
	}

	client := p.httpClient
	if client == nil {
		client = p.oauth.Client(ctx, tok)
		client.Timeout = 15 * time.Second
	}

	var user struct {
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := p.getJSON(ctx, client, tok, p.apiBase+"/user", &user); err != nil {
		return Identity{}, fmt.Errorf("auth: github get user: %w", err)
	}
	if user.Login == "" {
		return Identity{}, fmt.Errorf("auth: github returned empty login")
	}

	var orgs []struct {
		Login string `json:"login"`
	}
	if err := p.getJSON(ctx, client, tok, p.apiBase+"/user/orgs", &orgs); err != nil {
		return Identity{}, fmt.Errorf("auth: github get orgs: %w", err)
	}
	groups := make([]string, 0, len(orgs))
	for _, o := range orgs {
		if o.Login != "" {
			groups = append(groups, o.Login)
		}
	}

	return Identity{Login: user.Login, Name: user.Name, Groups: groups}, nil
}

// getJSON issues an authenticated GET and decodes a JSON body into out. When the
// shared oauth client is bypassed (tests inject a plain client), the bearer
// token is attached explicitly.
func (p *githubProvider) getJSON(ctx context.Context, client *http.Client, tok *oauth2.Token, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if p.httpClient != nil && tok != nil {
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode %s: %w", url, err)
	}
	return nil
}
