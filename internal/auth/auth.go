package auth

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/lavr/portreach/internal/i18n"
)

// Auth route paths. /auth/login renders the provider chooser (or redirects to a
// single provider when ?provider is set); /auth/callback completes the flow;
// /auth/logout clears the session.
const (
	LoginPath    = "/auth/login"
	CallbackPath = "/auth/callback"
	LogoutPath   = "/auth/logout"
)

// oauthStateCookieName holds the short-lived sealed CSRF state + OIDC nonce +
// chosen provider id bridging /auth/login and /auth/callback.
const oauthStateCookieName = "portreach_oauth_state"

// oauthStateMaxAge bounds how long an in-flight login may take.
const oauthStateMaxAge = 10 * time.Minute

//go:embed templates/login.html templates/denied.html
var templatesFS embed.FS

var (
	loginTmpl  = template.Must(template.ParseFS(templatesFS, "templates/login.html"))
	deniedTmpl = template.Must(template.ParseFS(templatesFS, "templates/denied.html"))
)

// oauthState is the payload sealed into the OAuth state cookie. It binds the
// authorization request to its callback: the CSRF state must echo back and the
// OIDC nonce is verified against the id_token.
type oauthState struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Provider string `json:"provider"`
	Expiry   int64  `json:"exp"`
}

// Authenticator owns the configured providers and the auth HTTP handlers. It is
// built once at startup from a validated Config.
type Authenticator struct {
	cfg       *Config
	providers map[string]Provider
	pcs       map[string]ProviderConfig // provider id -> config (allowlists)
	order     []string                  // provider ids in config order
}

// New builds an Authenticator from cfg, constructing one Provider per configured
// ProviderConfig. cfg is validated first. GitLab providers perform OIDC
// discovery against their issuer, so New may make network calls.
func New(cfg *Config) (*Authenticator, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	a := &Authenticator{
		cfg:       cfg,
		providers: make(map[string]Provider, len(cfg.Providers)),
		pcs:       make(map[string]ProviderConfig, len(cfg.Providers)),
	}
	for _, pc := range cfg.Providers {
		var (
			p   Provider
			err error
		)
		switch pc.Type {
		case TypeGitHub:
			p = newGitHubProvider(pc, cfg.RedirectURL)
		case TypeGitLab:
			p, err = newGitLabProvider(context.Background(), pc, cfg.RedirectURL)
		default:
			err = fmt.Errorf("auth: unknown provider type %q", pc.Type)
		}
		if err != nil {
			return nil, err
		}
		a.providers[pc.ID] = p
		a.pcs[pc.ID] = pc
		a.order = append(a.order, pc.ID)
	}
	return a, nil
}

// Mux returns an http.ServeMux serving the /auth/* routes.
func (a *Authenticator) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(LoginPath, a.handleLogin)
	mux.HandleFunc(CallbackPath, a.handleCallback)
	mux.HandleFunc(LogoutPath, a.handleLogout)
	return mux
}

// loginButton drives one entry on the login chooser page.
type loginButton struct {
	URL   string
	Label string
}

// handleLogin renders the provider chooser. With ?provider=<id> it instead
// starts that provider's authorization-code flow: it mints a fresh state +
// nonce, stores them in the sealed state cookie, and redirects to the provider.
// With no provider param it always renders a button per provider — even a single
// provider gets a button rather than an automatic redirect.
func (a *Authenticator) handleLogin(w http.ResponseWriter, r *http.Request) {
	loc := i18n.FromRequest(r)

	if pid := r.URL.Query().Get("provider"); pid != "" {
		p, ok := a.providers[pid]
		if !ok {
			http.Error(w, "unknown provider", http.StatusNotFound)
			return
		}
		state, err := randToken()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		nonce, err := randToken()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		st := oauthState{
			State:    state,
			Nonce:    nonce,
			Provider: pid,
			Expiry:   time.Now().Add(oauthStateMaxAge).Unix(),
		}
		if err := a.setStateCookie(w, st); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, p.AuthCodeURL(state, nonce), http.StatusFound)
		return
	}

	buttons := make([]loginButton, 0, len(a.order))
	for _, id := range a.order {
		p := a.providers[id]
		label := p.DisplayName()
		if label == "" {
			label = loc.T("auth.login.button", p.Type())
		}
		buttons = append(buttons, loginButton{
			URL:   LoginPath + "?provider=" + url.QueryEscape(id),
			Label: label,
		})
	}

	data := struct {
		Lang    string
		Title   string
		Heading string
		Buttons []loginButton
	}{
		Lang:    loc.Lang(),
		Title:   loc.T("auth.login.title"),
		Heading: loc.T("auth.login.heading"),
		Buttons: buttons,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTmpl.ExecuteTemplate(w, "login.html", data)
}

// handleCallback completes the authorization-code flow: it validates the state
// cookie against the returned state, exchanges the code for an Identity, enforces
// the allowlist, and on success seals a session cookie and redirects home.
func (a *Authenticator) handleCallback(w http.ResponseWriter, r *http.Request) {
	loc := i18n.FromRequest(r)

	st, err := a.readStateCookie(r)
	if err != nil {
		http.Error(w, "invalid auth state", http.StatusBadRequest)
		return
	}
	// The state cookie is single-use regardless of the outcome below.
	clearStateCookie(w)

	q := r.URL.Query()
	if got := q.Get("state"); got == "" || got != st.State {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	p, ok := a.providers[st.Provider]
	if !ok {
		http.Error(w, "unknown provider", http.StatusBadRequest)
		return
	}
	code := q.Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	id, err := p.Exchange(r.Context(), code, st.Nonce)
	if err != nil {
		http.Error(w, "authentication failed", http.StatusBadGateway)
		return
	}

	if !a.allowed(p.ID(), id) {
		a.renderDenied(w, loc)
		return
	}

	sess := Session{
		User:     id.Login,
		Name:     id.Name,
		Provider: p.ID(),
		Groups:   id.Groups,
		Expiry:   time.Now().Add(sessionMaxAge).Unix(),
	}
	if err := setSessionCookie(w, a.cfg.CookieKey, sess); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleLogout clears the session cookie and returns to the home page.
func (a *Authenticator) handleLogout(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

// allowed reports whether identity id may access the service via provider
// providerID. Access passes when no allowlist is configured (neither the global
// AllowedUsers nor that provider's org/group list), OR the user is in
// AllowedUsers, OR any of the user's groups is in the provider's allowlist.
func (a *Authenticator) allowed(providerID string, id Identity) bool {
	pc := a.pcs[providerID]
	allowedGroups := make([]string, 0, len(pc.AllowedOrgs)+len(pc.AllowedGroups))
	allowedGroups = append(allowedGroups, pc.AllowedOrgs...)
	allowedGroups = append(allowedGroups, pc.AllowedGroups...)

	if len(a.cfg.AllowedUsers) == 0 && len(allowedGroups) == 0 {
		return true
	}
	for _, u := range a.cfg.AllowedUsers {
		if u == id.Login {
			return true
		}
	}
	for _, want := range allowedGroups {
		for _, have := range id.Groups {
			if want == have {
				return true
			}
		}
	}
	return false
}

// renderDenied writes the localized 403 access-denied page.
func (a *Authenticator) renderDenied(w http.ResponseWriter, loc *i18n.Localizer) {
	data := struct {
		Lang       string
		Title      string
		Heading    string
		Message    string
		LoginURL   string
		LoginLabel string
	}{
		Lang:       loc.Lang(),
		Title:      loc.T("auth.denied.title"),
		Heading:    loc.T("auth.denied.heading"),
		Message:    loc.T("auth.denied.message"),
		LoginURL:   LoginPath,
		LoginLabel: loc.T("auth.login.title"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_ = deniedTmpl.ExecuteTemplate(w, "denied.html", data)
}

// setStateCookie seals st under the cookie key and writes the state cookie.
func (a *Authenticator) setStateCookie(w http.ResponseWriter, st oauthState) error {
	plaintext, err := json.Marshal(st)
	if err != nil {
		return err
	}
	token, err := sealBytes(a.cfg.CookieKey, plaintext)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(oauthStateMaxAge.Seconds()),
	})
	return nil
}

// readStateCookie opens and validates the OAuth state cookie, rejecting a
// missing, tampered or expired cookie.
func (a *Authenticator) readStateCookie(r *http.Request) (oauthState, error) {
	var st oauthState
	c, err := r.Cookie(oauthStateCookieName)
	if err != nil {
		return st, err
	}
	plaintext, err := openBytes(a.cfg.CookieKey, c.Value)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(plaintext, &st); err != nil {
		return st, err
	}
	if st.Expiry != 0 && time.Now().Unix() >= st.Expiry {
		return st, errors.New("auth: oauth state expired")
	}
	return st, nil
}

// clearStateCookie expires the OAuth state cookie.
func clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// randToken returns 32 bytes of cryptographic randomness as base64url text, used
// for the CSRF state and OIDC nonce.
func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
