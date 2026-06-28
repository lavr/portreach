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
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
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

// oidcDiscoveryTimeout bounds the OIDC discovery request made at startup so a
// slow or unreachable issuer fails fast rather than hanging UI boot indefinitely.
const oidcDiscoveryTimeout = 15 * time.Second

// callbackExchangeTimeout bounds the provider calls made during /auth/callback
// (token exchange, user/org fetch, JWKS verification). The incoming request
// context carries no deadline, so a stalled IdP would otherwise pin a callback
// goroutine indefinitely.
const callbackExchangeTimeout = 15 * time.Second

//go:embed templates/login.html templates/denied.html
var templatesFS embed.FS

var (
	loginTmpl       = template.Must(template.ParseFS(templatesFS, "templates/login.html"))
	deniedTmpl      = template.Must(template.ParseFS(templatesFS, "templates/denied.html"))
	authHTMLTagRe   = regexp.MustCompile(`<[^>]*>`)
	authHTMLSpaceRe = regexp.MustCompile(`\s+`)
)

// oauthState is the payload sealed into the OAuth state cookie. It binds the
// authorization request to its callback: the CSRF state must echo back and the
// OIDC nonce is verified against the id_token.
type oauthState struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Provider string `json:"provider"`
	// Callback pins the per-request redirect_uri derived at login (host-derived
	// mode); it is replayed at /auth/callback so the two ends of the flow use an
	// identical redirect_uri and the host cannot be swapped mid-flow. Empty in
	// fixed-redirectURL mode.
	Callback string `json:"cb,omitempty"`
	Expiry   int64  `json:"exp"`
}

// Authenticator owns the configured providers and the auth HTTP handlers. It is
// built once at startup from a validated Config.
type Authenticator struct {
	cfg       *Config
	providers map[string]Provider
	pcs       map[string]ProviderConfig // provider id -> config (allowlists)
	order     []string                  // provider ids in config order
	logger    *slog.Logger              // audit logger; nil falls back to slog.Default()
	branding  LoginBranding
}

// New builds an Authenticator from cfg, constructing one Provider per configured
// ProviderConfig. cfg is validated first. GitLab providers perform OIDC
// discovery against their issuer, so New may make network calls. Options (e.g.
// WithLogger) customise the result.
func New(cfg *Config, opts ...Option) (*Authenticator, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	a := &Authenticator{
		cfg:       cfg,
		providers: make(map[string]Provider, len(cfg.Providers)),
		pcs:       make(map[string]ProviderConfig, len(cfg.Providers)),
	}
	for _, opt := range opts {
		opt(a)
	}
	for _, pc := range cfg.Providers {
		var (
			p   Provider
			err error
		)
		switch {
		case pc.Type == TypeGitHub:
			p = newGitHubProvider(pc, cfg.RedirectURL)
		case pc.Type == TypeOIDC || isPreset(pc.Type):
			// The generic oidc type and every named preset (gitlab, okta,
			// keycloak, entra, ...) share the same OIDC code path; presets just
			// pre-fill issuer/scopes/claims defaults.
			dctx, cancel := context.WithTimeout(context.Background(), oidcDiscoveryTimeout)
			p, err = newPresetProvider(dctx, pc, cfg.RedirectURL)
			cancel()
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
		// Determine the redirect_uri for this flow: empty in fixed mode (the
		// provider uses its configured RedirectURL), or a host-derived callback
		// in dynamic mode. In dynamic mode an optional allowlist rejects unknown
		// hosts before the IdP is ever contacted.
		callback := a.callbackOverride(r)
		if callback != "" && !a.redirectHostAllowed(callback) {
			http.Error(w, "redirect host not allowed", http.StatusBadRequest)
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
			Callback: callback,
			Expiry:   time.Now().Add(oauthStateMaxAge).Unix(),
		}
		if err := a.setStateCookie(w, st, a.secureForRequest(r)); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, p.AuthCodeURL(state, nonce, callback), http.StatusFound)
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

	title, heading, showHeading := a.resolveAuthBranding(loc, "auth.login.title", "auth.login.heading")
	data := struct {
		Lang        string
		Title       string
		Heading     template.HTML
		ShowHeading bool
		Footer      template.HTML
		Buttons     []loginButton
	}{
		Lang:        loc.Lang(),
		Title:       title,
		Heading:     heading,
		ShowHeading: showHeading,
		Footer:      template.HTML(a.branding.Footer),
		Buttons:     buttons,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTmpl.ExecuteTemplate(w, "login.html", data)
}

// callbackOverride returns the per-request OAuth redirect_uri, or "" to fall
// back to the provider's configured RedirectURL. When auth.redirectURL is set
// (fixed mode) it returns "" so today's behaviour is preserved exactly.
// Otherwise (host-derived mode) it builds <proto>://<host>/auth/callback from
// the configured forwarded headers, falling back to r.Host and the connection's
// TLS state. The host/scheme are taken only from the trusted, configured
// headers — never from any other user-controllable field.
func (a *Authenticator) callbackOverride(r *http.Request) string {
	if a.cfg.RedirectURL != "" {
		return ""
	}
	hostHeader := a.cfg.ForwardedHostHeader
	if hostHeader == "" {
		hostHeader = defaultForwardedHostHeader
	}

	host := firstHeaderValue(r.Header.Get(hostHeader))
	if host == "" {
		host = r.Host
	}
	u := url.URL{Scheme: a.requestScheme(r), Host: host, Path: CallbackPath}
	return u.String()
}

// requestScheme reports the scheme ("https" or "http") the client used to reach
// the service, read only from trusted sources: the configured forwarded-proto
// header (default X-Forwarded-Proto) set by the ingress, falling back to the
// connection's TLS state. It is the single scheme decision shared by the
// host-derived callback URL and the cookie Secure flag so the two always agree.
func (a *Authenticator) requestScheme(r *http.Request) string {
	protoHeader := a.cfg.ForwardedProtoHeader
	if protoHeader == "" {
		protoHeader = defaultForwardedProtoHeader
	}
	if proto := firstHeaderValue(r.Header.Get(protoHeader)); proto != "" {
		return proto
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// requestIsHTTPS reports whether the request reached the service over https.
func (a *Authenticator) requestIsHTTPS(r *http.Request) bool {
	return a.requestScheme(r) == "https"
}

// secureForRequest decides the Secure attribute for cookies set on this request,
// honouring CookieSecure: always → true, never → false, auto (or empty) → Secure
// only when the request is https. Over http, auto yields a non-secure cookie so
// the browser will actually store it and the login flow can complete.
func (a *Authenticator) secureForRequest(r *http.Request) bool {
	switch a.cfg.CookieSecure {
	case cookieSecureAlways:
		return true
	case cookieSecureNever:
		return false
	default: // auto / empty
		return a.requestIsHTTPS(r)
	}
}

// firstHeaderValue returns the first comma-separated token of a forwarded
// header, trimmed. Proxies may chain values (e.g. "https, http"); the first is
// the one set closest to the client by the outermost trusted proxy.
func firstHeaderValue(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// redirectHostAllowed reports whether the host of a derived callback URL passes
// the optional AllowedRedirectHosts allowlist. An empty list allows any host
// (the IdP's registered-callback check is the backstop).
func (a *Authenticator) redirectHostAllowed(callback string) bool {
	if len(a.cfg.AllowedRedirectHosts) == 0 {
		return true
	}
	u, err := url.Parse(callback)
	if err != nil {
		return false
	}
	host := u.Hostname()
	for _, h := range a.cfg.AllowedRedirectHosts {
		if h == host {
			return true
		}
	}
	return false
}

// handleCallback completes the authorization-code flow: it validates the state
// cookie against the returned state, exchanges the code for an Identity, enforces
// the allowlist, and on success seals a session cookie and redirects home.
func (a *Authenticator) handleCallback(w http.ResponseWriter, r *http.Request) {
	loc := i18n.FromRequest(r)

	secure := a.secureForRequest(r)

	st, err := a.readStateCookie(r)
	if err != nil {
		http.Error(w, "invalid auth state", http.StatusBadRequest)
		return
	}
	// The state cookie is single-use regardless of the outcome below.
	clearStateCookie(w, secure)

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

	ctx, cancel := context.WithTimeout(r.Context(), callbackExchangeTimeout)
	defer cancel()
	id, err := p.Exchange(ctx, code, st.Nonce, st.Callback)
	if err != nil {
		// A hosted-domain (Google `hd`) mismatch is an access denial, not an
		// upstream failure: the login succeeded but the account is out of scope.
		if errors.Is(err, errHostedDomainMismatch) {
			a.logLogin(r, "", p.ID(), "denied")
			a.renderDenied(w, loc)
			return
		}
		http.Error(w, "authentication failed", http.StatusBadGateway)
		return
	}

	if !a.allowed(p.ID(), id) {
		a.logLogin(r, id.Login, p.ID(), "denied")
		a.renderDenied(w, loc)
		return
	}
	a.logLogin(r, id.Login, p.ID(), "ok")

	sess := Session{
		User:     id.Login,
		Name:     id.Name,
		Provider: p.ID(),
		Groups:   id.Groups,
		Expiry:   time.Now().Add(sessionMaxAge).Unix(),
	}
	if err := setSessionCookie(w, a.cfg.CookieKey, sess, secure); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleLogout clears the session cookie and returns to the home page.
func (a *Authenticator) handleLogout(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w, a.secureForRequest(r))
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
			if groupAllowed(pc.GroupMatch, want, have) {
				return true
			}
		}
	}
	return false
}

func groupAllowed(match, want, have string) bool {
	if want == have {
		return true
	}
	return match == GroupMatchSubtree && strings.HasPrefix(have, want+"/")
}

// renderDenied writes the localized 403 access-denied page.
func (a *Authenticator) renderDenied(w http.ResponseWriter, loc *i18n.Localizer) {
	title, heading, showHeading := a.resolveAuthBranding(loc, "auth.denied.title", "auth.denied.heading")
	data := struct {
		Lang        string
		Title       string
		Heading     template.HTML
		ShowHeading bool
		Message     string
		LoginURL    string
		LoginLabel  string
	}{
		Lang:        loc.Lang(),
		Title:       title,
		Heading:     heading,
		ShowHeading: showHeading,
		Message:     loc.T("auth.denied.message"),
		LoginURL:    LoginPath,
		LoginLabel:  loc.T("auth.login.title"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_ = deniedTmpl.ExecuteTemplate(w, "denied.html", data)
}

func (a *Authenticator) resolveAuthBranding(loc *i18n.Localizer, titleKey, headingKey string) (string, template.HTML, bool) {
	title := loc.T(titleKey)
	if a.branding.Title != nil && *a.branding.Title != "" {
		if stripped := stripAuthHTML(*a.branding.Title); stripped != "" {
			title = stripped
		}
	}

	heading := template.HTML(loc.T(headingKey))
	showHeading := true
	if a.branding.Header != nil {
		if *a.branding.Header == "" {
			showHeading = false
		} else {
			heading = template.HTML(*a.branding.Header)
		}
	}
	return title, heading, showHeading
}

func stripAuthHTML(s string) string {
	return strings.TrimSpace(authHTMLSpaceRe.ReplaceAllString(authHTMLTagRe.ReplaceAllString(s, " "), " "))
}

// setStateCookie seals st under the cookie key and writes the state cookie.
// secure sets the cookie's Secure attribute (see Authenticator.secureForRequest).
func (a *Authenticator) setStateCookie(w http.ResponseWriter, st oauthState, secure bool) error {
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
		Secure:   secure,
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

// clearStateCookie expires the OAuth state cookie. secure must match the value
// used when the cookie was set so the browser reliably clears it.
func clearStateCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
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
