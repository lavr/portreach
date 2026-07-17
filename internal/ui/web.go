package ui

import (
	_ "embed"
	"errors"
	"html/template"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lavr/portreach/internal/checkapi"
	"github.com/lavr/portreach/internal/i18n"
	"github.com/lavr/portreach/internal/ratelimit"
)

//go:embed web/index.html
var indexHTML string

var (
	indexTmpl   = template.Must(template.New("index").Parse(indexHTML))
	htmlTagRe   = regexp.MustCompile(`<[^>]*>`)
	htmlSpaceRe = regexp.MustCompile(`\s+`)
)

// pageData drives the server-rendered form page. The form fields echo the raw
// user input so a submitted form re-renders with its values preserved — with
// one deliberate exception: Password is never a field here, so a submitted
// Postgres check re-renders with an empty password box and the secret is never
// written back into the HTML. L is the request's localizer; the template pulls
// every visible string through it and Lang feeds the <html lang> attribute.
type pageData struct {
	L           *i18n.Localizer
	Lang        string
	DocTitle    string
	Title       template.HTML
	ShowTitle   bool
	Description template.HTML
	Footer      template.HTML

	// PostgresEnabled reflects the --enabled-checks allowlist: the check-type
	// selector and the Postgres credential fields render only when it is on, so
	// a TCP-only deployment sees exactly today's spartan form.
	PostgresEnabled bool
	// Check is the selected check type ("tcp" or "postgres"); it drives which
	// fields the form shows and whether results carry an Auth column.
	Check string

	Host    string
	Port    string
	Proto   string
	Timeout string

	// Postgres form fields, echoed back on re-render — Username/Database only.
	// Password is intentionally absent (never reflected). TLSVerify/TLSSkip echo
	// the TLS toggle state so a re-rendered form keeps the user's choice.
	Username   string
	Database   string
	ServerName string
	TLSEnabled bool
	TLSSkip    bool

	Submitted bool
	Error     string
	Results   []AgentResult
	Summary   Summary
}

// IsPostgres reports whether the rendered results should show the Auth column.
func (d pageData) IsPostgres() bool { return d.Check == string(checkapi.CheckPostgres) }

func (s *Server) newPageData(loc *i18n.Localizer) pageData {
	data := pageData{
		L:               loc,
		Lang:            loc.Lang(),
		DocTitle:        loc.T("app.title"),
		Title:           template.HTML(loc.T("app.heading")),
		ShowTitle:       true,
		Description:     template.HTML(s.branding.Description),
		Footer:          template.HTML(s.branding.Footer),
		PostgresEnabled: s.enabledChecks.Has(checkapi.CheckPostgres),
		Check:           string(checkapi.CheckTCP),
		TLSEnabled:      true, // TLS on by default, matching the API/pgauth default
	}
	if s.branding.Title != nil {
		if *s.branding.Title == "" {
			data.ShowTitle = false
		} else {
			data.Title = template.HTML(*s.branding.Title)
			data.DocTitle = stripHTML(*s.branding.Title)
			if data.DocTitle == "" {
				data.DocTitle = loc.T("app.title")
			}
		}
	}
	return data
}

func stripHTML(s string) string {
	return strings.TrimSpace(htmlSpaceRe.ReplaceAllString(htmlTagRe.ReplaceAllString(s, " "), " "))
}

// handleIndex renders the web form and, when the form is submitted, the
// aggregated results for the target. A TCP check works over GET (shareable
// result URLs) or POST; a Postgres check is POST-only, because its credentials
// belong in a request body, never a query string. The whole check runs
// server-side with no JavaScript required.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	loc := i18n.FromRequest(r)
	data := s.newPageData(loc)

	// ParseForm merges the query string and (for POST) the form body into
	// r.Form. We read non-secret fields from r.Form so a GET ?host=… link still
	// renders, but the password is read only from r.PostForm below — never from
	// the query — so a password can never arrive (or be echoed) via a URL.
	if err := r.ParseForm(); err != nil {
		data.Error = loc.T("error.bad_request")
		s.renderIndex(w, data, http.StatusBadRequest)
		return
	}

	// Selected check type: honour the postgres selection only when postgres is
	// actually enabled; anything else is a TCP check.
	if data.PostgresEnabled && r.Form.Get("check") == string(checkapi.CheckPostgres) {
		data.Check = string(checkapi.CheckPostgres)
	}

	data.Host = strings.TrimSpace(r.Form.Get("host"))
	data.Port = strings.TrimSpace(r.Form.Get("port"))
	data.Proto = r.Form.Get("proto")
	data.Timeout = strings.TrimSpace(r.Form.Get("timeout"))
	if data.Proto == "" {
		data.Proto = "tcp"
	}

	// Submitted means the form was sent: any of the target fields are present.
	data.Submitted = r.Form.Has("host") || r.Form.Has("port")
	if !data.Submitted {
		s.renderIndex(w, data, http.StatusOK)
		return
	}

	if data.Check == string(checkapi.CheckPostgres) {
		s.handleIndexPostgres(w, r, &data)
	} else {
		s.handleIndexTCP(w, r, &data)
	}
}

// handleIndexTCP runs the TCP web-form check and fills data with the results or
// a localized error, then renders the page.
func (s *Server) handleIndexTCP(w http.ResponseWriter, r *http.Request, data *pageData) {
	loc := data.L
	target, err := parseTarget(r.Form)
	switch {
	case data.Host == "":
		data.Error = loc.T("error.host_required")
		s.renderIndex(w, *data, http.StatusBadRequest)
	case errors.Is(err, errBadPort):
		data.Error = loc.T("error.bad_port")
		s.renderIndex(w, *data, http.StatusBadRequest)
	case errors.Is(err, errBadTimeout):
		data.Error = loc.T("error.bad_timeout")
		s.renderIndex(w, *data, http.StatusBadRequest)
	case err != nil:
		data.Error = err.Error()
		s.renderIndex(w, *data, http.StatusBadRequest)
	default:
		if retry, ok := s.allow(r, target); !ok {
			s.renderThrottled(w, data, retry)
			return
		}
		if !s.runFormCheck(w, r, data, target, nil) {
			return
		}
		data.Port = strconv.Itoa(target.Port)
		data.Proto = target.Proto
		s.renderIndex(w, *data, http.StatusOK)
	}
}

// handleIndexPostgres runs the Postgres web-form check. It reads credentials
// (password from the POST body only), validates via checkapi, applies both the
// general and the postgres-specific rate limiters, audits the request, then
// fans out — mirroring handleAPICheckPostgres, but rendering HTML. The password
// is used to build the request and is never written back into data.
func (s *Server) handleIndexPostgres(w http.ResponseWriter, r *http.Request, data *pageData) {
	loc := data.L

	username := strings.TrimSpace(r.PostForm.Get("username"))
	password := r.PostForm.Get("password")
	req := checkapi.PostgresCheckRequest{
		Host:        data.Host,
		Port:        0, // set after the port field parses cleanly below
		Credentials: checkapi.Credentials{Username: username, Password: password, Database: strings.TrimSpace(r.PostForm.Get("database"))},
		TLS:         s.formTLS(r),
	}
	// Echo back the non-secret fields (never the password) so a re-rendered form
	// keeps the user's input — including the TLS toggle state, so an unchecked
	// TLS box / skip-verify / custom server name survives a re-render.
	data.Username = username
	data.Database = req.Credentials.Database
	if req.TLS != nil {
		data.TLSEnabled = req.TLS.Enabled == nil || *req.TLS.Enabled
		data.TLSSkip = req.TLS.InsecureSkipVerify
		data.ServerName = req.TLS.ServerName
	}

	// Field-level checks first, so the form can show a localized, specific
	// message; req.Validate() below is the catch-all for anything remaining. All
	// of these messages are password-free.
	port, perr := strconv.Atoi(data.Port)
	switch {
	case data.Host == "":
		data.Error = loc.T("error.host_required")
		s.renderIndex(w, *data, http.StatusBadRequest)
		return
	case perr != nil:
		data.Error = loc.T("error.bad_port")
		s.renderIndex(w, *data, http.StatusBadRequest)
		return
	case username == "":
		data.Error = loc.T("error.username_required")
		s.renderIndex(w, *data, http.StatusBadRequest)
		return
	case password == "":
		data.Error = loc.T("error.password_required")
		s.renderIndex(w, *data, http.StatusBadRequest)
		return
	}
	req.Port = port
	if d := strings.TrimSpace(r.Form.Get("timeout")); d != "" {
		parsed, err := time.ParseDuration(d)
		if err != nil {
			data.Error = loc.T("error.bad_timeout")
			s.renderIndex(w, *data, http.StatusBadRequest)
			return
		}
		req.Timeout = checkapi.Duration(parsed)
	}

	if err := req.Validate(); err != nil {
		data.Error = err.Error() // password-free by construction
		s.renderIndex(w, *data, http.StatusBadRequest)
		return
	}

	target := Target{Host: req.Host, Port: req.Port, Proto: string(checkapi.CheckPostgres), Timeout: durationString(req.Timeout)}
	auth := &PostgresAuth{Credentials: req.Credentials, TLS: req.TLS}

	if retry, ok := s.allow(r, target); !ok {
		s.auditPostgres(r, req, "throttled", "")
		s.renderThrottled(w, data, retry)
		return
	}
	if retry, ok := s.allowPostgres(r, target); !ok {
		s.auditPostgres(r, req, "throttled", "")
		s.renderThrottled(w, data, retry)
		return
	}

	if !s.runFormCheck(w, r, data, target, auth) {
		return
	}
	s.auditPostgres(r, req, "completed", reachableSummary(data.Summary))
	data.Port = strconv.Itoa(target.Port)
	data.Proto = target.Proto
	s.renderIndex(w, *data, http.StatusOK)
}

// runFormCheck discovers agents and fans out, filling data.Results/data.Summary.
// It returns false (having already rendered an error page) if discovery failed
// or the budget expired; true if results were produced.
func (s *Server) runFormCheck(w http.ResponseWriter, r *http.Request, data *pageData, target Target, auth *PostgresAuth) bool {
	ctx, cancel := contextWithTimeout(r, s.timeout)
	defer cancel()

	agents, derr := s.disc.Agents(ctx)
	switch {
	case derr != nil && ctx.Err() != nil:
		data.Error = "deadline exceeded during discovery: " + ctx.Err().Error()
		s.renderIndex(w, *data, http.StatusBadRequest)
		return false
	case derr != nil:
		data.Error = "discovery: " + derr.Error()
		s.renderIndex(w, *data, http.StatusBadRequest)
		return false
	case ctx.Err() != nil:
		data.Error = "deadline exceeded after discovery: " + ctx.Err().Error()
		s.renderIndex(w, *data, http.StatusBadRequest)
		return false
	}
	target.Timeout = clampTimeout(target.Timeout, remainingBudget(ctx, s.timeout))
	data.Results, _, _, _ = s.fanout(ctx, r, agents, target, auth)
	data.Summary = Summarize(data.Results)
	return true
}

// formTLS builds the TLSOptions for a Postgres web-form submission. TLS is on
// by default (the "tls" checkbox renders checked); unchecking it submits no
// "tls" field, which we read as an explicit opt-out. skip-verify and a custom
// server name are honoured only when supplied.
func (s *Server) formTLS(r *http.Request) *checkapi.TLSOptions {
	enabled := r.PostForm.Has("tls")
	return &checkapi.TLSOptions{
		Enabled:            &enabled,
		ServerName:         strings.TrimSpace(r.PostForm.Get("tls_server_name")),
		InsecureSkipVerify: r.PostForm.Has("tls_skip_verify"),
	}
}

// renderThrottled renders the form with a localized 429 message + Retry-After,
// mirroring the JSON API's throttle response.
func (s *Server) renderThrottled(w http.ResponseWriter, data *pageData, retry time.Duration) {
	ra := ratelimit.RetryAfterSeconds(retry)
	w.Header().Set("Retry-After", ra)
	data.Error = data.L.T("error.rate_limited", ra)
	s.renderIndex(w, *data, http.StatusTooManyRequests)
}

// renderIndex writes the page at the given status. Isolating the write keeps
// the TLS/echo-state on data (esp. the never-set Password) as the single source
// of what reaches the HTML.
func (s *Server) renderIndex(w http.ResponseWriter, data pageData, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = indexTmpl.Execute(w, data)
}
