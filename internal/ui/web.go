package ui

import (
	_ "embed"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/lavr/portreach/internal/i18n"
)

//go:embed web/index.html
var indexHTML string

var indexTmpl = template.Must(template.New("index").Parse(indexHTML))

// pageData drives the server-rendered form page. The form fields echo the raw
// user input so a submitted form re-renders with its values preserved. L is the
// request's localizer; the template pulls every visible string through it and
// Lang feeds the <html lang> attribute.
type pageData struct {
	L         *i18n.Localizer
	Lang      string
	Host      string
	Port      string
	Proto     string
	Timeout   string
	Submitted bool
	Error     string
	Results   []AgentResult
	Summary   Summary
}

// handleIndex renders the web form and, when the form is submitted, the
// aggregated results for the target reusing CheckAll.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	loc := i18n.FromRequest(r)
	q := r.URL.Query()
	data := pageData{
		L:       loc,
		Lang:    loc.Lang(),
		Host:    strings.TrimSpace(q.Get("host")),
		Port:    strings.TrimSpace(q.Get("port")),
		Proto:   q.Get("proto"),
		Timeout: strings.TrimSpace(q.Get("timeout")),
	}
	if data.Proto == "" {
		data.Proto = "tcp"
	}

	// Submitted means the form was sent: any of the target fields are present.
	data.Submitted = q.Has("host") || q.Has("port")

	if data.Submitted {
		target, err := parseTarget(q)
		switch {
		case data.Host == "":
			data.Error = loc.T("error.host_required")
		case errors.Is(err, errBadPort):
			data.Error = loc.T("error.bad_port")
		case errors.Is(err, errBadTimeout):
			data.Error = loc.T("error.bad_timeout")
		case err != nil:
			data.Error = err.Error()
		default:
			ctx, cancel := contextWithTimeout(r, s.timeout)
			defer cancel()

			agents, derr := s.disc.Agents(ctx)
			switch {
			case derr != nil && ctx.Err() != nil:
				// The DNS discoverer reports a deadline as a LookupHost error, so a
				// discovery failure caused by the shared budget expiring should read as
				// a clean timeout rather than a generic discovery error.
				data.Error = "deadline exceeded during discovery: " + ctx.Err().Error()
			case derr != nil:
				data.Error = "discovery: " + derr.Error()
			case ctx.Err() != nil:
				// Discovery used the whole budget; no time left to probe. Report a
				// clean deadline error rather than fanning out with an expired ctx.
				data.Error = "deadline exceeded after discovery: " + ctx.Err().Error()
			default:
				// Mirror the JSON API: clamp the per-agent timeout against the
				// budget remaining after discovery so the UI's own deadline
				// can't pre-empt clean per-node results.
				target.Timeout = clampTimeout(target.Timeout, remainingBudget(ctx, s.timeout))
				data.Results = CheckAll(ctx, s.client, agents, target)
				data.Summary = Summarize(data.Results)
				// Normalize echoed port to the validated value.
				data.Port = strconv.Itoa(target.Port)
				data.Proto = target.Proto
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if data.Error != "" {
		w.WriteHeader(http.StatusBadRequest)
	}
	_ = indexTmpl.Execute(w, data)
}
