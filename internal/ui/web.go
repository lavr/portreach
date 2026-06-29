package ui

import (
	_ "embed"
	"errors"
	"html/template"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/lavr/portreach/internal/i18n"
)

//go:embed web/index.html
var indexHTML string

var (
	indexTmpl   = template.Must(template.New("index").Parse(indexHTML))
	htmlTagRe   = regexp.MustCompile(`<[^>]*>`)
	htmlSpaceRe = regexp.MustCompile(`\s+`)
)

// pageData drives the server-rendered form page. The form fields echo the raw
// user input so a submitted form re-renders with its values preserved. L is the
// request's localizer; the template pulls every visible string through it and
// Lang feeds the <html lang> attribute.
type pageData struct {
	L           *i18n.Localizer
	Lang        string
	DocTitle    string
	Title       template.HTML
	ShowTitle   bool
	Description template.HTML
	Footer      template.HTML
	Host        string
	Port        string
	Proto       string
	Timeout     string
	Submitted   bool
	Error       string
	Results     []AgentResult
	Summary     Summary
}

func (s *Server) newPageData(loc *i18n.Localizer) pageData {
	data := pageData{
		L:           loc,
		Lang:        loc.Lang(),
		DocTitle:    loc.T("app.title"),
		Title:       template.HTML(loc.T("app.heading")),
		ShowTitle:   true,
		Description: template.HTML(s.branding.Description),
		Footer:      template.HTML(s.branding.Footer),
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
// aggregated results for the target reusing CheckAll.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	loc := i18n.FromRequest(r)
	q := r.URL.Query()
	data := s.newPageData(loc)
	data.Host = strings.TrimSpace(q.Get("host"))
	data.Port = strings.TrimSpace(q.Get("port"))
	data.Proto = q.Get("proto")
	data.Timeout = strings.TrimSpace(q.Get("timeout"))
	if data.Proto == "" {
		data.Proto = "tcp"
	}

	// Submitted means the form was sent: any of the target fields are present.
	data.Submitted = q.Has("host") || q.Has("port")

	// status tracks the HTTP status to write: 200 by default, 400 for a bad
	// submission, 429 when the rate limiter throttles the request.
	status := http.StatusOK

	if data.Submitted {
		target, err := parseTarget(q)
		switch {
		case data.Host == "":
			data.Error = loc.T("error.host_required")
			status = http.StatusBadRequest
		case errors.Is(err, errBadPort):
			data.Error = loc.T("error.bad_port")
			status = http.StatusBadRequest
		case errors.Is(err, errBadTimeout):
			data.Error = loc.T("error.bad_timeout")
			status = http.StatusBadRequest
		case err != nil:
			data.Error = err.Error()
			status = http.StatusBadRequest
		default:
			if retry, ok := s.allow(r, target); !ok {
				// Over limit: render the form with a localized throttle message and
				// a Retry-After header, mirroring the JSON API's 429.
				ra := retryAfterSeconds(retry)
				w.Header().Set("Retry-After", ra)
				data.Error = loc.T("error.rate_limited", ra)
				status = http.StatusTooManyRequests
				break
			}
			ctx, cancel := contextWithTimeout(r, s.timeout)
			defer cancel()

			agents, derr := s.disc.Agents(ctx)
			switch {
			case derr != nil && ctx.Err() != nil:
				// The DNS discoverer reports a deadline as a LookupHost error, so a
				// discovery failure caused by the shared budget expiring should read as
				// a clean timeout rather than a generic discovery error.
				data.Error = "deadline exceeded during discovery: " + ctx.Err().Error()
				status = http.StatusBadRequest
			case derr != nil:
				data.Error = "discovery: " + derr.Error()
				status = http.StatusBadRequest
			case ctx.Err() != nil:
				// Discovery used the whole budget; no time left to probe. Report a
				// clean deadline error rather than fanning out with an expired ctx.
				data.Error = "deadline exceeded after discovery: " + ctx.Err().Error()
				status = http.StatusBadRequest
			default:
				// Mirror the JSON API: clamp the per-agent timeout against the
				// budget remaining after discovery so the UI's own deadline
				// can't pre-empt clean per-node results.
				target.Timeout = clampTimeout(target.Timeout, remainingBudget(ctx, s.timeout))
				data.Results, _, _, _ = s.fanout(ctx, r, agents, target)
				data.Summary = Summarize(data.Results)
				// Normalize echoed port to the validated value.
				data.Port = strconv.Itoa(target.Port)
				data.Proto = target.Proto
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = indexTmpl.Execute(w, data)
}
