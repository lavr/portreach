// Package i18n provides the UI translation layer for portreach. Interface
// language is selected from the browser's Accept-Language header, defaulting to
// English. Catalogs ship embedded (en + ru) and new locales are added by
// dropping a locales/<lang>.json file and registering its tag in supported.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"

	"golang.org/x/text/language"
)

//go:embed locales/*.json
var localesFS embed.FS

// DefaultTag is the fallback language used for unknown/missing Accept-Language.
var DefaultTag = language.English

// supported lists the languages shipped, in priority order. The first entry is
// the default the matcher falls back to. To add a locale, drop a
// locales/<lang>.json file and append its tag here.
var supported = []language.Tag{
	language.English, // en — must stay first (default/fallback)
	language.Russian, // ru
}

// localeFiles maps a supported tag to its catalog file (base name).
var localeFiles = map[language.Tag]string{
	language.English: "en.json",
	language.Russian: "ru.json",
}

// matcher resolves an Accept-Language value to one of the supported tags.
var matcher = language.NewMatcher(supported)

// catalogs holds the loaded message tables keyed by language tag.
var catalogs = mustLoadCatalogs()

// mustLoadCatalogs reads every embedded catalog at package init. A malformed or
// missing catalog is a programming error and panics.
func mustLoadCatalogs() map[language.Tag]map[string]string {
	out := make(map[language.Tag]map[string]string, len(localeFiles))
	for tag, file := range localeFiles {
		data, err := localesFS.ReadFile(path.Join("locales", file))
		if err != nil {
			panic(fmt.Sprintf("i18n: read catalog %s: %v", file, err))
		}
		var m map[string]string
		if err := json.Unmarshal(data, &m); err != nil {
			panic(fmt.Sprintf("i18n: parse catalog %s: %v", file, err))
		}
		out[tag] = m
	}
	return out
}

// Match resolves an Accept-Language header value to a supported language tag.
// Missing, empty or unknown values yield DefaultTag (English).
func Match(acceptLanguage string) language.Tag {
	if strings.TrimSpace(acceptLanguage) == "" {
		return DefaultTag
	}
	// ParseAcceptLanguage tolerates malformed input by returning what it can.
	tags, _, err := language.ParseAcceptLanguage(acceptLanguage)
	if err != nil {
		return DefaultTag
	}
	_, idx, conf := matcher.Match(tags...)
	if conf == language.No {
		return DefaultTag
	}
	return supported[idx]
}

// Localizer renders message keys for a single resolved language.
type Localizer struct {
	tag language.Tag
}

// NewLocalizer returns a Localizer for tag. The tag should come from Match; an
// unsupported tag still works, falling back to English for every key.
func NewLocalizer(tag language.Tag) *Localizer {
	return &Localizer{tag: tag}
}

// FromRequest builds a Localizer from a request's Accept-Language header. It is
// the shared entry point for both internal/ui and internal/auth.
func FromRequest(r *http.Request) *Localizer {
	return NewLocalizer(Match(r.Header.Get("Accept-Language")))
}

// Tag reports the language this Localizer renders.
func (l *Localizer) Tag() language.Tag { return l.tag }

// Lang returns the base-language code (e.g. "en", "ru") for use in <html lang>.
func (l *Localizer) Lang() string {
	base, _ := l.tag.Base()
	return base.String()
}

// T looks up key in this Localizer's catalog and, if args are supplied, formats
// the message with fmt.Sprintf. A key missing from the selected catalog falls
// back to the English catalog, then to the key itself.
func (l *Localizer) T(key string, args ...any) string {
	msg, ok := catalogs[l.tag][key]
	if !ok {
		msg, ok = catalogs[DefaultTag][key]
	}
	if !ok {
		msg = key
	}
	if len(args) == 0 {
		return msg
	}
	return fmt.Sprintf(msg, args...)
}
