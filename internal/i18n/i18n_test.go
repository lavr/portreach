package i18n

import (
	"net/http/httptest"
	"testing"

	"golang.org/x/text/language"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		want   language.Tag
	}{
		{"empty defaults to en", "", language.English},
		{"whitespace defaults to en", "   ", language.English},
		{"explicit ru", "ru", language.Russian},
		{"regional ru-RU", "ru-RU", language.Russian},
		{"ru with quality", "ru-RU,ru;q=0.9,en;q=0.8", language.Russian},
		{"explicit en", "en-US", language.English},
		{"unknown falls back to en", "fr-FR,fr;q=0.9", language.English},
		{"garbage falls back to en", "!!!not a language!!!", language.English},
		{"en preferred over ru by quality", "en;q=0.9,ru;q=0.1", language.English},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Match(tt.accept)
			if got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.accept, got, tt.want)
			}
		})
	}
}

func TestT_Lookup(t *testing.T) {
	en := NewLocalizer(language.English)
	ru := NewLocalizer(language.Russian)

	if got := en.T("form.host"); got != "host" {
		t.Errorf("en form.host = %q, want %q", got, "host")
	}
	if got := ru.T("form.host"); got != "хост" {
		t.Errorf("ru form.host = %q, want %q", got, "хост")
	}
}

func TestT_Format(t *testing.T) {
	en := NewLocalizer(language.English)
	got := en.T("result.summary", "3", "5", "db", "5432", "tcp")
	want := "3/5 agents reached db:5432/tcp"
	if got != want {
		t.Errorf("summary = %q, want %q", got, want)
	}
	ru := NewLocalizer(language.Russian)
	got = ru.T("result.summary", "3", "5", "db", "5432", "tcp")
	want = "3/5 агентов достигли db:5432/tcp"
	if got != want {
		t.Errorf("ru summary = %q, want %q", got, want)
	}
}

func TestT_FallbackToEnglish(t *testing.T) {
	// Simulate a key present in en but (hypothetically) absent in ru by using a
	// Localizer whose catalog lacks the key. ru.json is exhaustive, so instead
	// verify fallback path via an unsupported tag.
	fr := NewLocalizer(language.French) // no catalog → falls back to en
	if got := fr.T("form.check"); got != "check" {
		t.Errorf("french fallback form.check = %q, want en %q", got, "check")
	}
}

func TestT_FallbackToKey(t *testing.T) {
	en := NewLocalizer(language.English)
	if got := en.T("does.not.exist"); got != "does.not.exist" {
		t.Errorf("missing key = %q, want the key itself", got)
	}
}

func TestAllEnglishKeysPresentInRussian(t *testing.T) {
	en := catalogs[language.English]
	ru := catalogs[language.Russian]
	if len(en) == 0 {
		t.Fatal("english catalog is empty")
	}
	for key := range en {
		if _, ok := ru[key]; !ok {
			t.Errorf("ru catalog missing key %q", key)
		}
	}
	// And no stray ru keys that lack an en counterpart.
	for key := range ru {
		if _, ok := en[key]; !ok {
			t.Errorf("ru catalog has key %q absent from en", key)
		}
	}
}

func TestLang(t *testing.T) {
	if got := NewLocalizer(language.Russian).Lang(); got != "ru" {
		t.Errorf("ru Lang() = %q, want ru", got)
	}
	if got := NewLocalizer(language.English).Lang(); got != "en" {
		t.Errorf("en Lang() = %q, want en", got)
	}
}

func TestFromRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Language", "ru-RU,ru;q=0.9")
	if got := FromRequest(r).Tag(); got != language.Russian {
		t.Errorf("FromRequest tag = %v, want ru", got)
	}

	r2 := httptest.NewRequest("GET", "/", nil) // no header
	if got := FromRequest(r2).Tag(); got != language.English {
		t.Errorf("FromRequest no-header tag = %v, want en", got)
	}
}
