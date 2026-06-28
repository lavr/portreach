package auth

// LoginBranding customises operator-controlled HTML on auth pages. Title and
// Header are tri-state: nil keeps localized defaults; non-nil uses the value
// (including "" to suppress the heading, while the browser title falls back to
// a localized non-blank value). Footer is login-page only and omitted when empty.
type LoginBranding struct {
	Title  *string
	Header *string
	Footer string
}

// WithBranding sets login and denied-page branding.
func WithBranding(b LoginBranding) Option {
	return func(a *Authenticator) {
		a.branding = b
	}
}
