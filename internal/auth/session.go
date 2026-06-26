package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Session cookie names.
const (
	// sessionCookieName holds the sealed authenticated session.
	sessionCookieName = "portreach_session"
)

// sessionMaxAge bounds how long a sealed session cookie is accepted. The sealed
// payload also carries its own Expiry; both must hold for the session to be
// valid.
const sessionMaxAge = 12 * time.Hour

// errSessionExpired is returned by open when the sealed session has expired.
var errSessionExpired = errors.New("auth: session expired")

// Session is the stateless payload sealed into the session cookie. It is the
// only server-side record of who the user is: there is no session store.
type Session struct {
	User     string   `json:"user"`
	Name     string   `json:"name"`
	Provider string   `json:"provider"`
	Groups   []string `json:"groups,omitempty"`
	Expiry   int64    `json:"exp"`
}

// Expired reports whether the session is past its Expiry (Unix seconds).
func (s Session) Expired(now time.Time) bool {
	return s.Expiry != 0 && now.Unix() >= s.Expiry
}

// sealBytes encrypts plaintext with AES-256-GCM under key, returning a base64url
// (no padding) token of nonce||ciphertext. key must be 32 bytes. It is the
// shared primitive behind both the session cookie and the short-lived OAuth
// state cookie.
func sealBytes(key, plaintext []byte) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("auth: nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// openBytes decodes and decrypts a token produced by sealBytes, verifying the
// GCM authentication tag. It does not interpret the plaintext.
func openBytes(key []byte, token string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("auth: decode token: %w", err)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("auth: token too short")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("auth: authentication failed: %w", err)
	}
	return plaintext, nil
}

// seal serializes s and encrypts it with AES-256-GCM under key, returning a
// base64url (no padding) token. key must be 32 bytes.
func seal(key []byte, s Session) (string, error) {
	plaintext, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("auth: marshal session: %w", err)
	}
	return sealBytes(key, plaintext)
}

// open decodes and decrypts a token produced by seal, verifying the GCM
// authentication tag and rejecting expired sessions. now is the reference time
// for expiry (typically time.Now()).
func open(key []byte, token string, now time.Time) (Session, error) {
	var s Session
	plaintext, err := openBytes(key, token)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(plaintext, &s); err != nil {
		return s, fmt.Errorf("auth: unmarshal session: %w", err)
	}
	if s.Expired(now) {
		return s, errSessionExpired
	}
	return s, nil
}

// newGCM constructs an AES-256-GCM AEAD from a 32-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != cookieKeyLen {
		return nil, fmt.Errorf("auth: cookie key must be %d bytes, got %d", cookieKeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("auth: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("auth: new gcm: %w", err)
	}
	return gcm, nil
}

// setSessionCookie seals s under key and writes it as the session cookie.
func setSessionCookie(w http.ResponseWriter, key []byte, s Session) error {
	token, err := seal(key, s)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionMaxAge.Seconds()),
	})
	return nil
}

// clearSessionCookie expires the session cookie.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
