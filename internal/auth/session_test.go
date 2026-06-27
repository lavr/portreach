package auth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testKey(b byte) []byte {
	key := make([]byte, cookieKeyLen)
	for i := range key {
		key[i] = b
	}
	return key
}

func sampleSession() Session {
	return Session{
		User:     "alice",
		Name:     "Alice Example",
		Provider: "corp-gitlab",
		Groups:   []string{"infra", "sre"},
		Expiry:   time.Now().Add(time.Hour).Unix(),
	}
}

func TestSealOpenRoundtrip(t *testing.T) {
	key := testKey(1)
	in := sampleSession()
	token, err := seal(key, in)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	out, err := open(key, token, time.Now())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if out.User != in.User || out.Name != in.Name || out.Provider != in.Provider {
		t.Fatalf("roundtrip mismatch: got %+v want %+v", out, in)
	}
	if len(out.Groups) != len(in.Groups) {
		t.Fatalf("groups mismatch: got %v want %v", out.Groups, in.Groups)
	}
	for i := range in.Groups {
		if out.Groups[i] != in.Groups[i] {
			t.Fatalf("group %d: got %q want %q", i, out.Groups[i], in.Groups[i])
		}
	}
}

func TestOpenTamperedRejected(t *testing.T) {
	key := testKey(1)
	token, err := seal(key, sampleSession())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Flip a bit in the ciphertext (last byte, which is the auth tag region).
	raw[len(raw)-1] ^= 0x01
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := open(key, tampered, time.Now()); err == nil {
		t.Fatal("expected tampered token to be rejected")
	}
}

func TestOpenWrongKeyRejected(t *testing.T) {
	token, err := seal(testKey(1), sampleSession())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := open(testKey(2), token, time.Now()); err == nil {
		t.Fatal("expected wrong-key open to fail")
	}
}

func TestOpenExpiredRejected(t *testing.T) {
	key := testKey(1)
	s := sampleSession()
	s.Expiry = time.Now().Add(-time.Minute).Unix()
	token, err := seal(key, s)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	_, err = open(key, token, time.Now())
	if err != errSessionExpired {
		t.Fatalf("expected errSessionExpired, got %v", err)
	}
}

func TestOpenBadBase64Rejected(t *testing.T) {
	if _, err := open(testKey(1), "not!base64!!", time.Now()); err == nil {
		t.Fatal("expected bad base64 to be rejected")
	}
}

func TestNewGCMRejectsBadKeyLength(t *testing.T) {
	if _, err := newGCM(make([]byte, 16)); err == nil {
		t.Fatal("expected short key to be rejected")
	}
}

func TestSetSessionCookie(t *testing.T) {
	key := testKey(3)
	rec := httptest.NewRecorder()
	if err := setSessionCookie(rec, key, sampleSession()); err != nil {
		t.Fatalf("setSessionCookie: %v", err)
	}
	resp := rec.Result()
	var c *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookieName {
			c = ck
		}
	}
	if c == nil {
		t.Fatal("session cookie not set")
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Fatalf("cookie attributes wrong: %+v", c)
	}
	if c.MaxAge <= 0 {
		t.Fatalf("expected positive MaxAge, got %d", c.MaxAge)
	}
	// The cookie value must open back to the original session.
	if _, err := open(key, c.Value, time.Now()); err != nil {
		t.Fatalf("cookie value did not open: %v", err)
	}
}

func TestClearSessionCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	clearSessionCookie(rec)
	var c *http.Cookie
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == sessionCookieName {
			c = ck
		}
	}
	if c == nil {
		t.Fatal("clear cookie not set")
	}
	if c.MaxAge >= 0 {
		t.Fatalf("expected negative MaxAge to expire cookie, got %d", c.MaxAge)
	}
	if c.Value != "" {
		t.Fatalf("expected empty value, got %q", c.Value)
	}
}
