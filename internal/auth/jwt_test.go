package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
)

// signJWT builds a compact RS256 JWT from the given claims, signed with key and
// tagged with kid "test-key" to match the JWKS served by the fake issuer.
func signJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "test-key"})
	payload, _ := json.Marshal(claims)
	signingInput := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return signingInput + "." + enc.EncodeToString(sig)
}

// jwksJSON renders a single-key JWKS document exposing key's RSA public part.
func jwksJSON(key *rsa.PrivateKey) string {
	enc := base64.RawURLEncoding
	n := enc.EncodeToString(key.N.Bytes())
	e := enc.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"test-key","n":%q,"e":%q}]}`, n, e)
}
