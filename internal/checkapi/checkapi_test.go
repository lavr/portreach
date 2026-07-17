package checkapi

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDurationJSONRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		d    Duration
		want string
	}{
		{"seconds", Duration(5 * time.Second), `"5s"`},
		{"sub-second", Duration(250 * time.Millisecond), `"250ms"`},
		{"zero", Duration(0), `"0s"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.d)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(data) != tc.want {
				t.Fatalf("Marshal(%v) = %s, want %s", tc.d, data, tc.want)
			}
			var got Duration
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if got != tc.d {
				t.Fatalf("round-trip = %v, want %v", got, tc.d)
			}
		})
	}
}

func TestDurationUnmarshalEmptyString(t *testing.T) {
	var d Duration = 99
	if err := json.Unmarshal([]byte(`""`), &d); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if d != 0 {
		t.Fatalf("empty string should decode to 0, got %v", d)
	}
}

func TestDurationUnmarshalInvalid(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`"not-a-duration"`), &d); err == nil {
		t.Fatal("expected an error for an invalid duration string")
	}
	if err := json.Unmarshal([]byte(`5`), &d); err == nil {
		t.Fatal("expected an error for a bare-number duration (not a JSON string)")
	}
}

func TestTCPCheckRequestJSONRoundTrip(t *testing.T) {
	req := TCPCheckRequest{Host: "example.com", Port: 5432, Timeout: Duration(5 * time.Second)}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"host":"example.com","port":5432,"timeout":"5s"}`
	if string(data) != want {
		t.Fatalf("Marshal() = %s, want %s", data, want)
	}
	var got TCPCheckRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got != req {
		t.Fatalf("round-trip = %+v, want %+v", got, req)
	}
}

func TestPostgresCheckRequestJSONRoundTrip(t *testing.T) {
	enabled := false
	req := PostgresCheckRequest{
		Host:        "db.internal",
		Port:        5432,
		Timeout:     Duration(10 * time.Second),
		Credentials: Credentials{Username: "app", Password: "hunter2", Database: "appdb"},
		TLS:         &TLSOptions{Enabled: &enabled, ServerName: "db.internal", InsecureSkipVerify: true},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got PostgresCheckRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Host != req.Host || got.Port != req.Port || got.Timeout != req.Timeout {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, req)
	}
	if got.Credentials != req.Credentials {
		t.Fatalf("credentials round-trip mismatch: got %+v, want %+v", got.Credentials, req.Credentials)
	}
	if got.TLS == nil || *got.TLS.Enabled != false || got.TLS.ServerName != "db.internal" || !got.TLS.InsecureSkipVerify {
		t.Fatalf("TLS round-trip mismatch: got %+v", got.TLS)
	}
}

func TestPostgresCheckRequestOmitsTLSWhenNil(t *testing.T) {
	req := PostgresCheckRequest{Host: "db.internal", Port: 5432, Credentials: Credentials{Username: "app", Password: "x"}}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(data), `"tls"`) {
		t.Fatalf("expected no tls key when TLS is nil, got %s", data)
	}
}

func TestValidateHostPort(t *testing.T) {
	cases := []struct {
		name    string
		host    string
		port    int
		wantErr bool
	}{
		{"valid", "example.com", 5432, false},
		{"empty host", "", 5432, true},
		{"blank host", "   ", 5432, true},
		{"port zero", "example.com", 0, true},
		{"port negative", "example.com", -1, true},
		{"port too large", "example.com", 65536, true},
		{"port min boundary", "example.com", 1, false},
		{"port max boundary", "example.com", 65535, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHostPort(tc.host, tc.port)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateHostPort(%q, %d) error = %v, wantErr %v", tc.host, tc.port, err, tc.wantErr)
			}
		})
	}
}

func TestCredentialsValidate(t *testing.T) {
	cases := []struct {
		name    string
		creds   Credentials
		wantErr bool
	}{
		{"valid with database", Credentials{Username: "app", Password: "x", Database: "appdb"}, false},
		{"valid without database", Credentials{Username: "app", Password: "x"}, false},
		{"missing username", Credentials{Password: "x"}, true},
		{"blank username", Credentials{Username: "  ", Password: "x"}, true},
		{"missing password", Credentials{Username: "app"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.creds.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestTCPCheckRequestValidate(t *testing.T) {
	if err := (TCPCheckRequest{Host: "example.com", Port: 80}).Validate(); err != nil {
		t.Fatalf("expected valid request to pass, got %v", err)
	}
	if err := (TCPCheckRequest{Port: 80}).Validate(); err == nil {
		t.Fatal("expected missing host to fail validation")
	}
}

func TestPostgresCheckRequestValidate(t *testing.T) {
	valid := PostgresCheckRequest{Host: "db", Port: 5432, Credentials: Credentials{Username: "app", Password: "x"}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid request to pass, got %v", err)
	}

	noHost := valid
	noHost.Host = ""
	if err := noHost.Validate(); err == nil {
		t.Fatal("expected missing host to fail validation")
	}

	noCreds := valid
	noCreds.Credentials = Credentials{}
	if err := noCreds.Validate(); err == nil {
		t.Fatal("expected missing credentials to fail validation")
	}
}

func TestNormalizeTimeout(t *testing.T) {
	cases := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"zero becomes default", 0, DefaultTimeout},
		{"negative becomes default", -5 * time.Second, DefaultTimeout},
		{"within bounds unchanged", 10 * time.Second, 10 * time.Second},
		{"over max clamped", time.Hour, MaxTimeout},
		{"exactly max unchanged", MaxTimeout, MaxTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeTimeout(tc.in); got != tc.want {
				t.Fatalf("NormalizeTimeout(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// The checkapi<->probe timeout-bounds parity invariant is enforced by
// TestCheckAPITimeoutBoundsMatch in internal/probe: since internal/probe now
// imports internal/checkapi (probe.Result.Auth is a checkapi.AuthResult), the
// parity check must live on the probe side to avoid an import cycle. See that
// test for the "values must match" guarantee.

func TestEffectiveTimeout(t *testing.T) {
	tcpReq := TCPCheckRequest{Host: "h", Port: 1, Timeout: Duration(time.Hour)}
	if got := tcpReq.EffectiveTimeout(); got != MaxTimeout {
		t.Fatalf("TCPCheckRequest.EffectiveTimeout() = %v, want %v", got, MaxTimeout)
	}

	pgReq := PostgresCheckRequest{Host: "h", Port: 1}
	if got := pgReq.EffectiveTimeout(); got != DefaultTimeout {
		t.Fatalf("PostgresCheckRequest.EffectiveTimeout() = %v, want %v", got, DefaultTimeout)
	}
}

func TestResolveTLSDefaults(t *testing.T) {
	// Absent block entirely: TLS on, server name defaults to host.
	got := ResolveTLS(nil, "db.example.com")
	want := ResolvedTLS{Enabled: true, ServerName: "db.example.com"}
	if got != want {
		t.Fatalf("ResolveTLS(nil, host) = %+v, want %+v", got, want)
	}
}

func TestResolveTLSEmptyOptions(t *testing.T) {
	// Present but empty block: same defaults as nil (nil Enabled -> on, empty
	// ServerName -> host).
	got := ResolveTLS(&TLSOptions{}, "db.example.com")
	want := ResolvedTLS{Enabled: true, ServerName: "db.example.com"}
	if got != want {
		t.Fatalf("ResolveTLS(&TLSOptions{}, host) = %+v, want %+v", got, want)
	}
}

func TestResolveTLSExplicitDisable(t *testing.T) {
	disabled := false
	got := ResolveTLS(&TLSOptions{Enabled: &disabled}, "db.example.com")
	if got.Enabled {
		t.Fatalf("expected TLS disabled when Enabled points to false, got %+v", got)
	}
}

func TestResolveTLSCustomServerName(t *testing.T) {
	got := ResolveTLS(&TLSOptions{ServerName: "override.example.com"}, "db.example.com")
	if got.ServerName != "override.example.com" {
		t.Fatalf("expected explicit ServerName to win, got %q", got.ServerName)
	}
	if !got.Enabled {
		t.Fatal("expected Enabled to still default true")
	}
}

func TestResolveTLSInsecureSkipVerifyPassthrough(t *testing.T) {
	got := ResolveTLS(&TLSOptions{InsecureSkipVerify: true}, "db.example.com")
	if !got.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify to pass through")
	}
}

func TestEffectiveTLS(t *testing.T) {
	req := PostgresCheckRequest{Host: "db.example.com", Port: 5432}
	got := req.EffectiveTLS()
	want := ResolvedTLS{Enabled: true, ServerName: "db.example.com"}
	if got != want {
		t.Fatalf("EffectiveTLS() = %+v, want %+v", got, want)
	}
}

// responseTypes lists every response-shaped type this package defines. The
// test below enforces that none of them ever grows a password field — add new
// response types here as they're introduced.
var responseTypes = []any{
	AuthResult{},
}

// TestResponseTypesNeverCarryPassword is the structural half of the no-leak
// guarantee: it walks each response type's fields — descending through nested
// structs, pointers, slices, arrays, and map values — and fails if any field
// name or JSON tag looks like a password. This catches the mistake at the
// type-definition level, before a single value is ever marshaled.
func TestResponseTypesNeverCarryPassword(t *testing.T) {
	for _, rt := range responseTypes {
		for _, finding := range findPasswordFields(reflect.TypeOf(rt), map[reflect.Type]bool{}) {
			t.Errorf("%s: response types must never carry a password", finding)
		}
	}
}

// findPasswordFields recursively inspects typ and returns a description of
// every field whose name or JSON tag looks like a password. Container kinds
// (pointer, slice, array, map) are unwrapped to their element type before the
// struct check, so a `*TLSOptions`-style pointer field — the shape this
// package already uses — or a slice/map of structs cannot smuggle a password
// field past the guard. seen breaks cycles in self-referential types.
func findPasswordFields(typ reflect.Type, seen map[reflect.Type]bool) []string {
	for {
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
			// JSON object keys are strings, so for maps only the value type
			// can carry a struct field.
			typ = typ.Elem()
			continue
		}
		break
	}
	if typ.Kind() != reflect.Struct || seen[typ] {
		return nil
	}
	seen[typ] = true
	var findings []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if strings.EqualFold(tag, "password") || strings.Contains(strings.ToLower(f.Name), "password") {
			findings = append(findings, fmt.Sprintf("%s.%s (json tag %q)", typ.Name(), f.Name, tag))
		}
		findings = append(findings, findPasswordFields(f.Type, seen)...)
	}
	return findings
}

// TestFindPasswordFieldsDescendsContainers is a self-test of the guard: a
// password hidden behind a pointer, slice, or map field must still be found,
// otherwise the guard would silently pass future leaky response types.
func TestFindPasswordFieldsDescendsContainers(t *testing.T) {
	type leaky struct {
		Password string `json:"password"`
	}
	cases := []struct {
		name string
		typ  reflect.Type
	}{
		{"pointer", reflect.TypeOf(struct{ Inner *leaky }{})},
		{"slice", reflect.TypeOf(struct{ Inner []leaky }{})},
		{"map value", reflect.TypeOf(struct{ Inner map[string]leaky }{})},
		{"pointer slice", reflect.TypeOf(struct{ Inner []*leaky }{})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := findPasswordFields(tc.typ, map[reflect.Type]bool{}); len(got) == 0 {
				t.Fatalf("guard failed to find the password field behind a %s", tc.name)
			}
		})
	}
	// A self-referential type must terminate, not recurse forever.
	type node struct {
		Next *node `json:"next,omitempty"`
	}
	if got := findPasswordFields(reflect.TypeOf(node{}), map[reflect.Type]bool{}); len(got) != 0 {
		t.Fatalf("expected no findings on a clean cyclic type, got %v", got)
	}
}

// canaryPassword is a distinctive value planted into any password-shaped
// field by populateWithCanary; the behavioural test below asserts it never
// reaches marshaled response bytes.
const canaryPassword = "canary-hunter2-canary"

// populateWithCanary recursively fills v with non-zero values so omitempty
// cannot hide a field from the marshal: password-shaped string fields get
// canaryPassword, every other string a benign value, and pointers, slices,
// and maps are allocated and populated one element deep. seen breaks cycles.
func populateWithCanary(v reflect.Value, isPassword bool, seen map[reflect.Type]bool) {
	switch v.Kind() {
	case reflect.String:
		if isPassword {
			v.SetString(canaryPassword)
		} else {
			v.SetString("value")
		}
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1.5)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		populateWithCanary(v.Elem(), isPassword, seen)
	case reflect.Slice:
		elem := reflect.New(v.Type().Elem()).Elem()
		populateWithCanary(elem, isPassword, seen)
		v.Set(reflect.Append(reflect.MakeSlice(v.Type(), 0, 1), elem))
	case reflect.Map:
		elem := reflect.New(v.Type().Elem()).Elem()
		populateWithCanary(elem, isPassword, seen)
		m := reflect.MakeMap(v.Type())
		m.SetMapIndex(reflect.ValueOf("key").Convert(v.Type().Key()), elem)
		v.Set(m)
	case reflect.Struct:
		if seen[v.Type()] {
			return
		}
		seen[v.Type()] = true
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() {
				continue
			}
			tag := strings.Split(f.Tag.Get("json"), ",")[0]
			pw := strings.EqualFold(tag, "password") || strings.Contains(strings.ToLower(f.Name), "password")
			populateWithCanary(v.Field(i), pw, seen)
		}
	}
}

// TestResponseTypesJSONNeverContainsPassword is the behavioural half of the
// no-leak guarantee, driven by the same responseTypes registry as the
// structural test: every registered response type is fully populated (any
// password-shaped field anywhere in it would receive canaryPassword), then
// marshaled, and the canary must never reach the wire bytes. Combined with
// TestResponseTypesNeverCarryPassword this guards both the type definition
// and the actual bytes sent on the wire, and both tests scale together as
// types are added to the registry.
func TestResponseTypesJSONNeverContainsPassword(t *testing.T) {
	for _, rt := range responseTypes {
		typ := reflect.TypeOf(rt)
		t.Run(typ.Name(), func(t *testing.T) {
			v := reflect.New(typ).Elem()
			populateWithCanary(v, false, map[reflect.Type]bool{})
			data, err := json.Marshal(v.Interface())
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if strings.Contains(string(data), canaryPassword) {
				t.Fatalf("%s JSON must never contain a password value, got %s", typ.Name(), data)
			}
		})
	}
	// Negative control proving the harness catches a leak: Credentials (the
	// request-only type that legitimately carries a password) must trip it.
	v := reflect.New(reflect.TypeOf(Credentials{})).Elem()
	populateWithCanary(v, false, map[reflect.Type]bool{})
	data, err := json.Marshal(v.Interface())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), canaryPassword) {
		t.Fatalf("harness self-check failed: canary not planted into Credentials.Password, got %s", data)
	}
}

func TestAuthCodeConstants(t *testing.T) {
	// The code set is part of the stable wire contract; pin the literal
	// strings so a rename is caught here rather than by a client parsing them.
	want := map[string]string{
		"CodeAuthRejected":    "auth_rejected",
		"CodeUnsupportedAuth": "unsupported_auth",
		"CodeTLSError":        "tls_error",
		"CodeProtocolError":   "protocol_error",
		"CodeQueryFailed":     "query_failed",
	}
	got := map[string]string{
		"CodeAuthRejected":    CodeAuthRejected,
		"CodeUnsupportedAuth": CodeUnsupportedAuth,
		"CodeTLSError":        CodeTLSError,
		"CodeProtocolError":   CodeProtocolError,
		"CodeQueryFailed":     CodeQueryFailed,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("auth code constants changed: got %v, want %v", got, want)
	}
}

func TestAuthResultJSONTags(t *testing.T) {
	ar := AuthResult{OK: true, ServerVersion: "PostgreSQL 16.1", MS: 1.5}
	data, err := json.Marshal(ar)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{"ok", "server_version", "ms"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("expected key %q in AuthResult JSON, got %v", key, m)
		}
	}
	// code/reason are omitempty and empty on success, so they should be absent.
	for _, key := range []string{"code", "reason"} {
		if _, ok := m[key]; ok {
			t.Fatalf("expected key %q to be omitted on success, got %v", key, m)
		}
	}
}
