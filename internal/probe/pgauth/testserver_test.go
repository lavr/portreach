package pgauth

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

// fakePG is a minimal in-process PostgreSQL server speaking just enough of the
// v3 wire protocol to drive one Connector outcome. It uses trust authentication
// (AuthenticationOk with no password exchange) deliberately: these tests prove
// the Connector's connect/Exec plumbing, not SCRAM — pgauth delegates the crypto
// to pgconn, whose own suite covers it. A real end-to-end handshake (SCRAM, TLS
// verify) lives in the //go:build e2e suite against a real server.
type fakePG struct {
	serverVersion string // reported via ParameterStatus (default "16.0")
	rejectAuth    bool   // answer the startup with an ErrorResponse (→ auth_rejected)
	failQuery     bool   // answer SELECT 1 with an ErrorResponse (→ query_failed)
	refuseSSL     bool   // answer 'N' to SSLRequest (→ tls_error when TLS required)
}

// PostgreSQL wire constants used by the fake.
const (
	pgSSLRequestCode uint32 = 80877103

	pgMsgAuth        byte = 'R'
	pgMsgParamStatus byte = 'S'
	pgMsgBackendKey  byte = 'K'
	pgMsgReadyForQ   byte = 'Z'
	pgMsgRowDesc     byte = 'T'
	pgMsgDataRow     byte = 'D'
	pgMsgCmdComplete byte = 'C'
	pgMsgErrorResp   byte = 'E'
	pgMsgQuery       byte = 'Q'
)

// startFakePG binds a loopback listener serving one goroutine per accept and
// returns the dial host and port. The listener closes on test cleanup.
func startFakePG(t *testing.T, s fakePG) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

func (s fakePG) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)

	// The first 8 bytes are either an SSLRequest (len=8, magic code) or the start
	// of a StartupMessage (len, then protocol version). A plaintext client sends a
	// StartupMessage directly; a TLS client sends an SSLRequest first.
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(hdr[0:4])
	if binary.BigEndian.Uint32(hdr[4:8]) == pgSSLRequestCode {
		// We only model SSL refusal here (a valid TLS accept needs certs and is
		// covered by the e2e suite). Refusing with 'N' makes a TLS-required client
		// fail closed — pgconn does not fall back to plaintext (Fallbacks nil).
		_, _ = conn.Write([]byte{'N'})
		return
	}
	// StartupMessage: consume its remaining body (length counts the 4 length
	// bytes; we have already read 8).
	if rest := int(length) - 8; rest > 0 {
		if _, err := io.ReadFull(br, make([]byte, rest)); err != nil {
			return
		}
	}

	if s.rejectAuth {
		pgWriteMsg(conn, pgMsgErrorResp, pgErrResp("28P01", "password authentication failed"))
		return
	}

	// Trust auth: AuthenticationOk, a server_version ParameterStatus, backend key,
	// then ReadyForQuery.
	pgWriteMsg(conn, pgMsgAuth, pgBe32(0))
	sv := s.serverVersion
	if sv == "" {
		sv = "16.0"
	}
	pgWriteMsg(conn, pgMsgParamStatus, pgCStrings("server_version", sv))
	pgWriteMsg(conn, pgMsgBackendKey, make([]byte, 8))
	pgWriteMsg(conn, pgMsgReadyForQ, []byte{'I'})

	// The SELECT 1 simple query.
	typ, _, err := pgReadMsg(br)
	if err != nil || typ != pgMsgQuery {
		return
	}
	if s.failQuery {
		pgWriteMsg(conn, pgMsgErrorResp, pgErrResp("42601", "syntax error"))
		pgWriteMsg(conn, pgMsgReadyForQ, []byte{'I'})
	} else {
		pgWriteMsg(conn, pgMsgRowDesc, pgRowDesc1())
		pgWriteMsg(conn, pgMsgDataRow, pgDataRow1())
		pgWriteMsg(conn, pgMsgCmdComplete, pgCString("SELECT 1"))
		pgWriteMsg(conn, pgMsgReadyForQ, []byte{'I'})
	}
	// Drain until the client closes (it sends Terminate, then closes the socket).
	_, _ = io.Copy(io.Discard, br)
}

// --- framing helpers ----------------------------------------------------------

func pgWriteMsg(w net.Conn, typ byte, payload []byte) {
	buf := make([]byte, 5+len(payload))
	buf[0] = typ
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)+4))
	copy(buf[5:], payload)
	_, _ = w.Write(buf)
}

func pgReadMsg(br *bufio.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[1:5])) - 4
	if n < 0 {
		n = 0
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(br, payload); err != nil {
		return 0, nil, err
	}
	return hdr[0], payload, nil
}

func pgBe32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func pgCString(s string) []byte { return append([]byte(s), 0) }

func pgCStrings(ss ...string) []byte {
	var out []byte
	for _, s := range ss {
		out = append(out, s...)
		out = append(out, 0)
	}
	return out
}

// pgErrResp builds an ErrorResponse payload: (field-type, cstring) pairs then a
// terminating zero byte. Only SQLSTATE ('C') and message ('M') are surfaced.
func pgErrResp(code, message string) []byte {
	out := []byte{'S'}
	out = append(out, pgCString("ERROR")...)
	out = append(out, 'C')
	out = append(out, pgCString(code)...)
	out = append(out, 'M')
	out = append(out, pgCString(message)...)
	return append(out, 0)
}

// pgRowDesc1 describes a single int4 text column named "?column?".
func pgRowDesc1() []byte {
	out := binary.BigEndian.AppendUint16(nil, 1) // field count
	out = append(out, pgCString("?column?")...)
	out = binary.BigEndian.AppendUint32(out, 0)          // table OID
	out = binary.BigEndian.AppendUint16(out, 0)          // column attr
	out = binary.BigEndian.AppendUint32(out, 23)         // type OID (int4)
	out = binary.BigEndian.AppendUint16(out, 4)          // type size
	out = binary.BigEndian.AppendUint32(out, ^uint32(0)) // type modifier (-1)
	out = binary.BigEndian.AppendUint16(out, 0)          // format (text)
	return out
}

// pgDataRow1 is a single row with one column holding the text "1".
func pgDataRow1() []byte {
	out := binary.BigEndian.AppendUint16(nil, 1) // column count
	out = binary.BigEndian.AppendUint32(out, 1)  // value length
	return append(out, '1')
}
