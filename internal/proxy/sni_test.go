package proxy

import (
	"encoding/hex"
	"strings"
	"testing"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// syntheticHello returns a minimal but spec-valid TLS 1.2 ClientHello
// with a single SNI extension carrying name. Layout:
//
//	Record header: type=22, version=0x0301, length
//	Handshake header: type=1 (ClientHello), length
//	ClientHello body: version + random + sid_len(0) + cipher_suites_len(2) + cipher
//	                  + comp_methods_len(1) + comp_method(0) + extensions_len + SNI_extension
func syntheticHello(t *testing.T, name string) []byte {
	t.Helper()
	// SNI extension value
	var sni []byte
	listLen := 3 + len(name) // name_type(1) + name_length(2) + name
	sni = append(sni, byte(listLen>>8), byte(listLen))
	sni = append(sni, 0) // name_type = host_name
	sni = append(sni, byte(len(name)>>8), byte(len(name)))
	sni = append(sni, []byte(name)...)
	// Extension wrapper
	var ext []byte
	ext = append(ext, 0, 0) // type 0
	ext = append(ext, byte(len(sni)>>8), byte(len(sni)))
	ext = append(ext, sni...)
	// Extensions block
	var exts []byte
	exts = append(exts, byte(len(ext)>>8), byte(len(ext)))
	exts = append(exts, ext...)
	// ClientHello body
	var body []byte
	body = append(body, 0x03, 0x03)          // version 1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session_id_length
	body = append(body, 0, 2, 0x00, 0x35)    // cipher_suites_length=2 + 1 suite
	body = append(body, 1, 0)                // compression_methods_length=1, method 0
	body = append(body, exts...)
	// Handshake header
	hsLen := len(body)
	var hs []byte
	hs = append(hs, 0x01)
	hs = append(hs, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	hs = append(hs, body...)
	// Record header
	rLen := len(hs)
	var rec []byte
	rec = append(rec, 0x16)
	rec = append(rec, 0x03, 0x01)
	rec = append(rec, byte(rLen>>8), byte(rLen))
	rec = append(rec, hs...)
	return rec
}

func TestParseSNIHappyPath(t *testing.T) {
	hello := syntheticHello(t, "api.anthropic.com")
	host, err := parseSNI(hello)
	if err != nil {
		t.Fatalf("parseSNI: %v", err)
	}
	if host != "api.anthropic.com" {
		t.Errorf("got %q want %q", host, "api.anthropic.com")
	}
}

func TestParseSNIDifferentHostname(t *testing.T) {
	hello := syntheticHello(t, "api.openai.com")
	host, _ := parseSNI(hello)
	if host != "api.openai.com" {
		t.Errorf("got %q want %q", host, "api.openai.com")
	}
}

func TestParseSNINotATLSRecord(t *testing.T) {
	if _, err := parseSNI([]byte("not tls")); err == nil {
		t.Error("expected error on non-TLS bytes")
	}
}

func TestParseSNINotAHandshake(t *testing.T) {
	bytes := []byte{0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5}
	if _, err := parseSNI(bytes); err == nil {
		t.Error("expected error on non-handshake record")
	}
}

func TestParseSNINoExtension(t *testing.T) {
	// ClientHello with empty extensions block — ad-hoc bytes:
	// rec hdr (5) + hs hdr (4) + body (38: version 2 + random 32 + sid_len 1 + ciphers 2 (len) + 2 (suite) + comp 1 (len) + 1 (method) + ext_len 2 = 0)
	hello := mustHex("16 03 01 00 33 01 00 00 2f 03 03 " +
		"00000000000000000000000000000000" +
		"00000000000000000000000000000000" +
		"00 00 02 00 35 01 00 00 00")
	if _, err := parseSNI(hello); err == nil {
		t.Error("expected error when SNI extension is absent")
	}
}

func TestParseSNITruncated(t *testing.T) {
	hello := syntheticHello(t, "example.com")
	for i := 0; i < len(hello); i++ {
		if _, err := parseSNI(hello[:i]); err == nil {
			t.Errorf("expected error on truncation at byte %d", i)
		}
	}
}
