package licensing

// DevPublicKey is the ES256 public key used to verify license tokens.
// In production builds, replace this with your server's public key via
// -ldflags "-X ...licensing.DevPublicKey=..."
var DevPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER5z/3q3J2fD57euSiKDQYqI6n0Ma
FDlHE7Kh9crlOG9NyWs9O7HSvPMyfMJ9e2ap3xANvbmVIisQJwtid9XJTw==
-----END PUBLIC KEY-----`

// DemoToken is a pre-signed JWT that never expires (exp: 2099-12-31).
// It enables all features in demo mode. Customer: "demo".
//
// Claims: {"sub":"demo","features":["opf","premium_support"],"exp":4102444799,"demo":true}
var DemoToken = `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJkZW1vIjp0cnVlLCJleHAiOjQxMDI0NDQ3OTksImZlYXR1cmVzIjpbIm9wZiIsInByZW1pdW1fc3VwcG9ydCJdLCJpYXQiOjE3NzcyOTc3NjMsInN1YiI6ImRlbW8ifQ.kMpGWCiB3ePT4EWQEpYjHUAfU7-dkZYTj_vQQdtN-sgXMbwr50Asd82icEBsTpzYiUxWF3SXReaKBUfjCVykLA`
