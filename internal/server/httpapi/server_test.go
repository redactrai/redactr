package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redactrai/redactr/internal/control"
	"github.com/redactrai/redactr/internal/server/auth"
	"github.com/redactrai/redactr/internal/server/imagebuild"
	"github.com/redactrai/redactr/internal/server/store"
	"github.com/redactrai/redactr/internal/signing"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := New(st, auth.NewSigner(priv), "admin-key")
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts
}

func postJSON(t *testing.T, ts *httptest.Server, path, adminKey string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader(b))
	if adminKey != "" {
		req.Header.Set("X-Admin-Key", adminKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestEnrollWhoamiRevokeFlow(t *testing.T) {
	ts := newTestServer(t)

	resp := postJSON(t, ts, "/admin/orgs", "admin-key", map[string]string{"name": "Acme"})
	var org struct {
		ID string `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&org)
	resp.Body.Close()
	if org.ID == "" {
		t.Fatal("no org id")
	}

	resp = postJSON(t, ts, "/admin/orgs/"+org.ID+"/enrollment-tokens", "admin-key",
		map[string]int{"expires_in_hours": 1, "max_uses": 1})
	var mint struct {
		Token string `json:"token"`
	}
	json.NewDecoder(resp.Body).Decode(&mint)
	resp.Body.Close()
	if mint.Token == "" {
		t.Fatal("no enrollment token")
	}

	resp = postJSON(t, ts, "/v1/enroll", "",
		map[string]string{"enrollment_token": mint.Token, "device_name": "laptop", "platform": "darwin"})
	var enrRaw map[string]string
	json.NewDecoder(resp.Body).Decode(&enrRaw)
	resp.Body.Close()
	if resp.StatusCode != 200 || enrRaw["token"] == "" {
		t.Fatalf("enroll code=%d body=%v", resp.StatusCode, enrRaw)
	}

	req, _ := http.NewRequest("GET", ts.URL+"/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+enrRaw["token"])
	who, _ := http.DefaultClient.Do(req)
	if who.StatusCode != 200 {
		t.Fatalf("whoami code = %d, want 200", who.StatusCode)
	}
	who.Body.Close()

	rv := postJSON(t, ts, "/admin/devices/"+enrRaw["device_id"]+"/revoke", "admin-key", nil)
	rv.Body.Close()
	req2, _ := http.NewRequest("GET", ts.URL+"/v1/whoami", nil)
	req2.Header.Set("Authorization", "Bearer "+enrRaw["token"])
	who2, _ := http.DefaultClient.Do(req2)
	if who2.StatusCode != 401 {
		t.Fatalf("post-revoke whoami code = %d, want 401", who2.StatusCode)
	}
	who2.Body.Close()
}

func TestAdminKeyRequired(t *testing.T) {
	ts := newTestServer(t)
	resp := postJSON(t, ts, "/admin/orgs", "", map[string]string{"name": "X"})
	if resp.StatusCode != 401 {
		t.Errorf("no-admin-key code = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestPolicyDistribution(t *testing.T) {
	ts := newTestServer(t)

	r := postJSON(t, ts, "/admin/orgs", "admin-key", map[string]string{"name": "Acme"})
	var org struct {
		ID string `json:"id"`
	}
	json.NewDecoder(r.Body).Decode(&org)
	r.Body.Close()
	r = postJSON(t, ts, "/admin/orgs/"+org.ID+"/enrollment-tokens", "admin-key", map[string]int{"max_uses": 0})
	var mint struct {
		Token string `json:"token"`
	}
	json.NewDecoder(r.Body).Decode(&mint)
	r.Body.Close()
	r = postJSON(t, ts, "/v1/enroll", "", map[string]string{"enrollment_token": mint.Token, "device_name": "d", "platform": "darwin"})
	var enr map[string]string
	json.NewDecoder(r.Body).Decode(&enr)
	r.Body.Close()
	if enr["server_public_key"] == "" {
		t.Fatal("enroll response missing server_public_key")
	}

	req, _ := http.NewRequest("PUT", ts.URL+"/admin/orgs/"+org.ID+"/policy", bytes.NewReader([]byte(`{"image":"redactr-base:v9","mountMode":"bind","denylist":["evil.test"]}`)))
	req.Header.Set("X-Admin-Key", "admin-key")
	pr, _ := http.DefaultClient.Do(req)
	pr.Body.Close()

	greq, _ := http.NewRequest("GET", ts.URL+"/v1/policy", nil)
	greq.Header.Set("Authorization", "Bearer "+enr["token"])
	gresp, _ := http.DefaultClient.Do(greq)
	if gresp.StatusCode != 200 {
		t.Fatalf("/v1/policy code = %d", gresp.StatusCode)
	}
	etag := gresp.Header.Get("ETag")
	var sp struct {
		Bundle, Signature string
		Version           int
	}
	json.NewDecoder(gresp.Body).Decode(&sp)
	gresp.Body.Close()
	if sp.Version != 1 || etag == "" {
		t.Fatalf("version=%d etag=%q", sp.Version, etag)
	}
	pub, err := signing.ParsePublicKeyPEM(enr["server_public_key"])
	if err != nil {
		t.Fatalf("parse pubkey: %v", err)
	}
	bundleJSON, _ := base64.RawURLEncoding.DecodeString(sp.Bundle)
	if err := signing.Verify(pub, bundleJSON, sp.Signature); err != nil {
		t.Fatalf("bundle signature: %v", err)
	}
	if !bytes.Contains(bundleJSON, []byte("redactr-base:v9")) {
		t.Errorf("bundle = %s", bundleJSON)
	}

	greq2, _ := http.NewRequest("GET", ts.URL+"/v1/policy", nil)
	greq2.Header.Set("Authorization", "Bearer "+enr["token"])
	greq2.Header.Set("If-None-Match", etag)
	g2, _ := http.DefaultClient.Do(greq2)
	if g2.StatusCode != 304 {
		t.Errorf("If-None-Match code = %d, want 304", g2.StatusCode)
	}
	g2.Body.Close()

	sk, _ := http.Get(ts.URL + "/v1/server-key")
	var skBody struct {
		PublicKey string `json:"public_key"`
	}
	json.NewDecoder(sk.Body).Decode(&skBody)
	sk.Body.Close()
	if skBody.PublicKey == "" {
		t.Error("server-key empty")
	}
}

func TestGetAdminPolicyUnknownOrg404(t *testing.T) {
	ts := newTestServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/admin/orgs/does-not-exist/policy", nil)
	req.Header.Set("X-Admin-Key", "admin-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("unknown-org admin policy = %d, want 404", resp.StatusCode)
	}
}

func TestEventIngestionAndAdminRead(t *testing.T) {
	ts := newTestServer(t)
	r := postJSON(t, ts, "/admin/orgs", "admin-key", map[string]string{"name": "Acme"})
	var org struct {
		ID string `json:"id"`
	}
	json.NewDecoder(r.Body).Decode(&org)
	r.Body.Close()
	r = postJSON(t, ts, "/admin/orgs/"+org.ID+"/enrollment-tokens", "admin-key", map[string]int{"max_uses": 0})
	var mint struct {
		Token string `json:"token"`
	}
	json.NewDecoder(r.Body).Decode(&mint)
	r.Body.Close()
	r = postJSON(t, ts, "/v1/enroll", "", map[string]string{"enrollment_token": mint.Token, "device_name": "d", "platform": "darwin"})
	var enr map[string]string
	json.NewDecoder(r.Body).Decode(&enr)
	r.Body.Close()

	body := map[string]any{"events": []map[string]any{
		{"tool": "Claude Code", "verdict": "runaway", "reason": "direct", "direct_conn_count": 1, "observed_at": "2026-01-01T00:00:00Z"},
	}}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/events", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+enr["token"])
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("POST /v1/events code = %d", resp.StatusCode)
	}
	resp.Body.Close()

	req2, _ := http.NewRequest("POST", ts.URL+"/v1/events", bytes.NewReader(b))
	u, _ := http.DefaultClient.Do(req2)
	if u.StatusCode != 401 {
		t.Errorf("unauth events code = %d, want 401", u.StatusCode)
	}
	u.Body.Close()

	areq, _ := http.NewRequest("GET", ts.URL+"/admin/orgs/"+org.ID+"/events?limit=10", nil)
	areq.Header.Set("X-Admin-Key", "admin-key")
	ar, _ := http.DefaultClient.Do(areq)
	var evs []map[string]any
	json.NewDecoder(ar.Body).Decode(&evs)
	ar.Body.Close()
	if len(evs) != 1 {
		t.Fatalf("admin events len = %d", len(evs))
	}
}

func TestDashboardServedAndRoutePrecedence(t *testing.T) {
	ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "Redactr Control Plane") {
		t.Fatalf("dashboard / code=%d body=%.80s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("dashboard content-type = %q", ct)
	}

	h, _ := http.Get(ts.URL + "/healthz")
	hb, _ := io.ReadAll(h.Body)
	h.Body.Close()
	if !strings.Contains(string(hb), "ok") {
		t.Errorf("/healthz should still return health JSON, got %.80s", hb)
	}
}

type fakeBuilder struct{ ref, digest string }

func (f fakeBuilder) Build(_ context.Context, spec imagebuild.BuildSpec) (imagebuild.Result, error) {
	return imagebuild.Result{Ref: f.ref, Digest: f.digest}, nil
}

func newTestServerWithSrv(t *testing.T) (*httptest.Server, *Server) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := New(st, auth.NewSigner(priv), "admin-key")
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts, srv
}

func TestImageBuildSetsPolicy(t *testing.T) {
	ts, srv := newTestServerWithSrv(t)
	srv.SetBuilder(fakeBuilder{ref: "reg/acme/tools", digest: "sha256:cafe"}, "reg")

	r := postJSON(t, ts, "/admin/orgs", "admin-key", map[string]string{"name": "Acme"})
	var org struct {
		ID string `json:"id"`
	}
	json.NewDecoder(r.Body).Decode(&org)
	r.Body.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/admin/orgs/"+org.ID+"/images",
		bytes.NewReader([]byte(`{"dockerfile":"FROM redactr-base\nRUN echo hi","tag":"tools"}`)))
	req.Header.Set("X-Admin-Key", "admin-key")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("POST images code = %d", resp.StatusCode)
	}
	resp.Body.Close()

	preq, _ := http.NewRequest("GET", ts.URL+"/admin/orgs/"+org.ID+"/policy", nil)
	preq.Header.Set("X-Admin-Key", "admin-key")
	pr, _ := http.DefaultClient.Do(preq)
	var pol map[string]any
	json.NewDecoder(pr.Body).Decode(&pol)
	pr.Body.Close()
	if pol["image"] != "reg/acme/tools@sha256:cafe" {
		t.Fatalf("policy image = %v", pol["image"])
	}
}

func TestIngestEndpointDedup(t *testing.T) {
	ts := newTestServer(t)

	resp := postJSON(t, ts, "/admin/orgs", "admin-key", map[string]string{"name": "Acme"})
	var org struct{ ID string `json:"id"` }
	json.NewDecoder(resp.Body).Decode(&org)
	resp.Body.Close()

	resp = postJSON(t, ts, "/admin/orgs/"+org.ID+"/enrollment-tokens", "admin-key",
		map[string]int{"expires_in_hours": 1, "max_uses": 1})
	var mint struct{ Token string `json:"token"` }
	json.NewDecoder(resp.Body).Decode(&mint)
	resp.Body.Close()

	resp = postJSON(t, ts, "/v1/enroll", "",
		map[string]string{"enrollment_token": mint.Token, "device_name": "laptop", "platform": "darwin"})
	var enr map[string]string
	json.NewDecoder(resp.Body).Decode(&enr)
	resp.Body.Close()
	token := enr["token"]

	body := control.IngestRequest{Records: []control.IngestRecord{
		{UUID: "m1", Kind: control.KindMonitor, Monitor: &control.MonitorEvent{Tool: "Claude Code", Verdict: "runaway", Reason: "x"}},
		{UUID: "a1", Kind: control.KindAudit, Audit: &control.AuditRecord{Provider: "anthropic", Source: "proxy", Detector: "regex", Category: "aws_key", Action: "blocked"}},
	}}
	b, _ := json.Marshal(body)

	post := func() int {
		req, _ := http.NewRequest("POST", ts.URL+"/v1/ingest", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		return r.StatusCode
	}
	if code := post(); code != 200 {
		t.Fatalf("first ingest code=%d", code)
	}
	if code := post(); code != 200 {
		t.Fatalf("second ingest code=%d", code)
	}

	req, _ := http.NewRequest("GET", ts.URL+"/admin/orgs/"+org.ID+"/events", nil)
	req.Header.Set("X-Admin-Key", "admin-key")
	r, _ := http.DefaultClient.Do(req)
	var evs []map[string]any
	json.NewDecoder(r.Body).Decode(&evs)
	r.Body.Close()
	if len(evs) != 1 {
		t.Fatalf("events after dedup=%d want 1", len(evs))
	}
}
