package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// decodeJSON decodes resp.Body into v and closes it.
func decodeJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

// noRedirectClient does not follow redirects, so tests can inspect 303/302 and
// Set-Cookie headers on the redirect response itself.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func hasCookie(resp *http.Response, name string) (*http.Cookie, bool) {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c, true
		}
	}
	return nil, false
}

func TestSuperadminLoginSetsCookie(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	ts := newTestServerCfg(t, AuthConfig{
		SuperadminUser: "root",
		SuperadminHash: string(hash),
		SessionTTL:     time.Hour,
		MaxBodyBytes:   1 << 20,
	})
	cl := noRedirectClient()

	form := url.Values{"username": {"root"}, "password": {"hunter2"}}
	resp, err := cl.PostForm(ts.URL+"/admin/login", form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("good login code = %d, want 303", resp.StatusCode)
	}
	if _, ok := hasCookie(resp, "redactr_admin"); !ok {
		t.Fatalf("good login did not set redactr_admin cookie")
	}

	bad := url.Values{"username": {"root"}, "password": {"wrong"}}
	resp2, err := cl.PostForm(ts.URL+"/admin/login", bad)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad login code = %d, want 401", resp2.StatusCode)
	}
}

func TestLogoutClearsSession(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	ts := newTestServerCfg(t, AuthConfig{
		SuperadminUser: "root", SuperadminHash: string(hash),
		SessionTTL: time.Hour, MaxBodyBytes: 1 << 20,
	})
	cl := noRedirectClient()

	resp, err := cl.PostForm(ts.URL+"/admin/login", url.Values{"username": {"root"}, "password": {"hunter2"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	sessCookie, ok := hasCookie(resp, "redactr_admin")
	if !ok {
		t.Fatal("login did not set cookie")
	}

	// Session must exist in the store.
	st := testStores[ts]
	if _, err := st.LookupSession(sessCookie.Value); err != nil {
		t.Fatalf("session should exist before logout: %v", err)
	}

	req, _ := http.NewRequest("POST", ts.URL+"/admin/logout", nil)
	req.AddCookie(sessCookie)
	lr, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	lr.Body.Close()
	if lr.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout code = %d, want 303", lr.StatusCode)
	}
	// Cookie cleared (MaxAge < 0).
	if c, ok := hasCookie(lr, "redactr_admin"); !ok || c.MaxAge >= 0 {
		t.Fatalf("logout did not clear cookie: %+v", c)
	}
	// Session deleted.
	if _, err := st.LookupSession(sessCookie.Value); err == nil {
		t.Fatal("session should be deleted after logout")
	}
}

func TestAdminsRoutesRequireSuperadmin(t *testing.T) {
	ts := newTestServer(t)
	st := testStores[ts]

	// admin-role session: GET /admin/admins → 403.
	adminSess, _ := st.CreateSession("dev@x.test", "admin", time.Hour)
	req, _ := http.NewRequest("GET", ts.URL+"/admin/admins", nil)
	req.AddCookie(&http.Cookie{Name: "redactr_admin", Value: adminSess.ID})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin-role GET /admin/admins code = %d, want 403", resp.StatusCode)
	}

	// superadmin session: GET → 200, POST adds, DELETE removes.
	superSess, _ := st.CreateSession("root", "superadmin", time.Hour)
	super := &http.Cookie{Name: "redactr_admin", Value: superSess.ID}

	greq, _ := http.NewRequest("GET", ts.URL+"/admin/admins", nil)
	greq.AddCookie(super)
	gr, err := http.DefaultClient.Do(greq)
	if err != nil {
		t.Fatal(err)
	}
	gr.Body.Close()
	if gr.StatusCode != 200 {
		t.Fatalf("superadmin GET /admin/admins code = %d, want 200", gr.StatusCode)
	}

	preq, _ := http.NewRequest("POST", ts.URL+"/admin/admins", bytes.NewReader([]byte(`{"email":"NewAdmin@X.test"}`)))
	preq.AddCookie(super)
	pr, err := http.DefaultClient.Do(preq)
	if err != nil {
		t.Fatal(err)
	}
	pr.Body.Close()
	if pr.StatusCode != http.StatusCreated {
		t.Fatalf("POST /admin/admins code = %d, want 201", pr.StatusCode)
	}
	if ok, _ := st.IsAdmin("newadmin@x.test"); !ok {
		t.Fatal("admin was not added to store")
	}

	dreq, _ := http.NewRequest("DELETE", ts.URL+"/admin/admins/newadmin@x.test", nil)
	dreq.AddCookie(super)
	dr, err := http.DefaultClient.Do(dreq)
	if err != nil {
		t.Fatal(err)
	}
	dr.Body.Close()
	if dr.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /admin/admins code = %d, want 204", dr.StatusCode)
	}
	if ok, _ := st.IsAdmin("newadmin@x.test"); ok {
		t.Fatal("admin was not removed from store")
	}
}

func TestExistingAdminRouteNeedsSession(t *testing.T) {
	ts := newTestServer(t)

	// No cookie → 401.
	resp, err := http.Get(ts.URL + "/admin/orgs")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-cookie GET /admin/orgs code = %d, want 401", resp.StatusCode)
	}

	// Valid admin session → 200.
	st := testStores[ts]
	sess, _ := st.CreateSession("dev@x.test", "admin", time.Hour)
	req, _ := http.NewRequest("GET", ts.URL+"/admin/orgs", nil)
	req.AddCookie(&http.Cookie{Name: "redactr_admin", Value: sess.ID})
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != 200 {
		t.Fatalf("admin-session GET /admin/orgs code = %d, want 200", r2.StatusCode)
	}
}

func TestIngestBodyCapReturns413(t *testing.T) {
	// Body cap small enough that an oversized ingest payload trips it, but large
	// enough for the org/enroll setup requests below.
	ts := newTestServerCfg(t, AuthConfig{SessionTTL: time.Hour, MaxBodyBytes: 256})

	// Enroll a device to get a bearer token (same pattern as ingest tests).
	r := postJSON(t, ts, "/admin/orgs", adminCookie, map[string]string{"name": "Acme"})
	var org struct {
		ID string `json:"id"`
	}
	decodeJSON(t, r, &org)

	r = postJSON(t, ts, "/admin/orgs/"+org.ID+"/enrollment-tokens", adminCookie, map[string]int{"max_uses": 0})
	var mint struct {
		Token string `json:"token"`
	}
	decodeJSON(t, r, &mint)

	r = postJSON(t, ts, "/v1/enroll", "", map[string]string{"enrollment_token": mint.Token, "device_name": "d", "platform": "darwin"})
	var enr map[string]string
	decodeJSON(t, r, &enr)
	token := enr["token"]

	big := `{"records":[{"uuid":"` + strings.Repeat("x", 600) + `"}]}`
	req, _ := http.NewRequest("POST", ts.URL+"/v1/ingest", bytes.NewReader([]byte(big)))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized ingest code = %d, want 413", resp.StatusCode)
	}
}
