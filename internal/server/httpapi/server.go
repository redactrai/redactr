// Package httpapi wires the control-plane server's HTTP routes.
package httpapi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/redactrai/redactr/internal/control"
	"github.com/redactrai/redactr/internal/server/auth"
	"github.com/redactrai/redactr/internal/server/imagebuild"
	"github.com/redactrai/redactr/internal/server/store"
)

// AuthConfig configures the admin authentication surface (session-based login,
// optional super-admin password, optional OIDC, optional automation key).
type AuthConfig struct {
	SuperadminUser string
	SuperadminHash string        // bcrypt hash; empty = super-admin disabled
	Secure         bool          // set Secure flag on cookies (true in prod/https)
	SessionTTL     time.Duration // e.g. 12h
	MachineKey     string        // optional; empty = machine-key path disabled
	MaxBodyBytes   int64         // e.g. 1<<20
}

type Server struct {
	store    *store.Store
	signer   *auth.Signer
	cfg      AuthConfig
	oidc     *auth.OIDC // may be nil
	mux      *http.ServeMux
	builder  imagebuild.Builder
	registry string
}

// New builds the control-plane HTTP handler. oidc may be nil (SSO disabled).
func New(st *store.Store, signer *auth.Signer, cfg AuthConfig, oidc *auth.OIDC) *Server {
	s := &Server{store: st, signer: signer, cfg: cfg, oidc: oidc, mux: http.NewServeMux()}
	dev := auth.RequireDevice(st, signer)
	lookup := auth.SessionLookup(st.LookupSession)
	admin := auth.RequireSession("admin", lookup)
	superadmin := auth.RequireSession("superadmin", lookup)

	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("POST /v1/enroll", s.limitBody(s.handleEnroll))
	s.mux.Handle("GET /v1/whoami", dev(http.HandlerFunc(s.handleWhoami)))
	s.mux.Handle("GET /v1/policy", dev(http.HandlerFunc(s.handleGetPolicy)))
	s.mux.HandleFunc("GET /v1/server-key", s.handleServerKey)
	s.mux.Handle("PUT /admin/orgs/{id}/policy", admin(http.HandlerFunc(s.limitBody(s.handlePutPolicy))))
	s.mux.Handle("GET /admin/orgs/{id}/policy", admin(http.HandlerFunc(s.handleGetAdminPolicy)))
	s.mux.Handle("POST /v1/events", dev(http.HandlerFunc(s.limitBody(s.handlePostEvents))))
	s.mux.Handle("POST /v1/ingest", dev(http.HandlerFunc(s.limitBody(s.handleIngest))))
	s.mux.Handle("GET /admin/orgs/{id}/events", admin(http.HandlerFunc(s.handleAdminEvents)))
	s.mux.Handle("GET /admin/orgs/{id}/event-stats", admin(http.HandlerFunc(s.handleAdminEventStats)))

	s.mux.Handle("POST /admin/orgs", admin(http.HandlerFunc(s.limitBody(s.handleCreateOrg))))
	s.mux.Handle("GET /admin/orgs", admin(http.HandlerFunc(s.handleListOrgs)))
	// Enrollment-token minting accepts EITHER a valid admin session OR, when
	// configured, the X-Machine-Key header (for CI/automation). This is the
	// ONLY endpoint that honors the machine key.
	s.mux.Handle("POST /admin/orgs/{id}/enrollment-tokens",
		s.limitBody(s.machineKeyOr("admin", lookup)(http.HandlerFunc(s.handleMintToken)).ServeHTTP))
	s.mux.Handle("GET /admin/devices", admin(http.HandlerFunc(s.handleListDevices)))
	s.mux.Handle("POST /admin/devices/{id}/revoke", admin(http.HandlerFunc(s.handleRevokeDevice)))
	s.mux.Handle("POST /admin/orgs/{id}/images", admin(http.HandlerFunc(s.limitBody(s.handleBuildImage))))
	s.mux.Handle("GET /admin/orgs/{id}/images", admin(http.HandlerFunc(s.handleListImages)))

	// Unauthenticated auth-establishing routes.
	s.mux.HandleFunc("GET /admin/login", s.handleLoginForm)
	s.mux.HandleFunc("POST /admin/login", s.handleLogin)
	s.mux.HandleFunc("POST /admin/logout", s.handleLogout)
	s.mux.HandleFunc("GET /admin/oidc/start", s.handleOIDCStart)
	s.mux.HandleFunc("GET /admin/oidc/callback", s.handleOIDCCallback)

	// Session identity for the SPA (admin or superadmin).
	s.mux.Handle("GET /admin/me", admin(http.HandlerFunc(s.handleMe)))

	// Admin allowlist management (superadmin only).
	s.mux.Handle("GET /admin/admins", superadmin(http.HandlerFunc(s.handleListAdmins)))
	s.mux.Handle("POST /admin/admins", superadmin(http.HandlerFunc(s.limitBody(s.handleAddAdmin))))
	s.mux.Handle("DELETE /admin/admins/{email}", superadmin(http.HandlerFunc(s.handleDeleteAdmin)))

	s.mux.Handle("GET /", dashboardHandler())
	return s
}

// limitBody wraps a handler so the request body is capped at cfg.MaxBodyBytes.
// Reads past the cap surface as *http.MaxBytesError, which the wrapped handler's
// decode path maps to 413.
func (s *Server) limitBody(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.MaxBodyBytes > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
		}
		next(w, r)
	}
}

// machineKeyOr returns middleware that accepts EITHER a valid X-Machine-Key
// header (constant-time compare, only when cfg.MachineKey != "") OR a valid
// session of the given role. Used to allow CI/automation to mint enrollment
// tokens without a browser session.
func (s *Server) machineKeyOr(role string, lookup auth.SessionLookup) func(http.Handler) http.Handler {
	session := auth.RequireSession(role, lookup)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.cfg.MachineKey != "" {
				got := r.Header.Get("X-Machine-Key")
				if got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.MachineKey)) == 1 {
					next.ServeHTTP(w, r)
					return
				}
			}
			session(next).ServeHTTP(w, r)
		})
	}
}

// SetBuilder configures the image builder + registry base.
func (s *Server) SetBuilder(b imagebuild.Builder, registry string) {
	s.builder = b
	s.registry = registry
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// NewRawToken returns a 24-byte URL-safe random token (enrollment tokens,
// admin keys). Only the caller ever sees the raw value.
func NewRawToken() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// requireOrg resolves and validates the {id} path segment, writing a 404 and
// returning ok=false if the org does not exist. Shared by every org-scoped
// admin handler so the existence check lives in one place.
func (s *Server) requireOrg(w http.ResponseWriter, r *http.Request) (string, bool) {
	orgID := r.PathValue("id")
	if _, err := s.store.GetOrg(orgID); err != nil {
		http.Error(w, "unknown org", http.StatusNotFound)
		return "", false
	}
	return orgID, true
}

// canonicalBundle marshals the wire bundle with empty-field normalization
// (default mount mode, non-nil denylist) so stored policy JSON is stable.
func canonicalBundle(b control.PolicyBundle) []byte {
	if b.MountMode == "" {
		b.MountMode = "bind"
	}
	if b.Denylist == nil {
		b.Denylist = []string{}
	}
	out, _ := json.Marshal(control.PolicyBundle{Image: b.Image, MountMode: b.MountMode, Denylist: b.Denylist})
	return out
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var in struct {
		EnrollmentToken string `json:"enrollment_token"`
		DeviceName      string `json:"device_name"`
		Platform        string `json:"platform"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	res, err := auth.Enroll(s.store, s.signer,
		auth.EnrollInput{EnrollmentToken: in.EnrollmentToken, DeviceName: in.DeviceName, Platform: in.Platform},
		time.Now().UTC())
	if err != nil {
		http.Error(w, "enrollment failed", http.StatusUnauthorized)
		return
	}
	pubPEM, perr := s.signer.PublicKeyPEM()
	if perr != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, map[string]string{
		"device_id": res.DeviceID, "org_id": res.OrgID, "token": res.Token,
		"server_public_key": pubPEM,
	})
}

func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{
		"device_id": auth.DeviceID(r.Context()),
		"org_id":    auth.OrgID(r.Context()),
	})
}

func (s *Server) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if in.Name == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	org, err := s.store.CreateOrg(in.Name)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": org.ID, "name": org.Name})
}

func (s *Server) handleListOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := s.store.ListOrgs()
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, orgs)
}

func (s *Server) handleMintToken(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.requireOrg(w, r)
	if !ok {
		return
	}
	var in struct {
		ExpiresInHours int `json:"expires_in_hours"`
		MaxUses        int `json:"max_uses"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		// Body is optional; decode errors (empty body, EOF) are silently ignored.
	}
	if in.ExpiresInHours <= 0 {
		in.ExpiresInHours = 24
	}
	now := time.Now().UTC()
	rawToken := NewRawToken() // shown to the admin once; only its hash is stored
	expires := now.Add(time.Duration(in.ExpiresInHours) * time.Hour)
	if err := s.store.CreateEnrollmentToken(auth.HashToken(rawToken), orgID, expires, in.MaxUses, now); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": rawToken, "expires_at": expires})
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	devs, err := s.store.ListDevices(r.URL.Query().Get("org"))
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, devs)
}

func (s *Server) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	if err := s.store.RevokeDevice(r.PathValue("id")); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, map[string]bool{"revoked": true})
}

func (s *Server) handleServerKey(w http.ResponseWriter, r *http.Request) {
	pem, err := s.signer.PublicKeyPEM()
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, map[string]string{"public_key": pem})
}

func (s *Server) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.requireOrg(w, r)
	if !ok {
		return
	}
	var b control.PolicyBundle
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if b.Image == "" || b.MountMode == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	version, err := s.store.PutPolicy(orgID, canonicalBundle(b))
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"version": version})
}

func (s *Server) handleGetAdminPolicy(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.requireOrg(w, r)
	if !ok {
		return
	}
	raw, version, err := s.store.GetPolicy(orgID)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(bundleWithVersion(raw, version))
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	raw, version, err := s.store.GetPolicy(auth.OrgID(r.Context()))
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	etag := fmt.Sprintf("\"v%d\"", version)
	if r.Header.Get("If-None-Match") == etag {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	bundleJSON := bundleWithVersion(raw, version)
	sig, err := s.signer.SignDetached(bundleJSON)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("ETag", etag)
	writeJSON(w, 200, control.SignedPolicy{
		Bundle:    base64.RawURLEncoding.EncodeToString(bundleJSON),
		Signature: sig,
		Version:   version,
	})
}

const maxEventBatch = 500

func (s *Server) handlePostEvents(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Events []control.MonitorEvent `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(in.Events) > maxEventBatch {
		http.Error(w, "batch too large", http.StatusBadRequest)
		return
	}
	if len(in.Events) == 0 {
		writeJSON(w, 200, map[string]int{"accepted": 0})
		return
	}
	if err := s.store.InsertEvents(auth.OrgID(r.Context()), auth.DeviceID(r.Context()), in.Events, time.Now().UTC()); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, map[string]int{"accepted": len(in.Events)})
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	var in control.IngestRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(in.Records) > maxEventBatch {
		http.Error(w, "batch too large", http.StatusBadRequest)
		return
	}
	if len(in.Records) == 0 {
		writeJSON(w, 200, control.IngestResponse{Accepted: []string{}})
		return
	}
	accepted, err := s.store.IngestRecords(auth.OrgID(r.Context()), auth.DeviceID(r.Context()), in.Records, time.Now().UTC())
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, control.IngestResponse{Accepted: accepted})
}

func (s *Server) handleAdminEvents(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.requireOrg(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	evs, err := s.store.ListEvents(orgID, limit)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, evs)
}

func (s *Server) handleAdminEventStats(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.requireOrg(w, r)
	if !ok {
		return
	}
	hours, _ := strconv.Atoi(r.URL.Query().Get("since_hours"))
	if hours <= 0 {
		hours = 24
	}
	counts, err := s.store.CountByVerdict(orgID, time.Now().UTC().Add(-time.Duration(hours)*time.Hour))
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, counts)
}

func (s *Server) handleListImages(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.requireOrg(w, r)
	if !ok {
		return
	}
	imgs, err := s.store.ListImages(orgID)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, imgs)
}

func (s *Server) handleBuildImage(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.requireOrg(w, r)
	if !ok {
		return
	}
	if s.builder == nil {
		http.Error(w, "image build not configured (server needs docker+cosign)", http.StatusServiceUnavailable)
		return
	}
	var in struct {
		Dockerfile string `json:"dockerfile"`
		Tag        string `json:"tag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if in.Dockerfile == "" || in.Tag == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if strings.ContainsAny(in.Tag, " /\t\n:@") {
		http.Error(w, "invalid tag", http.StatusBadRequest)
		return
	}
	id, err := s.store.InsertImage(orgID, in.Tag)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	target := s.registry + "/" + orgID + "/" + in.Tag
	res, err := s.builder.Build(r.Context(), imagebuild.BuildSpec{Dockerfile: in.Dockerfile, BaseRef: "redactr-base", TargetRef: target})
	if err != nil {
		_ = s.store.SetImageResult(id, "", "", "failed")
		http.Error(w, "build failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	pinned := res.Ref + "@" + res.Digest
	_ = s.store.SetImageResult(id, res.Ref, res.Digest, "ready")
	raw, _, gerr := s.store.GetPolicy(orgID)
	if gerr != nil {
		http.Error(w, "image built but policy read failed", http.StatusInternalServerError)
		return
	}
	var b control.PolicyBundle
	_ = json.Unmarshal(raw, &b)
	b.Image = pinned
	version, perr := s.store.PutPolicy(orgID, canonicalBundle(b))
	if perr != nil {
		http.Error(w, "image built but policy pin failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"image": pinned, "policy_version": version})
}

// bundleWithVersion injects the authoritative version into the stored bundle JSON.
func bundleWithVersion(raw []byte, version int) []byte {
	var b control.PolicyBundle
	_ = json.Unmarshal(raw, &b)
	if b.Denylist == nil {
		b.Denylist = []string{}
	}
	b.Version = version
	out, _ := json.Marshal(b)
	return out
}
