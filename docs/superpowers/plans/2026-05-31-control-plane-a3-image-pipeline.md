# Image Pipeline (A3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Admin uploads a Dockerfile (`FROM redactr-base`); the server orchestrates build → push → cosign-sign to an immutable `ref@digest`, records it, and sets the org policy `image` to it. Real Docker/cosign/registry execution is behind a command-runner seam (unit-tested with a fake; live run deferred to a Docker+cosign+registry host).

**Architecture:** `images` store table; `internal/server/imagebuild` (`Builder` interface + `commandRunner` seam + `FROM` validation); HTTP `POST/GET /admin/orgs/{id}/images` with an **injectable** `Builder`; on success it `PutPolicy(image=ref@digest)`. Dashboard Images tab.

**Tech Stack:** Go 1.26, modernc sqlite, net/http; production runner shells out to `docker`/`cosign`.

**Verification bar:** `go build ./...`, `go test ./internal/... ` green, `go vet ./...`, `CGO_ENABLED=0 GOOS=linux go build ./cmd/redactr-server/`. Real build/sign/push deferred (documented).

---

## Task 1: `images` store

**Files:** Modify `internal/server/store/schema.sql`, `internal/server/store/store.go`. Test: append to `store_test.go`.

- [ ] **Step 1: schema (append to `schema.sql`)**
```sql
CREATE TABLE IF NOT EXISTS images (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL REFERENCES orgs(id),
  tag         TEXT NOT NULL,
  ref         TEXT NOT NULL DEFAULT '',
  digest      TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL,
  created_at  TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_images_org ON images(org_id, created_at);
```

- [ ] **Step 2: failing test (append to `store_test.go`)**
```go
func TestImagesLifecycle(t *testing.T) {
	s := openTest(t)
	org, _ := s.CreateOrg("Acme")
	id, err := s.InsertImage(org.ID, "team-tools")
	if err != nil || id == "" {
		t.Fatalf("InsertImage: %v id=%q", err, id)
	}
	imgs, _ := s.ListImages(org.ID)
	if len(imgs) != 1 || imgs[0].Status != "building" || imgs[0].Tag != "team-tools" {
		t.Fatalf("ListImages: %+v", imgs)
	}
	if err := s.SetImageResult(id, "reg/acme/team-tools", "sha256:abc", "ready"); err != nil {
		t.Fatalf("SetImageResult: %v", err)
	}
	imgs, _ = s.ListImages(org.ID)
	if imgs[0].Status != "ready" || imgs[0].Digest != "sha256:abc" || imgs[0].Ref != "reg/acme/team-tools" {
		t.Errorf("after SetImageResult: %+v", imgs[0])
	}
}
```

- [ ] **Step 3: implement (append to `store.go`)**
```go
// Image is a stored built-image record.
type Image struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Tag       string    `json:"tag"`
	Ref       string    `json:"ref"`
	Digest    string    `json:"digest"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// InsertImage records a new image in 'building' status and returns its id.
func (s *Store) InsertImage(orgID, tag string) (string, error) {
	id := newID()
	_, err := s.db.Exec(
		`INSERT INTO images(id,org_id,tag,status,created_at) VALUES(?,?,?,?,?)`,
		id, orgID, tag, "building", time.Now().UTC())
	return id, err
}

// SetImageResult updates an image row after a build attempt.
func (s *Store) SetImageResult(id, ref, digest, status string) error {
	_, err := s.db.Exec(`UPDATE images SET ref=?, digest=?, status=? WHERE id=?`, ref, digest, status, id)
	return err
}

// ListImages returns an org's images, newest first.
func (s *Store) ListImages(orgID string) ([]Image, error) {
	rows, err := s.db.Query(
		`SELECT id,org_id,tag,ref,digest,status,created_at FROM images WHERE org_id=? ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Image{}
	for rows.Next() {
		var im Image
		if err := rows.Scan(&im.ID, &im.OrgID, &im.Tag, &im.Ref, &im.Digest, &im.Status, &im.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, im)
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: verify + commit**
Run: `go test ./internal/server/store/ -v && go vet ./internal/server/store/`
```bash
git add internal/server/store/schema.sql internal/server/store/store.go internal/server/store/store_test.go
git commit -m "feat(server): images store — Insert/List/SetImageResult"
```

---

## Task 2: `internal/server/imagebuild`

**Files:** Create `internal/server/imagebuild/imagebuild.go`, `internal/server/imagebuild/imagebuild_test.go`.

- [ ] **Step 1: failing test**
```go
package imagebuild

import (
	"context"
	"strings"
	"testing"
)

type fakeRunner struct{ calls [][]string }

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if name == "docker" && len(args) > 0 && args[0] == "push" {
		return "...\nlatest: digest: sha256:deadbeef size: 1234\n", nil
	}
	return "", nil
}

func TestBuildSequence(t *testing.T) {
	fr := &fakeRunner{}
	b := &ShellBuilder{Run: fr.Run, CosignKey: "/keys/cosign.key"}
	res, err := b.Build(context.Background(), BuildSpec{
		Dockerfile: "FROM redactr-base\nRUN echo hi\n",
		BaseRef:    "redactr-base",
		TargetRef:  "reg/acme/tools",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if res.Digest != "sha256:deadbeef" || res.Ref != "reg/acme/tools" {
		t.Fatalf("result = %+v", res)
	}
	// Expect: docker build, docker push, cosign sign — in order.
	if len(fr.calls) != 3 || fr.calls[0][0] != "docker" || fr.calls[0][1] != "build" ||
		fr.calls[1][1] != "push" || fr.calls[2][0] != "cosign" {
		t.Fatalf("call sequence = %v", fr.calls)
	}
	// cosign signs the digest-pinned ref.
	if !strings.Contains(strings.Join(fr.calls[2], " "), "reg/acme/tools@sha256:deadbeef") {
		t.Errorf("cosign target = %v", fr.calls[2])
	}
}

func TestBuildRejectsNonBaseFrom(t *testing.T) {
	b := &ShellBuilder{Run: (&fakeRunner{}).Run, CosignKey: "k"}
	_, err := b.Build(context.Background(), BuildSpec{
		Dockerfile: "FROM ubuntu:22.04\n", BaseRef: "redactr-base", TargetRef: "reg/x",
	})
	if err == nil {
		t.Fatal("expected rejection of a Dockerfile not based on redactr-base")
	}
}
```
Run `go test ./internal/server/imagebuild/ -v` → FAIL.

- [ ] **Step 2: implement `internal/server/imagebuild/imagebuild.go`**
```go
// Package imagebuild orchestrates the central image pipeline: validate the
// admin Dockerfile extends the hardened base, build it, push it to the
// registry, and cosign-sign the resulting digest. The actual docker/cosign
// execution is behind a command-runner seam; production wires a shell runner.
package imagebuild

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// BuildSpec is one image build request.
type BuildSpec struct {
	Dockerfile string // full Dockerfile text (must FROM BaseRef)
	BaseRef    string // e.g. "redactr-base"
	TargetRef  string // e.g. "registry.example.com/acme/team-tools"
}

// Result is a completed build.
type Result struct {
	Ref    string
	Digest string // "sha256:..."
}

// Builder builds, pushes, and signs an image.
type Builder interface {
	Build(ctx context.Context, spec BuildSpec) (Result, error)
}

// CommandRunner runs an external command and returns its combined stdout.
type CommandRunner func(ctx context.Context, name string, args ...string) (string, error)

// ShellBuilder is the production Builder; Run defaults to ExecRunner.
type ShellBuilder struct {
	Run       CommandRunner
	CosignKey string
}

// NewShellBuilder builds a ShellBuilder using the real exec runner.
func NewShellBuilder(cosignKey string) *ShellBuilder {
	return &ShellBuilder{Run: ExecRunner, CosignKey: cosignKey}
}

// ExecRunner is the real command runner (shells out, combined output).
func ExecRunner(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

var fromRe = regexp.MustCompile(`(?im)^\s*FROM\s+(\S+)`)
var digestRe = regexp.MustCompile(`digest:\s*(sha256:[0-9a-f]{64})`)

func (b *ShellBuilder) Build(ctx context.Context, spec BuildSpec) (Result, error) {
	m := fromRe.FindStringSubmatch(spec.Dockerfile)
	if m == nil || !strings.HasPrefix(m[1], spec.BaseRef) {
		return Result{}, fmt.Errorf("Dockerfile must be FROM %s", spec.BaseRef)
	}

	dir, err := os.MkdirTemp("", "redactr-build-*")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(dir)
	dockerfile := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(dockerfile, []byte(spec.Dockerfile), 0o600); err != nil {
		return Result{}, err
	}

	if _, err := b.Run(ctx, "docker", "build", "-t", spec.TargetRef, "-f", dockerfile, dir); err != nil {
		return Result{}, fmt.Errorf("docker build: %w", err)
	}
	pushOut, err := b.Run(ctx, "docker", "push", spec.TargetRef)
	if err != nil {
		return Result{}, fmt.Errorf("docker push: %w", err)
	}
	dm := digestRe.FindStringSubmatch(pushOut)
	if dm == nil {
		return Result{}, fmt.Errorf("could not parse pushed digest from output")
	}
	digest := dm[1]
	if _, err := b.Run(ctx, "cosign", "sign", "--key", b.CosignKey, spec.TargetRef+"@"+digest); err != nil {
		return Result{}, fmt.Errorf("cosign sign: %w", err)
	}
	return Result{Ref: spec.TargetRef, Digest: digest}, nil
}
```
Run `go test ./internal/server/imagebuild/ -v` → PASS. Commit:
```bash
git add internal/server/imagebuild/
git commit -m "feat(server): imagebuild — build/push/cosign-sign orchestration (runner seam, FROM-gated)"
```

---

## Task 3: HTTP images endpoints + policy wiring

**Files:** Modify `internal/server/httpapi/server.go`, `cmd/redactr-server/main.go`. Test: append to `server_test.go`.

- [ ] **Step 1: failing test (append to `server_test.go`)** — injects a fake builder.
```go
type fakeBuilder struct{ ref, digest string }

func (f fakeBuilder) Build(_ context.Context, spec imagebuild.BuildSpec) (imagebuild.Result, error) {
	return imagebuild.Result{Ref: f.ref, Digest: f.digest}, nil
}

func TestImageBuildSetsPolicy(t *testing.T) {
	ts, srv := newTestServerWithSrv(t) // helper returns both (see note)
	srv.SetBuilder(fakeBuilder{ref: "reg/acme/tools", digest: "sha256:cafe"}, "reg")

	r := postJSON(t, ts, "/admin/orgs", "admin-key", map[string]string{"name": "Acme"})
	var org struct{ ID string `json:"id"` }
	json.NewDecoder(r.Body).Decode(&org); r.Body.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/admin/orgs/"+org.ID+"/images",
		bytes.NewReader([]byte(`{"dockerfile":"FROM redactr-base\nRUN echo hi","tag":"tools"}`)))
	req.Header.Set("X-Admin-Key", "admin-key")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("POST images code = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Policy image is now the signed ref@digest.
	preq, _ := http.NewRequest("GET", ts.URL+"/admin/orgs/"+org.ID+"/policy", nil)
	preq.Header.Set("X-Admin-Key", "admin-key")
	pr, _ := http.DefaultClient.Do(preq)
	var pol map[string]any
	json.NewDecoder(pr.Body).Decode(&pol); pr.Body.Close()
	if pol["image"] != "reg/acme/tools@sha256:cafe" {
		t.Fatalf("policy image = %v", pol["image"])
	}
}
```
> NOTE: add a small test helper to `server_test.go`:
> ```go
> func newTestServerWithSrv(t *testing.T) (*httptest.Server, *Server) {
> 	t.Helper()
> 	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
> 	if err != nil { t.Fatal(err) }
> 	t.Cleanup(func() { st.Close() })
> 	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
> 	srv := New(st, auth.NewSigner(priv), "admin-key")
> 	ts := httptest.NewServer(srv)
> 	t.Cleanup(ts.Close)
> 	return ts, srv
> }
> ```
> and import `"context"` + `"github.com/rakeshguha/redactr/internal/server/imagebuild"` in the test.

Run `go test ./internal/server/httpapi/ -run TestImageBuild -v` → FAIL.

- [ ] **Step 2: extend `internal/server/httpapi/server.go`**
Add fields + setter + routes + handlers. Add imports `"github.com/rakeshguha/redactr/internal/server/imagebuild"`, `"encoding/json"` (present), `"github.com/rakeshguha/redactr/internal/control"` (present).
```go
// In the Server struct, add:
//   builder  imagebuild.Builder
//   registry string

// SetBuilder configures the image builder + registry base (production wires a
// ShellBuilder; tests inject a fake).
func (s *Server) SetBuilder(b imagebuild.Builder, registry string) {
	s.builder = b
	s.registry = registry
}
```
Routes in `New`:
```go
	s.mux.Handle("POST /admin/orgs/{id}/images", admin(http.HandlerFunc(s.handleBuildImage)))
	s.mux.Handle("GET /admin/orgs/{id}/images", admin(http.HandlerFunc(s.handleListImages)))
```
Handlers:
```go
func (s *Server) handleListImages(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	if _, err := s.store.GetOrg(orgID); err != nil {
		http.Error(w, "unknown org", http.StatusNotFound)
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
	orgID := r.PathValue("id")
	if _, err := s.store.GetOrg(orgID); err != nil {
		http.Error(w, "unknown org", http.StatusNotFound)
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
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Dockerfile == "" || in.Tag == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
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
	// Point the org policy at the freshly signed image (preserve other fields).
	raw, _, _ := s.store.GetPolicy(orgID)
	var b control.PolicyBundle
	_ = json.Unmarshal(raw, &b)
	b.Image = pinned
	if b.MountMode == "" {
		b.MountMode = "bind"
	}
	if b.Denylist == nil {
		b.Denylist = []string{}
	}
	canonical, _ := json.Marshal(control.PolicyBundle{Image: b.Image, MountMode: b.MountMode, Denylist: b.Denylist})
	version, _ := s.store.PutPolicy(orgID, canonical)
	writeJSON(w, 200, map[string]any{"image": pinned, "policy_version": version})
}
```

- [ ] **Step 3: wire production builder in `cmd/redactr-server/main.go`**
After `srv := httpapi.New(...)` (it's currently inline in the `&http.Server{Handler: ...}` — refactor to a named `handler := httpapi.New(...)` and pass it), add:
```go
	handler := httpapi.New(st, auth.NewSigner(priv), adminKey)
	if reg := os.Getenv("REDACTR_REGISTRY"); reg != "" {
		handler.SetBuilder(imagebuild.NewShellBuilder(env("REDACTR_COSIGN_KEY", "./keys/cosign.key")), reg)
	}
	srv := &http.Server{Addr: addr, Handler: handler}
```
Add imports `"github.com/rakeshguha/redactr/internal/server/imagebuild"`.

- [ ] **Step 4: verify + commit**
Run: `go test ./internal/server/httpapi/ -v && go build ./... && go vet ./internal/server/... && CGO_ENABLED=0 GOOS=linux go build ./cmd/redactr-server/`
```bash
git add internal/server/httpapi/server.go internal/server/httpapi/server_test.go cmd/redactr-server/main.go
git commit -m "feat(server): image build endpoint + policy pin to signed ref@digest"
```

---

## Task 4: Dashboard Images tab

**Files:** Modify `internal/server/httpapi/dashboard/app.js`.

- [ ] **Step 1:** add `"images"` to the `tabs` array in `renderOrg` (after `"policy"`), add the dispatch `else if (cur === "images") await tabImages(orgID, panel);`, and add the function:
```js
async function tabImages(orgID, panel) {
  const imgs = await api("GET", "/admin/orgs/" + orgID + "/images") || [];
  const tbl = h("table", {}, h("tr", {}, h("th", {}, "Tag"), h("th", {}, "Status"), h("th", {}, "Ref@digest")));
  for (const im of imgs) {
    tbl.append(h("tr", {}, h("td", {}, im.tag), h("td", {}, im.status),
      h("td", { class: "mono" }, im.ref ? im.ref + "@" + im.digest : "—")));
  }
  const tag = h("input", { placeholder: "image tag (e.g. team-tools)" });
  const dockerfile = h("textarea", { rows: "8", placeholder: "FROM redactr-base\nRUN ..." });
  const build = h("button", { class: "btn", onclick: async () => {
    if (!tag.value.trim() || !dockerfile.value.trim()) return;
    try {
      const r = await api("POST", "/admin/orgs/" + orgID + "/images", { tag: tag.value.trim(), dockerfile: dockerfile.value });
      toast("Built " + r.image + " (policy v" + r.policy_version + ")");
      render();
    } catch (e) { toast(e.message, true); }
  } }, "Build & sign");
  panel.replaceChildren(h("h2", {}, "Images"),
    imgs.length ? tbl : h("p", { class: "empty" }, "No images built yet."),
    h("h3", {}, "Build a new image"),
    h("label", {}, "Tag"), tag, h("label", {}, "Dockerfile (must FROM redactr-base)"), dockerfile, build);
}
```

- [ ] **Step 2: verify + commit**
Run: `node --check internal/server/httpapi/dashboard/app.js` (if node present), `go test ./internal/server/httpapi/ -run TestDashboardServed -v`, `go build ./...`.
```bash
git add internal/server/httpapi/dashboard/app.js
git commit -m "feat(dashboard): Images tab — list + build/sign Dockerfile"
```

---

## Final verification
```bash
go build ./... && go test ./internal/... 2>&1 | grep -v "no test files" && go vet ./... \
  && CGO_ENABLED=0 GOOS=linux go build ./cmd/redactr-server/
```

**Deferred (documented):** real `docker build`/`docker push`/`cosign sign` + client `cosign verify` on a Docker+cosign+registry-equipped server (set `REDACTR_REGISTRY` + `REDACTR_COSIGN_KEY`). The Go orchestration + `FROM` gate + policy pinning are tested via the runner/builder seams.

## Self-Review map
- images store → T1; build/push/sign orchestration (seam, FROM-gated, digest parse) → T2; HTTP endpoint + policy-pin (injected fake builder) → T3; dashboard Images tab → T4. Real docker/cosign/registry + client verify deferred.
