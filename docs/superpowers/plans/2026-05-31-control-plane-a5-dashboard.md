# Hosted Admin Dashboard (A5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** A framework-free admin dashboard embedded in `redactr-server`, served at `/`, wrapping the existing admin API (orgs / devices / enrollment tokens / policy / events).

**Architecture:** `//go:embed dashboard/*` + `http.FileServer` at `/` (Go 1.22 mux gives `/v1`, `/admin`, `/healthz` priority). Vanilla JS + `fetch` with an `X-Admin-Key` held in `sessionStorage`. No build step. The only Go is the embed handler + route + a serving test; the API it calls is already built and tested.

**Tech Stack:** Go 1.26 `embed`/`net/http`; vanilla HTML/CSS/JS.

**Verification bar:** `go build ./...`, `go test ./internal/server/httpapi/ ` + full suite green, `go vet ./...`, `CGO_ENABLED=0 GOOS=linux go build ./cmd/redactr-server/`. UI behavior is browser-verified (deferred to a running server, documented).

---

## Task 1: Embed + serve route + serving test

**Files:** Create `internal/server/httpapi/embed.go`, `internal/server/httpapi/dashboard/index.html` (placeholder marker), `internal/server/httpapi/dashboard/app.js` (placeholder). Modify `internal/server/httpapi/server.go` (route), `internal/server/store/store.go` (json tags). Test: append to `server_test.go`.

- [ ] **Step 0: uniform snake_case admin API — add json tags to `store.Org` and `store.Device`**

`GET /admin/orgs` / `GET /admin/devices` serialize these structs; without tags they emit PascalCase, inconsistent with the snake_case create-handler maps and the events endpoint. Add tags so the whole admin API is snake_case (the dashboard then uses one casing). In `internal/server/store/store.go`:
```go
type Org struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}
```
```go
type Device struct {
	ID         string     `json:"id"`
	OrgID      string     `json:"org_id"`
	Name       string     `json:"name"`
	Platform   string     `json:"platform"`
	EnrolledAt time.Time  `json:"enrolled_at"`
	LastSeenAt *time.Time `json:"last_seen_at"`
	Revoked    bool       `json:"revoked"`
}
```
Run `go test ./internal/server/... -v` — existing tests still pass (they decode the create-handler's `{id,name}` map and the events endpoint, not these struct fields directly).

- [ ] **Step 1: minimal embedded assets so the package compiles**

`internal/server/httpapi/dashboard/index.html`:
```html
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Redactr Control Plane</title></head>
<body><div id="app"></div><script src="app.js"></script></body></html>
```
`internal/server/httpapi/dashboard/app.js`:
```js
// placeholder — replaced in Task 2
```

- [ ] **Step 2: `internal/server/httpapi/embed.go`**
```go
package httpapi

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed dashboard/*
var dashboardFiles embed.FS

// dashboardHandler serves the embedded admin dashboard SPA.
func dashboardHandler() http.Handler {
	sub, err := fs.Sub(dashboardFiles, "dashboard")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}
```

- [ ] **Step 3: route in `New` (`internal/server/httpapi/server.go`)** — add as the LAST route (fallback), replacing the `// SEAM A5:` comment:
```go
	s.mux.Handle("GET /", dashboardHandler())
```

- [ ] **Step 4: failing test (append to `internal/server/httpapi/server_test.go`)**
```go
func TestDashboardServedAndRoutePrecedence(t *testing.T) {
	ts := newTestServer(t)

	// "/" serves the dashboard HTML.
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

	// Precise API routes still win over the "/" fallback.
	h, _ := http.Get(ts.URL + "/healthz")
	hb, _ := io.ReadAll(h.Body)
	h.Body.Close()
	if !strings.Contains(string(hb), "ok") {
		t.Errorf("/healthz should still return health JSON, got %.80s", hb)
	}
}
```
(Add `"io"` and `"strings"` to the test imports if not present.)
Run `go test ./internal/server/httpapi/ -run TestDashboardServed -v` → FAIL.

- [ ] **Step 5: implement → verify pass**
Run: `go test ./internal/server/httpapi/ -v` (all incl. new pass), `go vet ./internal/server/httpapi/`, `go build ./...`, `CGO_ENABLED=0 GOOS=linux go build ./cmd/redactr-server/`.

- [ ] **Step 6: commit**
```bash
git add internal/server/store/store.go internal/server/httpapi/embed.go internal/server/httpapi/dashboard/ internal/server/httpapi/server.go internal/server/httpapi/server_test.go
git commit -m "feat(server): embed + serve admin dashboard at / + snake_case org/device json"
```

---

## Task 2: Dashboard assets (HTML / CSS / JS)

**Files:** Replace `internal/server/httpapi/dashboard/index.html`, `app.js`; create `internal/server/httpapi/dashboard/style.css`.

This is hand-written vanilla JS — no automated unit tests (the Task-1 serving test is the automated bar). Implement all views per the spec. Keep it readable and dependency-free.

- [ ] **Step 1: `index.html`**
```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Redactr Control Plane</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <header><h1>Redactr Control Plane</h1><span id="whoami"></span></header>
  <main id="app"></main>
  <div id="toast" class="toast hidden"></div>
  <script src="app.js"></script>
</body>
</html>
```

- [ ] **Step 2: `style.css`** — a clean utilitarian stylesheet. Minimum: readable system-font body; a header bar; `.card`, `.btn`, `.btn-danger`, `table`/`th`/`td`, `.tabs`/`.tab.active`, `.alert` (red banner), `.empty` (muted), `.toast` (fixed bottom), `.hidden{display:none}`, `code`/`.mono`. Use a restrained palette (one accent, red for danger/runaway). ~120 lines is plenty; keep it functional, not ornate.

- [ ] **Step 3: `app.js`** — the SPA. Implement exactly these behaviors:

```js
"use strict";

const KEY = "redactr_admin_key";
const app = document.getElementById("app");

function adminKey() { return sessionStorage.getItem(KEY) || ""; }
function setKey(k) { sessionStorage.setItem(KEY, k); }
function clearKey() { sessionStorage.removeItem(KEY); }

function toast(msg, isErr) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.className = "toast" + (isErr ? " err" : "");
  setTimeout(() => (t.className = "toast hidden"), 3500);
}

async function api(method, path, body) {
  const opts = { method, headers: { "X-Admin-Key": adminKey() } };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(path, opts);
  if (resp.status === 401) { clearKey(); render(); throw new Error("unauthorized"); }
  if (!resp.ok) throw new Error(method + " " + path + " → " + resp.status);
  const ct = resp.headers.get("Content-Type") || "";
  return ct.includes("application/json") ? resp.json() : resp.text();
}

function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const k in (attrs || {})) {
    if (k === "onclick") e.onclick = attrs[k];
    else if (k === "class") e.className = attrs[k];
    else if (k === "html") e.innerHTML = attrs[k];
    else e.setAttribute(k, attrs[k]);
  }
  for (const kid of kids) e.append(kid && kid.nodeType ? kid : document.createTextNode(kid == null ? "" : String(kid)));
  return e;
}

// ---- key gate ----
function renderGate() {
  app.replaceChildren(h("div", { class: "card" },
    h("h2", {}, "Admin key"),
    h("p", { class: "empty" }, "Enter the server's admin key (X-Admin-Key)."),
    (() => {
      const input = h("input", { type: "password", id: "k", placeholder: "admin key" });
      const submit = async () => {
        setKey(input.value.trim());
        try { await api("GET", "/admin/orgs"); render(); }
        catch (e) { clearKey(); toast("Invalid admin key", true); }
      };
      input.addEventListener("keydown", (ev) => { if (ev.key === "Enter") submit(); });
      return h("div", {}, input, h("button", { class: "btn", onclick: submit }, "Unlock"));
    })()
  ));
}

// ---- orgs ----
async function renderOrgs() {
  const orgs = await api("GET", "/admin/orgs") || [];
  const list = h("div", { class: "card" }, h("h2", {}, "Organizations"));
  if (!orgs.length) list.append(h("p", { class: "empty" }, "No orgs yet."));
  for (const o of orgs) {
    list.append(h("div", { class: "row" },
      h("a", { href: "#/org/" + o.id, class: "link" }, o.name),
      h("span", { class: "mono" }, o.id)));
  }
  const name = h("input", { placeholder: "new org name", id: "newOrg" });
  const create = h("button", { class: "btn", onclick: async () => {
    if (!name.value.trim()) return;
    try { await api("POST", "/admin/orgs", { name: name.value.trim() }); location.hash = ""; render(); }
    catch (e) { toast(e.message, true); }
  } }, "Create org");
  app.replaceChildren(list, h("div", { class: "card" }, h("h3", {}, "New organization"), name, create));
}

// ---- org detail ----
async function renderOrg(orgID) {
  const tabs = ["overview", "devices", "enrollment", "policy", "events"];
  const cur = (location.hash.split("/")[3]) || "overview";
  const bar = h("div", { class: "tabs" });
  for (const t of tabs) {
    bar.append(h("a", { class: "tab" + (t === cur ? " active" : ""), href: "#/org/" + orgID + "/" + t }, t));
  }
  const panel = h("div", { class: "card" }, "Loading…");
  app.replaceChildren(h("div", { class: "row" }, h("a", { href: "#", class: "link" }, "← orgs")), bar, panel);
  try {
    if (cur === "overview") await tabOverview(orgID, panel);
    else if (cur === "devices") await tabDevices(orgID, panel);
    else if (cur === "enrollment") await tabEnroll(orgID, panel);
    else if (cur === "policy") await tabPolicy(orgID, panel);
    else if (cur === "events") await tabEvents(orgID, panel);
  } catch (e) { panel.replaceChildren(h("p", { class: "err" }, e.message)); }
}

async function tabOverview(orgID, panel) {
  const stats = await api("GET", "/admin/orgs/" + orgID + "/event-stats?since_hours=24") || {};
  const kids = [h("h2", {}, "Last 24h")];
  if ((stats.runaway || 0) > 0) kids.push(h("div", { class: "alert" }, "⚠ " + stats.runaway + " runaway session(s) — agents bypassing the proxy"));
  for (const k of ["protected", "runaway", "unknown"]) kids.push(h("div", { class: "row" }, h("b", {}, k), String(stats[k] || 0)));
  panel.replaceChildren(...kids);
}

async function tabDevices(orgID, panel) {
  const devs = await api("GET", "/admin/devices?org=" + orgID) || [];
  if (!devs.length) { panel.replaceChildren(h("p", { class: "empty" }, "No enrolled devices.")); return; }
  const tbl = h("table", {}, h("tr", {}, h("th", {}, "Name"), h("th", {}, "Platform"), h("th", {}, "Enrolled"), h("th", {}, "Last seen"), h("th", {}, "")));
  for (const d of devs) {
    const revoke = h("button", { class: "btn btn-danger", onclick: async () => {
      try { await api("POST", "/admin/devices/" + d.id + "/revoke"); render(); } catch (e) { toast(e.message, true); }
    } }, d.revoked ? "revoked" : "Revoke");
    if (d.revoked) revoke.disabled = true;
    tbl.append(h("tr", {}, h("td", {}, d.name), h("td", {}, d.platform), h("td", {}, fmtTime(d.enrolled_at)), h("td", {}, fmtTime(d.last_seen_at)), h("td", {}, revoke)));
  }
  panel.replaceChildren(h("h2", {}, "Devices"), tbl);
}

async function tabEnroll(orgID, panel) {
  const hours = h("input", { type: "number", value: "24", id: "h" });
  const uses = h("input", { type: "number", value: "0", id: "u" });
  const out = h("div", {});
  const mint = h("button", { class: "btn", onclick: async () => {
    try {
      const r = await api("POST", "/admin/orgs/" + orgID + "/enrollment-tokens", { expires_in_hours: +hours.value, max_uses: +uses.value });
      const cmd = "redactr enroll --server " + location.origin + " --token " + r.token;
      out.replaceChildren(
        h("p", { class: "alert" }, "Copy now — the token is shown only once."),
        h("code", { class: "mono" }, r.token),
        h("p", {}, "Run on the device:"),
        h("code", { class: "mono" }, cmd),
        h("button", { class: "btn", onclick: () => navigator.clipboard.writeText(cmd).then(() => toast("Copied")) }, "Copy command"));
    } catch (e) { toast(e.message, true); }
  } }, "Mint token");
  panel.replaceChildren(h("h2", {}, "Enrollment token"),
    h("label", {}, "Expires in (hours) "), hours, h("label", {}, " Max uses (0=unlimited) "), uses, mint, out);
}

async function tabPolicy(orgID, panel) {
  const p = await api("GET", "/admin/orgs/" + orgID + "/policy") || {};
  const image = h("input", { value: p.image || "redactr-base:local" });
  const mount = h("select", {});
  for (const m of ["bind", "diffback"]) { const o = h("option", { value: m }, m); if (p.mountMode === m) o.selected = true; mount.append(o); }
  const deny = h("textarea", { rows: "6" }, (p.denylist || []).join("\n"));
  const save = h("button", { class: "btn", onclick: async () => {
    const body = { image: image.value.trim(), mountMode: mount.value, denylist: deny.value.split("\n").map(s => s.trim()).filter(Boolean) };
    try { const r = await api("PUT", "/admin/orgs/" + orgID + "/policy", body); toast("Saved policy v" + r.version); } catch (e) { toast(e.message, true); }
  } }, "Save policy");
  panel.replaceChildren(h("h2", {}, "Policy (v" + (p.version || 0) + ")"),
    h("label", {}, "Image"), image, h("label", {}, "Mount mode"), mount, h("label", {}, "Denylist (one host per line)"), deny, save);
}

let eventsTimer = null;
async function tabEvents(orgID, panel) {
  async function load() {
    const evs = await api("GET", "/admin/orgs/" + orgID + "/events?limit=100") || [];
    if (!evs.length) { panel.replaceChildren(h("h2", {}, "Events"), h("p", { class: "empty" }, "No events yet.")); return; }
    const tbl = h("table", {}, h("tr", {}, h("th", {}, "Device"), h("th", {}, "Tool"), h("th", {}, "Verdict"), h("th", {}, "Reason"), h("th", {}, "Conns"), h("th", {}, "Seen")));
    for (const e of evs) {
      tbl.append(h("tr", { class: e.verdict === "runaway" ? "danger" : "" },
        h("td", { class: "mono" }, (e.device_id || "").slice(0, 8)), h("td", {}, e.tool), h("td", {}, e.verdict),
        h("td", {}, e.reason), h("td", {}, String(e.direct_conn_count)), h("td", {}, fmtTime(e.received_at))));
    }
    panel.replaceChildren(h("h2", {}, "Events (auto-refresh 10s)"), tbl);
  }
  await load();
  if (eventsTimer) clearInterval(eventsTimer);
  eventsTimer = setInterval(() => { if (location.hash.includes("/events")) load().catch(() => {}); else { clearInterval(eventsTimer); eventsTimer = null; } }, 10000);
}

function fmtTime(t) { if (!t) return "—"; const d = new Date(t); return isNaN(d) ? "—" : d.toLocaleString(); }

function render() {
  if (!adminKey()) { renderGate(); return; }
  document.getElementById("whoami").textContent = "admin";
  const parts = location.hash.replace(/^#\//, "").split("/");
  if (parts[0] === "org" && parts[1]) renderOrg(parts[1]).catch((e) => toast(e.message, true));
  else renderOrgs().catch((e) => toast(e.message, true));
}

window.addEventListener("hashchange", render);
window.addEventListener("DOMContentLoaded", render);
render();
```

> NOTE: with Task 1 Step 0 adding json tags to `store.Org`/`store.Device`, the admin API is now uniformly **snake_case** — orgs (`o.id`, `o.name`), devices (`d.id`, `d.name`, `d.platform`, `d.revoked`, `d.enrolled_at`, `d.last_seen_at`), events (`e.device_id`, `e.verdict`, `e.received_at`, `e.direct_conn_count`), and policy (`image`, `mountMode`, `denylist`, `version` from `control.PolicyBundle`). The JS above uses these exactly.

- [ ] **Step 4: verify serving + commit**
Run: `go test ./internal/server/httpapi/ -v` (the Task-1 serving test still passes with the real assets), `go build ./...`, `CGO_ENABLED=0 GOOS=linux go build ./cmd/redactr-server/`. Manually sanity-check the JS for syntax with `node --check internal/server/httpapi/dashboard/app.js` if node is available (optional).
```bash
git add internal/server/httpapi/dashboard/
git commit -m "feat(dashboard): admin UI — orgs, devices, enrollment, policy, events"
```

---

## Final verification
```bash
go build ./... && go test ./internal/... 2>&1 | grep -v "no test files" && go vet ./... \
  && CGO_ENABLED=0 GOOS=linux go build ./cmd/redactr-server/
```

**Manual (deferred to a running server):** `REDACTR_ADMIN_KEY=secret ./redactr-server` → open `http://localhost:8080/` → enter key → create org → mint token → `redactr enroll ...` on a device → see it in Devices + Events → edit policy.

## Self-Review map
- embed + route + precedence test → T1; full dashboard (key gate + orgs + device registry/revoke + enrollment mint + policy editor + events feed/stats + runaway alert) → T2. Image-management tab deferred to A3. JSON casing per-endpoint documented (PascalCase orgs/devices, snake_case events) to avoid a silent field-mismatch.
