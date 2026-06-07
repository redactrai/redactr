"use strict";

const app = document.getElementById("app");

function toast(msg, isErr) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.className = "toast" + (isErr ? " err" : "");
  setTimeout(() => (t.className = "toast hidden"), 3500);
}

async function api(method, path, body) {
  // The admin session lives in an HttpOnly cookie that JS cannot read; the
  // browser attaches it automatically on same-origin requests.
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(path, opts);
  if (resp.status === 401) { window.location.href = "/admin/login"; throw new Error("unauthorized"); }
  if (!resp.ok) throw new Error(method + " " + path + " → " + resp.status);
  const ct = resp.headers.get("Content-Type") || "";
  return ct.includes("application/json") ? resp.json() : resp.text();
}

function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const k in (attrs || {})) {
    if (k === "onclick") e.onclick = attrs[k];
    else if (k === "class") e.className = attrs[k];
    else e.setAttribute(k, attrs[k]);
  }
  for (const kid of kids) e.append(kid && kid.nodeType ? kid : document.createTextNode(kid == null ? "" : String(kid)));
  return e;
}

async function logout() {
  try { await fetch("/admin/logout", { method: "POST", credentials: "same-origin" }); }
  finally { window.location.href = "/admin/login"; }
}

async function renderOrgs() {
  const orgs = await api("GET", "/admin/orgs") || [];
  const list = h("div", { class: "card" },
    h("div", { class: "row" },
      h("h2", {}, "Organizations"),
      h("button", { class: "btn", onclick: logout }, "Logout")));
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

async function renderOrg(orgID) {
  const tabs = ["overview", "devices", "enrollment", "policy", "images", "events"];
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
    else if (cur === "images") await tabImages(orgID, panel);
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
        h("button", { class: "btn", onclick: () => navigator.clipboard.writeText(cmd).then(() => toast("Copied")).catch(() => toast("Clipboard unavailable (use HTTPS/localhost)", true)) }, "Copy command"));
    } catch (e) { toast(e.message, true); }
  } }, "Mint token");
  panel.replaceChildren(h("h2", {}, "Enrollment token"),
    h("label", {}, "Expires in (hours) "), hours, h("label", {}, " Max uses (0=unlimited) "), uses, mint, out);
}

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

async function render() {
  if (eventsTimer) { clearInterval(eventsTimer); eventsTimer = null; }
  // Confirm the session cookie is valid and learn who we are. If the cookie is
  // missing/expired, api() redirects to /admin/login and throws — so we bail
  // before rendering any content.
  let me;
  try { me = await api("GET", "/admin/me"); }
  catch (e) { return; }
  document.getElementById("whoami").textContent = (me && (me.subject || me.role)) || "admin";
  const parts = location.hash.replace(/^#\//, "").split("/");
  if (parts[0] === "org" && parts[1]) renderOrg(parts[1]).catch((e) => toast(e.message, true));
  else renderOrgs().catch((e) => toast(e.message, true));
}

window.addEventListener("hashchange", render);
window.addEventListener("DOMContentLoaded", render);
