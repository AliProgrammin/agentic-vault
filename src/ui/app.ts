// Single-page UI, inlined. No build step, no framework.
//
// The server emits this as GET /. It ships with its own CSS + vanilla
// JS. All API calls go to /api/* with `credentials: 'same-origin'` so
// the session cookie travels automatically. No CDN, no analytics, no
// external fonts.

export const INDEX_HTML = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Agentic Vault</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; height: 100%; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, sans-serif; background: #0f0f10; color: #e7e7e7; }
  button { cursor: pointer; font-family: inherit; font-size: 14px; border: 1px solid #3a3a3a; background: #1b1b1b; color: #e7e7e7; border-radius: 6px; padding: 6px 12px; }
  button:hover { background: #2a2a2a; }
  button.primary { background: #3b82f6; border-color: #3b82f6; color: #fff; }
  button.primary:hover { background: #2563eb; }
  button.danger { background: #7f1d1d; border-color: #7f1d1d; color: #fff; }
  button.danger:hover { background: #991b1b; }
  input, textarea, select { font-family: inherit; font-size: 14px; background: #1b1b1b; color: #e7e7e7; border: 1px solid #3a3a3a; border-radius: 6px; padding: 8px 10px; width: 100%; }
  input:focus, textarea:focus, select:focus { outline: none; border-color: #3b82f6; }
  code { font-family: "SF Mono", Menlo, Consolas, monospace; }
  .login-wrap { display: flex; align-items: center; justify-content: center; height: 100vh; }
  .login-card { width: 360px; background: #1b1b1b; border: 1px solid #2a2a2a; border-radius: 12px; padding: 32px; }
  .login-card h1 { margin: 0 0 6px; font-size: 22px; }
  .login-card p { margin: 0 0 20px; color: #9a9a9a; font-size: 13px; }
  .login-card label { display: block; font-size: 12px; color: #9a9a9a; margin-bottom: 6px; }
  .login-card .err { color: #ef4444; font-size: 13px; margin-top: 10px; min-height: 18px; }
  .app { display: grid; grid-template-columns: 220px 1fr; height: 100vh; }
  .side { background: #141414; border-right: 1px solid #262626; padding: 20px 0; }
  .brand { font-weight: 700; font-size: 16px; padding: 0 20px 20px; border-bottom: 1px solid #262626; }
  .detail-toggle { cursor: pointer; color: #3b82f6; font-size: 11px; margin-top: 4px; user-select: none; }
  .detail-panel { margin-top: 10px; background: #0a0a0a; border: 1px solid #1f1f1f; border-radius: 6px; padding: 10px; font-family: "SF Mono", Menlo, monospace; font-size: 12px; white-space: pre-wrap; word-break: break-word; max-height: 260px; overflow: auto; color: #c4c4c4; }
  .detail-label { color: #9a9a9a; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 8px; }
  .detail-label:first-child { margin-top: 0; }
  .nav { padding: 10px 0; }
  .nav a { display: block; padding: 10px 20px; color: #b4b4b4; text-decoration: none; cursor: pointer; font-size: 14px; border-left: 3px solid transparent; }
  .nav a.active { color: #fff; background: #1c1c1c; border-left-color: #3b82f6; }
  .nav a:hover { color: #fff; }
  .main { overflow: auto; padding: 24px 32px; }
  .topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
  .topbar h2 { margin: 0; font-size: 18px; }
  .topbar .controls { display: flex; gap: 8px; align-items: center; }
  .session-info { font-size: 12px; color: #9a9a9a; margin-right: 10px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 10px; border-bottom: 1px solid #2a2a2a; color: #9a9a9a; font-weight: 500; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
  td { padding: 12px 10px; border-bottom: 1px solid #1f1f1f; }
  tr:hover td { background: #161616; }
  .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 500; }
  .tag.global { background: #1e3a5f; color: #93c5fd; }
  .tag.project { background: #3f1f5c; color: #c4b5fd; }
  .tag.allowed { background: #064e3b; color: #6ee7b7; }
  .tag.denied { background: #5a1d1d; color: #fca5a5; }
  .actions { display: flex; gap: 6px; }
  .actions button { padding: 4px 8px; font-size: 12px; }
  .modal-bg { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.7); display: flex; align-items: center; justify-content: center; z-index: 10; }
  .modal { background: #1b1b1b; border: 1px solid #2a2a2a; border-radius: 12px; padding: 24px; width: 560px; max-height: 85vh; overflow: auto; }
  .modal h3 { margin: 0 0 16px; }
  .modal .row { margin-bottom: 14px; }
  .modal .row label { display: block; font-size: 12px; color: #9a9a9a; margin-bottom: 6px; }
  .modal .row textarea { min-height: 120px; font-family: "SF Mono", Menlo, monospace; font-size: 12px; }
  .modal .footer { display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px; }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; padding: 6px; background: #141414; border: 1px solid #2a2a2a; border-radius: 6px; min-height: 40px; }
  .chip { display: inline-flex; align-items: center; gap: 6px; background: #2a2a2a; padding: 4px 10px; border-radius: 4px; font-size: 12px; }
  .chip button { background: transparent; border: none; color: #9a9a9a; padding: 0; font-size: 14px; }
  .chips input { border: none; background: transparent; padding: 4px; flex: 1; min-width: 160px; }
  .chips input:focus { border: none; }
  .filters { display: flex; gap: 10px; margin-bottom: 14px; }
  .filters input, .filters select { width: auto; min-width: 160px; }
  .reveal-box { font-family: "SF Mono", Menlo, monospace; font-size: 13px; background: #0a0a0a; border: 1px solid #2a2a2a; padding: 10px; border-radius: 6px; word-break: break-all; margin-top: 8px; }
  .empty { text-align: center; color: #6a6a6a; padding: 40px; font-size: 14px; }
  .err-banner { background: #3a1818; border: 1px solid #7f1d1d; color: #fca5a5; padding: 10px 14px; border-radius: 6px; margin-bottom: 14px; font-size: 13px; }
  .ok-banner { background: #0f2e1e; border: 1px solid #065f46; color: #6ee7b7; padding: 10px 14px; border-radius: 6px; margin-bottom: 14px; font-size: 13px; }
  .detail-wrap { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  @media (max-width: 900px) { .detail-wrap { grid-template-columns: 1fr; } }
  .detail-pane { background: #141414; border: 1px solid #262626; border-radius: 8px; padding: 16px; }
  .detail-pane h3 { margin: 0 0 12px; font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em; color: #9a9a9a; }
  .meta-row { display: grid; grid-template-columns: 120px 1fr; gap: 10px; padding: 4px 0; font-size: 13px; border-bottom: 1px solid #1f1f1f; }
  .meta-row:last-child { border-bottom: 0; }
  .meta-row .k { color: #9a9a9a; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; padding-top: 4px; }
  .meta-row .v { font-family: "SF Mono", Menlo, monospace; font-size: 12px; word-break: break-all; }
  .copy-btn { font-size: 11px; padding: 2px 6px; margin-left: 6px; }
  .timeline { display: flex; gap: 8px; margin-bottom: 14px; flex-wrap: wrap; }
  .timeline .stage { display: flex; flex-direction: column; background: #1c1c1c; border: 1px solid #2a2a2a; border-radius: 6px; padding: 6px 10px; min-width: 140px; }
  .timeline .stage .s-name { color: #93c5fd; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; }
  .timeline .stage .s-ts { color: #b4b4b4; font-size: 11px; font-family: "SF Mono", Menlo, monospace; }
  .timeline .stage .s-delta { color: #6ee7b7; font-size: 11px; font-family: "SF Mono", Menlo, monospace; }
  .tabs { display: flex; gap: 4px; margin-bottom: 8px; }
  .tabs button { padding: 4px 10px; font-size: 12px; }
  .tabs button.active { background: #3b82f6; border-color: #3b82f6; color: #fff; }
  .body-view { background: #0a0a0a; border: 1px solid #1f1f1f; border-radius: 6px; padding: 10px; font-family: "SF Mono", Menlo, monospace; font-size: 12px; white-space: pre-wrap; word-break: break-word; max-height: 500px; overflow: auto; }
  .redacted-pill { display: inline-block; padding: 1px 6px; background: #78350f; color: #fbbf24; border: 1px solid #f59e0b; border-radius: 4px; font-size: 11px; font-family: "SF Mono", Menlo, monospace; }
  .scrubbed-badge { display: inline-block; padding: 1px 6px; margin-left: 6px; background: #422006; color: #fbbf24; border: 1px solid #b45309; border-radius: 4px; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
  .scrubbed-badge::before { content: "⊘ "; }
  .cutoff-bar { display: flex; align-items: center; gap: 8px; margin-top: 8px; padding: 6px 10px; background: #422006; border: 1px solid #b45309; color: #fbbf24; border-radius: 4px; font-size: 12px; font-family: "SF Mono", Menlo, monospace; }
  .cutoff-bar::before { content: "✂"; font-size: 14px; }
  .empty-block { display: flex; align-items: center; gap: 8px; padding: 12px; background: #0a0a0a; border: 1px dashed #2a2a2a; color: #9a9a9a; border-radius: 6px; font-size: 12px; font-style: italic; }
  .empty-block::before { content: "∅"; font-size: 14px; color: #6a6a6a; }
  .pruned-block { display: flex; align-items: center; gap: 8px; padding: 12px; background: #1a1a2e; border: 1px dashed #4338ca; color: #a5b4fc; border-radius: 6px; font-size: 12px; }
  .pruned-block::before { content: "🗑"; }
  .decrypt-failed { display: flex; align-items: center; gap: 8px; padding: 12px; background: #3a1818; border: 1px solid #7f1d1d; color: #fca5a5; border-radius: 6px; font-size: 12px; }
  .decrypt-failed::before { content: "⚠"; }
  .headers-table { width: 100%; font-size: 12px; font-family: "SF Mono", Menlo, monospace; }
  .headers-table th { cursor: pointer; user-select: none; }
  .header-row.scrubbed-header { background: rgba(120, 53, 15, 0.2); }
  .toast { position: fixed; bottom: 24px; right: 24px; background: #065f46; color: #6ee7b7; padding: 10px 16px; border-radius: 8px; font-size: 13px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5); z-index: 20; }
  .permalink { color: #9a9a9a; font-size: 11px; display: inline-flex; align-items: center; gap: 6px; margin-left: 10px; }
  .permalink code { color: #3b82f6; background: #1a1a1a; padding: 2px 6px; border-radius: 4px; }
  .section { margin-bottom: 16px; }
  .kbd { display: inline-block; padding: 1px 5px; background: #262626; border: 1px solid #3a3a3a; border-bottom-width: 2px; border-radius: 3px; font-family: "SF Mono", Menlo, monospace; font-size: 10px; }
</style>
</head>
<body>
<div id="root"></div>
<script>
(() => {
  "use strict";
  const root = document.getElementById("root");

  const api = {
    async json(path, opts) {
      opts = opts || {};
      const res = await fetch(path, Object.assign({ credentials: "same-origin" }, opts, {
        headers: Object.assign({ "Content-Type": "application/json", "Accept": "application/json" }, opts.headers || {}),
      }));
      if (!res.ok && res.status === 401) return { _unauth: true };
      return res.json();
    },
  };

  const state = {
    view: "secrets",
    loggedIn: false,
    secrets: [],
    templates: [],
    audit: [],
    err: null,
    ok: null,
    modal: null,
    detail: null,
    detailBodyTab: "pretty",
    toast: null,
    auditFilters: { secret: "", tool: "", outcome: "" },
  };

  function showToast(msg) {
    state.toast = msg;
    render();
    setTimeout(() => { if (state.toast === msg) { state.toast = null; render(); } }, 1800);
  }

  function copyText(value) {
    if (typeof navigator !== "undefined" && navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      navigator.clipboard.writeText(value).then(() => showToast("Copied"), () => showToast("Copy failed"));
    } else {
      showToast("Clipboard unavailable");
    }
  }

  function copyButton(value, label) {
    return h("button", { class: "copy-btn", onclick: (e) => { e.stopPropagation(); copyText(value); } }, label || "Copy");
  }

  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    if (props) {
      for (const k of Object.keys(props)) {
        if (k === "class") el.className = props[k];
        else if (k === "html") el.innerHTML = props[k];
        else if (k.startsWith("on") && typeof props[k] === "function") el.addEventListener(k.slice(2).toLowerCase(), props[k]);
        else if (k in el) el[k] = props[k];
        else el.setAttribute(k, props[k]);
      }
    }
    for (const kid of kids.flat()) {
      if (kid == null) continue;
      if (typeof kid === "string" || typeof kid === "number") el.appendChild(document.createTextNode(String(kid)));
      else el.appendChild(kid);
    }
    return el;
  }

  function render() {
    root.innerHTML = "";
    if (!state.loggedIn) return renderLogin();
    const app = h("div", { class: "app" });
    app.appendChild(renderSide());
    const main = h("div", { class: "main" });
    if (state.err) main.appendChild(h("div", { class: "err-banner" }, state.err));
    if (state.ok) main.appendChild(h("div", { class: "ok-banner" }, state.ok));
    if (state.view === "secrets") main.appendChild(renderSecrets());
    else if (state.view === "audit") main.appendChild(renderAudit());
    else if (state.view === "audit-detail") main.appendChild(renderAuditDetail());
    app.appendChild(main);
    root.appendChild(app);
    if (state.modal) root.appendChild(state.modal());
    if (state.toast) {
      const t = h("div", { class: "toast", role: "status", "aria-live": "polite" }, state.toast);
      root.appendChild(t);
    }
  }

  function renderLogin() {
    const pwInput = h("input", { type: "password", autofocus: true, placeholder: "master password", autocomplete: "off", name: "vault-unlock", "data-lpignore": "true", "data-form-type": "other" });
    const errEl = h("div", { class: "err" }, "");
    const submit = async () => {
      errEl.textContent = "";
      const r = await api.json("/api/login", { method: "POST", body: JSON.stringify({ password: pwInput.value }) });
      if (r && r.ok) { state.loggedIn = true; await loadAll(); render(); return; }
      errEl.textContent = (r && r.error) || "login failed";
    };
    pwInput.addEventListener("keydown", e => { if (e.key === "Enter") submit(); });
    const card = h("div", { class: "login-card" },
      h("h1", {}, "Agentic Vault"),
      h("p", {}, "Enter the master password to unlock the vault."),
      h("label", {}, "Master password"),
      pwInput,
      errEl,
      h("div", { style: "margin-top: 16px;" },
        h("button", { class: "primary", style: "width: 100%;", onclick: submit }, "Unlock")
      )
    );
    root.appendChild(h("div", { class: "login-wrap" }, card));
  }

  function renderSide() {
    return h("div", { class: "side" },
      h("div", { class: "brand" }, "Agentic Vault"),
      h("div", { class: "nav" },
        h("a", {
          class: state.view === "secrets" ? "active" : "",
          href: "#secrets",
          onclick: () => { state.view = "secrets"; render(); },
        }, "Secrets"),
        h("a", {
          class: state.view === "audit" ? "active" : "",
          href: "#audit",
          onclick: () => { state.view = "audit"; loadAudit().then(render); },
        }, "Audit log"),
      ),
      h("div", { style: "position: absolute; bottom: 20px; left: 20px;" },
        h("button", { onclick: logout }, "Log out")
      )
    );
  }

  function renderSecrets() {
    const frag = document.createDocumentFragment();
    const top = h("div", { class: "topbar" },
      h("h2", {}, "Secrets"),
      h("div", { class: "controls" },
        h("button", { class: "primary", onclick: () => openAddModal() }, "+ Add secret"),
      )
    );
    frag.appendChild(top);
    if (state.secrets.length === 0) {
      frag.appendChild(h("div", { class: "empty" }, "No secrets yet. Add one to get started."));
      return frag;
    }
    const table = h("table");
    table.appendChild(h("thead", {}, h("tr", {},
      h("th", {}, "Name"),
      h("th", {}, "Scope"),
      h("th", {}, "Policy"),
      h("th", {}, "Updated"),
      h("th", {}, "Actions"),
    )));
    const tbody = h("tbody");
    for (const s of state.secrets) {
      tbody.appendChild(h("tr", {},
        h("td", {}, h("code", {}, s.name)),
        h("td", {}, h("span", { class: "tag " + s.scope }, s.scope)),
        h("td", {}, s.has_policy
          ? ("hosts: " + s.hosts_count + " · cmds: " + s.commands_count + " · env: " + s.env_vars_count)
          : h("span", { style: "color: #ef4444;" }, "none (deny)")),
        h("td", {}, new Date(s.updated_at).toLocaleString()),
        h("td", {}, h("div", { class: "actions" },
          h("button", { onclick: () => revealSecret(s) }, "Reveal"),
          h("button", { onclick: () => openPolicyModal(s) }, "Policy"),
          h("button", { class: "danger", onclick: () => removeSecret(s) }, "Remove"),
        )),
      ));
    }
    table.appendChild(tbody);
    frag.appendChild(table);
    return frag;
  }

  function renderAudit() {
    const frag = document.createDocumentFragment();
    frag.appendChild(h("div", { class: "topbar" },
      h("h2", {}, "Audit log"),
      h("div", { class: "controls" }, h("button", { onclick: () => loadAudit().then(render) }, "Refresh"))
    ));
    const filters = h("div", { class: "filters" });
    const fSecret = h("input", { placeholder: "filter by secret name" });
    const fTool = h("select" );
    for (const v of ["", "http_request", "run_command"]) fTool.appendChild(h("option", { value: v }, v || "any tool"));
    const fOutcome = h("select");
    for (const v of ["", "allowed", "denied"]) fOutcome.appendChild(h("option", { value: v }, v || "any outcome"));
    const apply = h("button", { onclick: async () => {
      await loadAudit({ secret: fSecret.value, tool: fTool.value, outcome: fOutcome.value });
      render();
    } }, "Apply");
    filters.append(fSecret, fTool, fOutcome, apply);
    frag.appendChild(filters);
    if (state.audit.length === 0) {
      frag.appendChild(h("div", { class: "empty" }, "No audit events yet. Run a tool call to see entries here."));
      return frag;
    }
    const table = h("table");
    table.appendChild(h("thead", {}, h("tr", {},
      h("th", {}, "Time"),
      h("th", {}, "Tool"),
      h("th", {}, "Secret"),
      h("th", {}, "Target"),
      h("th", {}, "Outcome"),
      h("th", {}, "Reason"),
    )));
    const tbody = h("tbody");
    for (const ev of [...state.audit].reverse()) {
      const openBtn = h("button", {
        onclick: () => { location.hash = "#/audit/" + encodeURIComponent(ev.request_id); },
        style: "margin-right: 6px;",
      }, "open");
      const reasonCell = h("td", {},
        ev.reason || ev.code || "",
      );
      if (ev.detail) {
        const shouldAutoExpand = location.hash.includes("expand");
        const toggle = h("div", { class: "detail-toggle" }, shouldAutoExpand ? "▾ details" : "▸ details");
        const panel = h("div", { class: "detail-panel", style: shouldAutoExpand ? "display: block;" : "display: none;" });
        renderDetail(panel, ev);
        toggle.addEventListener("click", () => {
          const open = panel.style.display !== "none";
          panel.style.display = open ? "none" : "block";
          toggle.textContent = open ? "▸ details" : "▾ details";
        });
        reasonCell.appendChild(toggle);
        reasonCell.appendChild(panel);
      }
      tbody.appendChild(h("tr", {},
        h("td", {}, openBtn, new Date(ev.ts).toLocaleString()),
        h("td", {}, h("code", {}, ev.tool)),
        h("td", {}, h("code", {}, ev.secret_name)),
        h("td", {}, ev.target),
        h("td", {}, h("span", { class: "tag " + ev.outcome }, ev.outcome)),
        reasonCell,
      ));
    }
    table.appendChild(tbody);
    frag.appendChild(table);
    return frag;
  }

  function renderDetail(host, ev) {
    const d = ev.detail || {};
    function sec(label, value) {
      if (value === undefined || value === null || value === "") return;
      host.appendChild(h("div", { class: "detail-label" }, label));
      const v = typeof value === "object" ? JSON.stringify(value, null, 2) : String(value);
      host.appendChild(h("div", {}, v));
    }
    if (ev.tool === "http_request") {
      sec("Method", d.method);
      sec("URL", d.url);
      sec("Request body", d.request_body);
      sec("Response status", d.response_status);
      sec("Response body (scrubbed)", d.response_body);
    } else if (ev.tool === "run_command") {
      sec("Binary", ev.target);
      sec("Argv", d.argv);
      sec("Exit code", d.exit_code);
      sec("Stdout (scrubbed)", d.stdout);
      sec("Stderr (scrubbed)", d.stderr);
    } else {
      sec("Detail", d);
    }
  }

  async function loadAll() {
    state.err = null;
    await Promise.all([loadSecrets(), loadTemplates()]);
  }
  async function loadSecrets() {
    const r = await api.json("/api/secrets");
    if (r && r._unauth) { state.loggedIn = false; return; }
    state.secrets = (r && r.secrets) || [];
  }
  async function loadTemplates() {
    const r = await api.json("/api/policy-templates");
    if (r && r._unauth) { state.loggedIn = false; return; }
    state.templates = (r && r.templates) || [];
  }
  async function loadAudit(filter) {
    filter = filter || {};
    const qs = [];
    if (filter.secret) qs.push("secret=" + encodeURIComponent(filter.secret));
    if (filter.tool) qs.push("tool=" + encodeURIComponent(filter.tool));
    if (filter.outcome) qs.push("outcome=" + encodeURIComponent(filter.outcome));
    const r = await api.json("/api/audit" + (qs.length ? "?" + qs.join("&") : ""));
    if (r && r._unauth) { state.loggedIn = false; return; }
    state.audit = (r && r.events) || [];
  }

  async function logout() {
    await api.json("/api/logout", { method: "POST" });
    state.loggedIn = false; state.secrets = []; state.audit = [];
    render();
  }

  async function revealSecret(s) {
    const r = await api.json("/api/secrets/" + encodeURIComponent(s.name) + "/reveal?scope=" + s.scope);
    if (r && r._unauth) { state.loggedIn = false; render(); return; }
    state.modal = () => {
      const close = () => { state.modal = null; render(); };
      return modalBg(close, h("div", { class: "modal" },
        h("h3", {}, s.name),
        h("div", { class: "reveal-box" }, r.value),
        h("div", { class: "footer" },
          h("button", { onclick: () => { navigator.clipboard.writeText(r.value); } }, "Copy"),
          h("button", { class: "primary", onclick: close }, "Close"),
        )
      ));
    };
    render();
  }

  async function removeSecret(s) {
    if (!confirm("Remove " + s.name + " from " + s.scope + " vault?")) return;
    const r = await api.json("/api/secrets/" + encodeURIComponent(s.name) + "?scope=" + s.scope, { method: "DELETE" });
    if (r && r._unauth) { state.loggedIn = false; render(); return; }
    if (r && r.ok) { state.ok = "Removed " + s.name; await loadSecrets(); setTimeout(() => { state.ok = null; render(); }, 2500); }
    else { state.err = (r && r.error) || "remove failed"; }
    render();
  }

  function modalBg(onBg, content) {
    const bg = h("div", { class: "modal-bg", onclick: (e) => { if (e.target === bg) onBg(); } }, content);
    return bg;
  }

  function emptyPolicy() {
    return { allowed_http_hosts: [], allowed_commands: [], allowed_env_vars: [], rate_limit: { requests: 60, window_seconds: 60 } };
  }

  function openAddModal() {
    let policy = emptyPolicy();
    let name = "", value = "", scope = "global";
    const tplSel = h("select");
    tplSel.appendChild(h("option", { value: "" }, "-- pick template --"));
    for (const t of state.templates) tplSel.appendChild(h("option", { value: t.name }, t.name));
    tplSel.addEventListener("change", () => {
      const t = state.templates.find(x => x.name === tplSel.value);
      if (t) { policy = JSON.parse(JSON.stringify(t.policy)); name = t.name; nameInput.value = name; rerenderPolicy(); }
    });
    const nameInput = h("input", { placeholder: "SECRET_NAME (uppercase_with_underscores)", oninput: (e) => name = e.target.value });
    const valueInput = h("input", { type: "password", placeholder: "secret value", oninput: (e) => value = e.target.value });
    const scopeSel = h("select", { onchange: (e) => scope = e.target.value });
    scopeSel.appendChild(h("option", { value: "global" }, "global"));
    scopeSel.appendChild(h("option", { value: "project" }, "project"));
    const policyHost = h("div");
    const rerenderPolicy = () => {
      policyHost.innerHTML = "";
      policyHost.appendChild(renderPolicyForm(policy));
    };
    rerenderPolicy();
    const close = () => { state.modal = null; render(); };
    const submit = async () => {
      if (!name || !value) { state.err = "name and value required"; render(); return; }
      const r = await api.json("/api/secrets", { method: "POST", body: JSON.stringify({ name, value, scope, policy }) });
      if (r && r.ok) {
        state.ok = "Added " + name;
        state.modal = null;
        await loadSecrets(); render();
        setTimeout(() => { state.ok = null; render(); }, 2500);
      } else {
        state.err = (r && r.error) || "add failed"; render();
      }
    };
    state.modal = () => modalBg(close, h("div", { class: "modal" },
      h("h3", {}, "Add secret"),
      h("div", { class: "row" }, h("label", {}, "Template (optional)"), tplSel),
      h("div", { class: "row" }, h("label", {}, "Name"), nameInput),
      h("div", { class: "row" }, h("label", {}, "Value"), valueInput),
      h("div", { class: "row" }, h("label", {}, "Scope"), scopeSel),
      h("div", { class: "row" }, h("label", {}, "Policy"), policyHost),
      h("div", { class: "footer" },
        h("button", { onclick: close }, "Cancel"),
        h("button", { class: "primary", onclick: submit }, "Add"),
      )
    ));
    render();
  }

  async function openPolicyModal(s) {
    const r = await api.json("/api/secrets/" + encodeURIComponent(s.name) + "/policy?scope=" + s.scope);
    let policy = r && r.policy ? r.policy : emptyPolicy();
    const tplSel = h("select");
    tplSel.appendChild(h("option", { value: "" }, "-- pick template --"));
    for (const t of state.templates) tplSel.appendChild(h("option", { value: t.name }, t.name));
    tplSel.addEventListener("change", () => {
      const t = state.templates.find(x => x.name === tplSel.value);
      if (t) { policy = JSON.parse(JSON.stringify(t.policy)); rerenderPolicy(); }
    });
    const policyHost = h("div");
    const rerenderPolicy = () => {
      policyHost.innerHTML = "";
      policyHost.appendChild(renderPolicyForm(policy));
    };
    rerenderPolicy();
    const close = () => { state.modal = null; render(); };
    const submit = async () => {
      const r = await api.json("/api/secrets/" + encodeURIComponent(s.name) + "/policy", {
        method: "PUT",
        body: JSON.stringify({ scope: s.scope, policy }),
      });
      if (r && r.ok) {
        state.ok = "Policy updated for " + s.name;
        state.modal = null;
        await loadSecrets(); render();
        setTimeout(() => { state.ok = null; render(); }, 2500);
      } else {
        state.err = (r && r.error) || "update failed"; render();
      }
    };
    state.modal = () => modalBg(close, h("div", { class: "modal" },
      h("h3", {}, "Policy — " + s.name),
      h("div", { class: "row" }, h("label", {}, "Apply template"), tplSel),
      policyHost,
      h("div", { class: "footer" },
        h("button", { onclick: close }, "Cancel"),
        h("button", { class: "primary", onclick: submit }, "Save"),
      )
    ));
    render();
  }

  function renderPolicyForm(policy) {
    const frag = document.createDocumentFragment();
    frag.appendChild(h("div", { class: "row" },
      h("label", {}, "Allowed hosts (FQDN, no wildcards)"),
      chipInput(policy.allowed_http_hosts, "api.example.com"),
    ));
    frag.appendChild(h("div", { class: "row" },
      h("label", {}, "Allowed env vars (UPPER_SNAKE)"),
      chipInput(policy.allowed_env_vars, "MY_VAR"),
    ));
    // Commands: list of objects
    const cmdHost = h("div");
    const rerender = () => {
      cmdHost.innerHTML = "";
      for (let i = 0; i < policy.allowed_commands.length; i++) {
        const cmd = policy.allowed_commands[i];
        cmdHost.appendChild(h("div", { style: "border: 1px solid #2a2a2a; border-radius: 6px; padding: 10px; margin-bottom: 8px;" },
          h("div", { class: "row" },
            h("label", {}, "Binary"),
            h("input", { value: cmd.binary, oninput: (e) => cmd.binary = e.target.value, placeholder: "wrangler" }),
          ),
          h("div", { class: "row" },
            h("label", {}, "Allowed args patterns (regex, ^...$)"),
            chipInput(cmd.allowed_args_patterns, "^deploy$"),
          ),
          h("button", { class: "danger", onclick: () => { policy.allowed_commands.splice(i, 1); rerender(); } }, "Remove command"),
        ));
      }
      cmdHost.appendChild(h("button", { onclick: () => {
        policy.allowed_commands.push({ binary: "", allowed_args_patterns: [] });
        rerender();
      } }, "+ Add command"));
    };
    rerender();
    frag.appendChild(h("div", { class: "row" }, h("label", {}, "Allowed commands"), cmdHost));
    const rlRow = h("div", { class: "row" },
      h("label", {}, "Rate limit (requests per window_seconds)"),
      h("div", { style: "display: flex; gap: 8px;" },
        h("input", { type: "number", min: "1", value: policy.rate_limit.requests, oninput: (e) => policy.rate_limit.requests = Math.max(1, parseInt(e.target.value, 10) || 1) }),
        h("input", { type: "number", min: "1", value: policy.rate_limit.window_seconds, oninput: (e) => policy.rate_limit.window_seconds = Math.max(1, parseInt(e.target.value, 10) || 1) }),
      )
    );
    frag.appendChild(rlRow);
    return frag;
  }

  function chipInput(arr, placeholder) {
    const wrap = h("div", { class: "chips" });
    const rerender = () => {
      wrap.innerHTML = "";
      for (let i = 0; i < arr.length; i++) {
        const v = arr[i];
        wrap.appendChild(h("span", { class: "chip" },
          v,
          h("button", { onclick: () => { arr.splice(i, 1); rerender(); } }, "×"),
        ));
      }
      const input = h("input", { placeholder });
      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === ",") {
          e.preventDefault();
          const v = input.value.trim();
          if (v) { arr.push(v); rerender(); }
        }
      });
      wrap.appendChild(input);
      if (arr.length === 0) setTimeout(() => input.focus(), 0);
    };
    rerender();
    return wrap;
  }

  function renderAuditDetail() {
    const frag = document.createDocumentFragment();
    const topbar = h("div", { class: "topbar" });
    const title = h("h2", {}, "Audit entry");
    const permalinkUrl = location.origin + location.pathname + "#/audit/" + encodeURIComponent(state.detail && state.detail.id ? state.detail.id : "");
    topbar.appendChild(h("div", {},
      title,
      h("span", { class: "permalink" },
        "permalink: ",
        h("code", {}, "#/audit/" + (state.detail ? state.detail.id : "")),
        copyButton(permalinkUrl, "copy permalink"),
      ),
    ));
    topbar.appendChild(h("div", { class: "controls" },
      h("button", { onclick: () => { location.hash = "#audit"; } }, "← Back to list"),
      h("span", { style: "margin-left:10px; color: #6a6a6a; font-size: 11px;" },
        h("span", { class: "kbd" }, "j"), "/", h("span", { class: "kbd" }, "k"), " nav ",
        h("span", { class: "kbd" }, "Esc"), " back ",
        h("span", { class: "kbd" }, "c"), " copy permalink",
      ),
    ));
    frag.appendChild(topbar);

    if (!state.detail) {
      frag.appendChild(h("div", { class: "empty" }, state.detail === null ? "Loading..." : "Not found."));
      return frag;
    }
    if (state.detail.error) {
      frag.appendChild(h("div", { class: "err-banner" }, state.detail.error));
      return frag;
    }
    const m = state.detail.model;

    // Summary metadata block + timeline
    frag.appendChild(renderSummaryBlock(m));
    frag.appendChild(renderTimeline(m.timeline));

    // side-by-side or stacked Request/Response
    const wrap = h("div", { class: "detail-wrap" });
    wrap.appendChild(renderDetailPane("Request", m.request, true));
    wrap.appendChild(renderDetailPane("Response", m.response, false));
    frag.appendChild(wrap);

    // Injected secrets + policy + rate limit + process context
    frag.appendChild(renderInjectedPane(m));
    frag.appendChild(renderReplayPane(m));
    return frag;
  }

  function renderSummaryBlock(m) {
    const pane = h("div", { class: "detail-pane section" });
    pane.appendChild(h("h3", {}, "Summary"));
    pane.appendChild(metaRow("ID", m.id, true));
    pane.appendChild(metaRow("When", m.ts, true));
    pane.appendChild(metaRow("Surface", m.surface, false));
    pane.appendChild(metaRow("Outcome", m.outcome + (m.code ? " [" + m.code + "]" : ""), false));
    if (m.reason) pane.appendChild(metaRow("Reason", m.reason, true));
    pane.appendChild(metaRow("Secret", m.secret_name, true));
    pane.appendChild(metaRow("Target", m.target, true));
    return pane;
  }

  function renderTimeline(timeline) {
    const pane = h("div", { class: "detail-pane section" });
    pane.appendChild(h("h3", {}, "Timeline" + (timeline.total_ms !== undefined ? " (" + timeline.total_ms + " ms total)" : "")));
    const strip = h("div", { class: "timeline" });
    if (!timeline.stages || timeline.stages.length === 0) {
      strip.appendChild(h("div", { class: "empty-block" }, "No timing captured in this record."));
    } else {
      for (const s of timeline.stages) {
        strip.appendChild(h("div", { class: "stage" },
          h("span", { class: "s-name" }, s.name),
          h("span", { class: "s-ts" }, s.ts || "—"),
          s.delta_ms !== undefined ? h("span", { class: "s-delta" }, "+" + s.delta_ms + " ms") : null,
        ));
      }
    }
    pane.appendChild(strip);
    return pane;
  }

  function metaRow(k, v, copy) {
    const vEl = h("span", { class: "v" }, highlightRedactionsHtml(String(v)));
    const row = h("div", { class: "meta-row" },
      h("span", { class: "k" }, k),
      h("span", {}, vEl, copy ? copyButton(String(v)) : null),
    );
    return row;
  }

  function highlightRedactionsHtml(text) {
    const frag = document.createDocumentFragment();
    const re = /\[REDACTED:[^\]]+\]/g;
    let last = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
      frag.appendChild(h("span", { class: "redacted-pill" }, m[0]));
      last = re.lastIndex;
    }
    if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
    return frag;
  }

  function renderDetailPane(title, section, isReq) {
    const pane = h("div", { class: "detail-pane" });
    pane.appendChild(h("h3", {}, title));
    if (!section || section.kind === "none") {
      pane.appendChild(h("div", { class: "empty-block" }, "not captured in this record"));
      return pane;
    }
    if (section.kind === "http") {
      if (isReq) {
        pane.appendChild(metaRow("Method", section.view.method || "?", false));
        pane.appendChild(metaRow("URL", section.view.url || "?", true));
      } else {
        pane.appendChild(metaRow("Status", String(section.view.status_code !== undefined ? section.view.status_code : "?"), false));
      }
      pane.appendChild(renderHeadersTable(section.view.headers || []));
      pane.appendChild(renderBodyBlock("Body", section.view.body));
    } else if (section.kind === "command") {
      if (isReq) {
        pane.appendChild(metaRow("Binary", section.view.binary || "?", true));
        pane.appendChild(metaRow("Args", JSON.stringify(section.view.args || []), true));
        if (section.view.cwd) pane.appendChild(metaRow("Cwd", section.view.cwd, true));
        pane.appendChild(metaRow("Env keys", JSON.stringify(section.view.env_keys || []), false));
      } else {
        pane.appendChild(metaRow("Exit", String(section.view.exit_code !== undefined ? section.view.exit_code : "?"), false));
        pane.appendChild(renderBodyBlock("Stdout", section.view.stdout));
        pane.appendChild(renderBodyBlock("Stderr", section.view.stderr));
      }
    }
    return pane;
  }

  function renderHeadersTable(headers) {
    if (!headers.length) {
      return h("div", { class: "empty-block" }, "no headers captured");
    }
    let sortKey = "name", sortDir = 1;
    const host = h("div", { class: "section" });
    function rebuild() {
      host.innerHTML = "";
      const sorted = [...headers].sort((a, b) => {
        const va = String(a[sortKey] || "").toLowerCase();
        const vb = String(b[sortKey] || "").toLowerCase();
        return va < vb ? -sortDir : va > vb ? sortDir : 0;
      });
      const table = h("table", { class: "headers-table" });
      table.appendChild(h("thead", {}, h("tr", {},
        h("th", { onclick: () => { sortKey = "name"; sortDir = -sortDir; rebuild(); } }, "Header"),
        h("th", { onclick: () => { sortKey = "value"; sortDir = -sortDir; rebuild(); } }, "Value"),
      )));
      const tbody = h("tbody");
      for (const row of sorted) {
        const cls = row.scrubbed ? "header-row scrubbed-header" : "header-row";
        const valueCell = h("td", {}, highlightRedactionsHtml(String(row.value)));
        if (row.scrubbed) valueCell.appendChild(h("span", { class: "scrubbed-badge", "aria-label": "header value scrubbed" }, "scrubbed"));
        tbody.appendChild(h("tr", { class: cls },
          h("td", {}, String(row.name)),
          valueCell,
        ));
      }
      table.appendChild(tbody);
      host.appendChild(table);
    }
    rebuild();
    return host;
  }

  function renderBodyBlock(label, body) {
    const wrap = h("div", { class: "section" });
    wrap.appendChild(h("div", { class: "meta-row" }, h("span", { class: "k" }, label), h("span", {})));
    if (!body || body.status === "not_captured") {
      wrap.appendChild(h("div", { class: "empty-block" }, "not captured in this record"));
      return wrap;
    }
    if (body.status === "pruned") {
      wrap.appendChild(h("div", { class: "pruned-block" }, "body pruned per retention policy — metadata retained"));
      return wrap;
    }
    if (body.status === "decrypt_failed") {
      wrap.appendChild(h("div", { class: "decrypt-failed" }, "decryption failed: " + (body.error || "authenticated-decrypt error")));
      return wrap;
    }
    const a = body.artifact;
    if (!a || a.kind === "empty") {
      wrap.appendChild(h("div", { class: "empty-block" }, "empty body"));
      return wrap;
    }

    const tabs = h("div", { class: "tabs" });
    const mkTab = (name) => {
      const cls = state.detailBodyTab === name ? "active" : "";
      return h("button", { class: cls, onclick: () => { state.detailBodyTab = name; render(); } }, name);
    };
    tabs.appendChild(mkTab("pretty"));
    tabs.appendChild(mkTab("raw"));
    tabs.appendChild(mkTab("hex"));
    wrap.appendChild(tabs);

    const bodyView = h("div", { class: "body-view" });
    if (a.kind === "binary") {
      bodyView.appendChild(document.createTextNode("<binary, " + a.bytes + " bytes, sha256:" + a.sha256 + ">"));
    } else if (a.kind === "text") {
      const text = a.text || "";
      if (state.detailBodyTab === "pretty") {
        let pretty = text;
        try { pretty = JSON.stringify(JSON.parse(text), null, 2); } catch {}
        bodyView.appendChild(highlightRedactionsHtml(pretty));
      } else if (state.detailBodyTab === "raw") {
        bodyView.appendChild(highlightRedactionsHtml(text));
      } else {
        bodyView.appendChild(document.createTextNode(toHexDump(text)));
      }
    }
    wrap.appendChild(bodyView);
    if (a.kind === "text" && a.truncated) {
      wrap.appendChild(h("div", { class: "cutoff-bar" }, "truncated — " + a.truncated_bytes + " bytes elided"));
    }
    return wrap;
  }

  function toHexDump(text) {
    const bytes = new TextEncoder().encode(text);
    const lines = [];
    const cap = Math.min(bytes.length, 1024);
    for (let o = 0; o < cap; o += 16) {
      const slice = bytes.subarray(o, Math.min(o + 16, cap));
      const hex = Array.from(slice).map(b => b.toString(16).padStart(2, "0")).join(" ");
      const ascii = Array.from(slice).map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : ".").join("");
      lines.push(o.toString(16).padStart(8, "0") + "  " + hex.padEnd(47, " ") + "  " + ascii);
    }
    if (bytes.length > cap) lines.push("... (" + (bytes.length - cap) + " more bytes)");
    return lines.join("\n");
  }

  function renderInjectedPane(m) {
    const pane = h("div", { class: "detail-pane section" });
    pane.appendChild(h("h3", {}, "Injected secrets & policy"));
    if (m.injected_secrets && m.injected_secrets.length > 0) {
      for (const s of m.injected_secrets) {
        pane.appendChild(h("div", { class: "meta-row" },
          h("span", { class: "k" }, s.secret_name),
          h("span", { class: "v" }, "scope: ", s.scope, " · target: ", s.target, copyButton(s.secret_name)),
        ));
      }
    } else {
      pane.appendChild(h("div", { class: "empty-block" }, "no injections captured"));
    }
    pane.appendChild(metaRow("Policy", m.outcome + (m.code ? " [" + m.code + "]" : "") + (m.reason ? " — " + m.reason : ""), false));
    if (m.rate_limit) {
      pane.appendChild(metaRow("Rate limit", m.rate_limit.remaining + "/" + m.rate_limit.capacity + " (window " + m.rate_limit.window_seconds + "s)", false));
    }
    return pane;
  }

  function renderReplayPane(m) {
    const pane = h("div", { class: "detail-pane section" });
    pane.appendChild(h("h3", {}, "Replay context"));
    pane.appendChild(metaRow("Surface", m.process.surface, false));
    if (m.process.pid !== undefined) pane.appendChild(metaRow("PID", String(m.process.pid), false));
    pane.appendChild(metaRow("Cwd", m.process.cwd, true));
    if (m.process.argv) pane.appendChild(metaRow("Argv", JSON.stringify(m.process.argv), true));
    if (m.process.tool_name) pane.appendChild(metaRow("Tool", m.process.tool_name, false));
    pane.appendChild(metaRow("Ts", m.process.ts, true));
    return pane;
  }

  async function loadAuditDetail(id) {
    state.detail = null; render();
    const r = await api.json("/api/audit/" + encodeURIComponent(id));
    if (r && r._unauth) { state.loggedIn = false; render(); return; }
    if (r && r.error) { state.detail = { error: r.error }; render(); return; }
    state.detail = { id, model: r.model, event: r.event };
    render();
  }

  function navigateDetail(delta) {
    if (!state.detail || !state.audit || state.audit.length === 0) return;
    const idx = state.audit.findIndex(e => e.request_id === state.detail.id);
    const next = idx + delta;
    if (next < 0 || next >= state.audit.length) return;
    const neighbor = state.audit[next];
    if (neighbor && neighbor.request_id) {
      location.hash = "#/audit/" + encodeURIComponent(neighbor.request_id);
    }
  }

  window.addEventListener("keydown", (e) => {
    if (state.view !== "audit-detail") return;
    if (e.target && (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA")) return;
    if (e.key === "j") { e.preventDefault(); navigateDetail(1); }
    else if (e.key === "k") { e.preventDefault(); navigateDetail(-1); }
    else if (e.key === "Escape") { e.preventDefault(); location.hash = "#audit"; }
    else if (e.key === "c") {
      e.preventDefault();
      if (state.detail && state.detail.id) {
        copyText(location.origin + location.pathname + "#/audit/" + encodeURIComponent(state.detail.id));
      }
    }
  });

  function syncViewFromHash() {
    const raw = (location.hash || "").replace(/^#/, "");
    if (raw.startsWith("/audit/")) {
      state.view = "audit-detail";
      const id = decodeURIComponent(raw.slice("/audit/".length));
      if (state.loggedIn) { loadAuditDetail(id); }
      return;
    }
    const h = raw.split(/[?&]/)[0];
    if (h === "audit" || h === "audit-expand") state.view = "audit";
    else if (h === "secrets") state.view = "secrets";
  }
  window.addEventListener("hashchange", () => {
    syncViewFromHash();
    if (state.view === "audit" && state.loggedIn) { loadAudit().then(render); return; }
    if (state.view === "audit-detail") { render(); return; }
    render();
  });
  async function init() {
    syncViewFromHash();
    const r = await api.json("/api/session");
    if (r && r.ok) {
      state.loggedIn = true;
      await loadAll();
    }
    render();
  }
  init();
})();
</script>
</body>
</html>`;
