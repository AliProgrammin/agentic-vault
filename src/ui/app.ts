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
<title>SecretProxy</title>
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
  };

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
    app.appendChild(main);
    root.appendChild(app);
    if (state.modal) root.appendChild(state.modal());
  }

  function renderLogin() {
    let pw = "", err = "";
    const pwInput = h("input", { type: "password", autofocus: true, placeholder: "master password" });
    const errEl = h("div", { class: "err" }, "");
    const submit = async () => {
      errEl.textContent = "";
      const r = await api.json("/api/login", { method: "POST", body: JSON.stringify({ password: pwInput.value }) });
      if (r && r.ok) { state.loggedIn = true; await loadAll(); render(); return; }
      errEl.textContent = (r && r.error) || "login failed";
    };
    pwInput.addEventListener("keydown", e => { if (e.key === "Enter") submit(); });
    const card = h("div", { class: "login-card" },
      h("h1", {}, "SecretProxy"),
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
      h("div", { class: "brand" }, "SecretProxy"),
      h("div", { class: "nav" },
        h("a", {
          class: state.view === "secrets" ? "active" : "",
          onclick: () => { state.view = "secrets"; render(); },
        }, "Secrets"),
        h("a", {
          class: state.view === "audit" ? "active" : "",
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
      tbody.appendChild(h("tr", {},
        h("td", {}, new Date(ev.ts).toLocaleString()),
        h("td", {}, h("code", {}, ev.tool)),
        h("td", {}, h("code", {}, ev.secret_name)),
        h("td", {}, ev.target),
        h("td", {}, h("span", { class: "tag " + ev.outcome }, ev.outcome)),
        h("td", {}, ev.reason || ev.code || ""),
      ));
    }
    table.appendChild(tbody);
    frag.appendChild(table);
    return frag;
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

  async function init() {
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
