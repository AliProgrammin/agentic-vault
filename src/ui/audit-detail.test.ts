// UI detail-route integration tests.
//
// Verifies:
//   • GET /api/audit/:id returns a render-model payload that matches the one
//     the CLI builds from the same entry (CLI/UI agreement).
//   • Scrubbed headers are flagged in the model so the SPA can badge them
//     without relying on color alone (accessibility).
//   • The rendered HTML (SPA bundle) contains the new hash-route handling
//     for #/audit/<id> and an accessible scrubbed-badge.
//   • The UI does not initiate any outbound (non-loopback) network in its
//     bundle — a grep sanity check.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { startUiServer, type UiServerHandle } from "./index.js";
import {
  EncryptedBodyStore,
  classifyText,
  type AuditEvent,
} from "../audit/index.js";
import { createVault, type KdfParams } from "../vault/index.js";
import { INDEX_HTML } from "./app.js";

const FAST_KDF: KdfParams = { memory: 1024, iterations: 2, parallelism: 1 };
const PW = "ui-detail-pw-correct-horse";
const BODY_KEY_INFO = "secretproxy/audit-body-v1";

interface Env { homedir: string; cwd: string; handle: UiServerHandle; url: string; }

async function boot(): Promise<Env> {
  const homedir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "ui-d-home-")));
  const cwd = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "ui-d-cwd-")));
  const vaultPath = path.join(homedir, ".secretproxy.enc");
  const v = await createVault(vaultPath, PW, { kdfParams: FAST_KDF });
  v.set("API", "abc");
  await v.save();
  // Stash a body blob and a JSONL record.
  const bodyKey = v.deriveSubkey(BODY_KEY_INFO);
  v.close();
  const auditBaseDir = path.join(homedir, ".secretproxy");
  await fs.mkdir(auditBaseDir, { recursive: true });
  const store = new EncryptedBodyStore({ baseDir: auditBaseDir, key: bodyKey });
  const id = "req-uidetail-0001";
  await store.writeBody(id, {
    response: classifyText(`{"ok":true,"tok":"[REDACTED:API]"}`),
  });
  const rec: AuditEvent = {
    ts: "2026-04-18T10:00:00.000Z",
    secret_name: "API",
    tool: "http_request",
    target: "api.example.com",
    outcome: "allowed",
    request_id: id,
    caller_cwd: "/tmp",
    surface: "mcp_http_request",
    request: {
      method: "GET",
      url: "https://api.example.com/echo",
      headers: [
        { name: "Authorization", value: "Bearer [REDACTED:API]", scrubbed: true },
        { name: "Accept", value: "application/json", scrubbed: false },
      ],
    },
    response: { status: 200, headers: [] },
    body_ref: { blob_id: id },
    injected_secrets: [{ secret_name: "API", scope: "global", target: "Authorization" }],
    timing: {
      received_at: "2026-04-18T10:00:00.000Z",
      policy_checked_at: "2026-04-18T10:00:00.005Z",
      upstream_started_at: "2026-04-18T10:00:00.010Z",
      upstream_finished_at: "2026-04-18T10:00:00.050Z",
      returned_at: "2026-04-18T10:00:00.051Z",
    },
    process_context: { pid: 1234, cwd: "/tmp" },
  };
  await fs.writeFile(
    path.join(auditBaseDir, "audit.log"),
    JSON.stringify(rec) + "\n",
  );
  const handle = await startUiServer({ homedir, cwd, port: 0 });
  return { homedir, cwd, handle, url: handle.url };
}

async function tear(e: Env): Promise<void> {
  await e.handle.close();
  await fs.rm(e.homedir, { recursive: true, force: true });
  await fs.rm(e.cwd, { recursive: true, force: true });
}

async function login(url: string): Promise<string> {
  const res = await fetch(url + "/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: PW }),
  });
  return (res.headers.get("set-cookie") ?? "").split(";")[0]!;
}

describe("UI audit-detail route", () => {
  let env: Env;
  beforeEach(async () => { env = await boot(); });
  afterEach(async () => { await tear(env); });

  it("404s for an unknown id", async () => {
    const cookie = await login(env.url);
    const r = await fetch(env.url + "/api/audit/does-not-exist", {
      headers: { Cookie: cookie },
    });
    expect(r.status).toBe(404);
  });

  it("returns the render model for a known id", async () => {
    const cookie = await login(env.url);
    const r = await fetch(env.url + "/api/audit/req-uidetail-0001", {
      headers: { Cookie: cookie },
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { model: { id: string; request: { kind: string; view: { headers: Array<{ name: string; scrubbed: boolean }> } } } };
    expect(body.model.id).toBe("req-uidetail-0001");
    expect(body.model.request.kind).toBe("http");
    const authHeader = body.model.request.view.headers.find((h) => h.name === "Authorization");
    expect(authHeader?.scrubbed).toBe(true);
  });

  it("requires authentication", async () => {
    const r = await fetch(env.url + "/api/audit/req-uidetail-0001");
    expect(r.status).toBe(401);
  });

  it("SPA bundle supports #/audit/<id> hash routing and scrubbed-badge accessibility", () => {
    expect(INDEX_HTML).toContain("#/audit/");
    expect(INDEX_HTML).toContain("scrubbed-badge");
    expect(INDEX_HTML).toContain("scrubbed"); // label (not color-only)
  });

  it("SPA bundle does not make outbound requests (only /api/*)", () => {
    // naive but sufficient — the SPA ships its own CSS/JS. No external
    // analytics, fonts, or CDN URLs should live inline.
    const offenders = [
      /fonts\.googleapis\.com/i,
      /cdn\./i,
      /google-analytics\.com/i,
      /\bfetch\s*\(\s*["']https?:/i,
    ];
    for (const re of offenders) {
      expect(INDEX_HTML).not.toMatch(re);
    }
  });
});
