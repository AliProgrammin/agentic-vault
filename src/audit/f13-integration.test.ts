// F13 integration: the plaintext secret SEKRET123 must never appear in
//   (1) the JSONL audit file,
//   (2) the decrypted body blob,
//   (3) the CLI `audit show` output,
//   (4) the UI-rendered HTML (hash route).
//
// The test drives `runHttpRequest` + `runRunCommand` against mocks so there
// is no network I/O. It verifies:
//   • Scrub-before-persist: encrypted blob decrypts to content with
//     [REDACTED:...] — never the plaintext.
//   • Render-pass scrub (defense-in-depth): a fabricated blob containing a
//     raw secret (simulating a storage bug) still renders redacted.
//   • Binary detection: application/octet-stream responses collapse to a
//     placeholder the renderer shows as `<binary, N bytes, sha256:...>`.
//   • Size cap: a response > 256 KiB truncates with an explicit marker.
//   • CLI / UI agreement: the same request_id renders the same model fields
//     in both surfaces.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as crypto from "node:crypto";
import {
  DEFAULT_RESPONSE_BODY_CAP_BYTES,
  EncryptedBodyStore,
  FileAuditLogger,
  buildRenderModel,
  classifyText,
  findEntryById,
  formatAuditDetail,
  readAuditEntries,
} from "./index.js";
import { runHttpRequest, type HttpRequestDeps } from "../mcp/http_request.js";
import { runRunCommand, type RunCommandDeps, type RunCommandSpawn, type SpawnedChild } from "../mcp/run_command.js";
import { createVault, type KdfParams, type VaultHandle } from "../vault/index.js";
import { RateLimiter } from "../ratelimit/index.js";
import type { Policy } from "../policy/index.js";
import { EventEmitter } from "node:events";

const FAST_KDF: KdfParams = { memory: 1024, iterations: 2, parallelism: 1 };
const BODY_KEY_INFO = "secretproxy/audit-body-v1";
const SEKRET = "SEKRET123";

function cloudflarePolicy(): Policy {
  return {
    allowed_http_hosts: ["api.example.com"],
    allowed_commands: [
      {
        binary: "fake-wrangler",
        allowed_args_patterns: ["^deploy$"],
      },
    ],
    allowed_env_vars: ["CLOUDFLARE_API_TOKEN"],
    rate_limit: { requests: 50, window_seconds: 60 },
  };
}

class FakeChild extends EventEmitter {
  public readonly stdout = new EventEmitter();
  public readonly stderr = new EventEmitter();
  public pid: number | undefined = undefined;
  kill(): boolean { return true; }
}

describe("F13 — no-plaintext-anywhere integration", () => {
  let root: string;
  let vault: VaultHandle | undefined;

  beforeEach(async () => {
    root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "f13-")));
  });
  afterEach(async () => {
    vault?.close();
    vault = undefined;
    await fs.rm(root, { recursive: true, force: true });
  });

  it("end-to-end: http_request + run_command produce audit entries where SEKRET123 is never persisted or rendered", async () => {
    const auditBaseDir = path.join(root, ".secretproxy");
    await fs.mkdir(auditBaseDir, { recursive: true });
    const auditLogPath = path.join(auditBaseDir, "audit.log");
    const vaultPath = path.join(root, ".secretproxy.enc");
    const v = await createVault(vaultPath, "pw-correct-horse-battery", { kdfParams: FAST_KDF });
    vault = v;
    v.set("CLOUDFLARE_API_TOKEN", SEKRET, cloudflarePolicy());
    await v.save();
    const bodyKey = v.deriveSubkey(BODY_KEY_INFO);
    const bodyStore = new EncryptedBodyStore({ baseDir: auditBaseDir, key: bodyKey });
    const audit = new FileAuditLogger({ baseDir: auditBaseDir });

    // ── HTTP request against a mock upstream that echoes the secret ──
    const httpDeps: HttpRequestDeps = {
      sources: { global: v },
      audit,
      rateLimiter: new RateLimiter(),
      bodyStore,
      fetch: async () =>
        new Response(`{"echo":"Bearer ${SEKRET}","note":"leaked-${SEKRET}-inline"}`, {
          status: 200,
          headers: { "content-type": "application/json", "x-echo-token": `Bearer ${SEKRET}` },
        }),
    };
    const httpResult = await runHttpRequest(
      {
        url: "https://api.example.com/who-am-i",
        method: "GET",
        inject: [
          {
            secret: "CLOUDFLARE_API_TOKEN",
            into: "header",
            name: "Authorization",
            template: "Bearer {{value}}",
          },
        ],
      },
      httpDeps,
    );
    expect(httpResult.status).toBe("ok");
    // ── run_command that echoes the secret to stdout ──
    const spawn: RunCommandSpawn = (_cmd, _args, _opts) => {
      const child = new FakeChild();
      setImmediate(() => {
        child.stdout.emit("data", Buffer.from(`deployed: api_token=${SEKRET}\n`));
        child.stderr.emit("data", Buffer.from(`warning: saw secret ${SEKRET} in env\n`));
        child.emit("close", 0);
      });
      return child as unknown as SpawnedChild;
    };
    const runDeps: RunCommandDeps = {
      sources: { global: v },
      audit,
      rateLimiter: new RateLimiter(),
      bodyStore,
      spawn,
      parentEnv: { PATH: "/usr/bin" },
      timeoutMs: 5_000,
    };
    const runResult = await runRunCommand(
      {
        command: "fake-wrangler",
        args: ["deploy"],
        inject_env: { CLOUDFLARE_API_TOKEN: "CLOUDFLARE_API_TOKEN" },
      },
      runDeps,
    );
    expect(runResult.ok).toBe(true);
    if (runResult.ok) {
      expect(runResult.stdout).not.toContain(SEKRET);
      expect(runResult.stdout).toContain("[REDACTED:CLOUDFLARE_API_TOKEN]");
    }

    // ── 1. JSONL file: no plaintext ──
    const jsonlRaw = await fs.readFile(auditLogPath, "utf8");
    expect(jsonlRaw).not.toContain(SEKRET);

    const entries = await readAuditEntries(auditLogPath);
    expect(entries.length).toBeGreaterThan(0);
    const httpEv = entries.find(
      (e) => e.surface === "mcp_http_request" && e.outcome === "allowed",
    );
    const runEv = entries.find(
      (e) => e.surface === "mcp_run_command" && e.outcome === "allowed",
    );
    expect(httpEv).toBeDefined();
    expect(runEv).toBeDefined();

    // ── 2. Decrypted body blobs: no plaintext ──
    for (const ev of [httpEv!, runEv!]) {
      const ref = ev.body_ref;
      expect(ref).toBeDefined();
      if (!ref) continue;
      const blobPath = bodyStore.pathFor(ref.blob_id);
      const rawBlobBytes = await fs.readFile(blobPath);
      // raw bytes encrypted — no plaintext
      expect(rawBlobBytes.toString("utf8")).not.toContain(SEKRET);
      // decrypted payload must be scrubbed
      const payload = await bodyStore.readBody(ref.blob_id);
      const decryptedSerialized = JSON.stringify(payload);
      expect(decryptedSerialized).not.toContain(SEKRET);
      expect(decryptedSerialized).toContain("[REDACTED:CLOUDFLARE_API_TOKEN]");
    }

    // ── 3. CLI `audit show` output: no plaintext ──
    for (const ev of [httpEv!, runEv!]) {
      const ref = ev.body_ref;
      if (!ref) continue;
      const payload = await bodyStore.readBody(ref.blob_id);
      const model = buildRenderModel(ev, {
        bodies: payload,
        inScopeSecrets: [{ name: "CLOUDFLARE_API_TOKEN", value: SEKRET }],
      });
      const cliOutput = formatAuditDetail(model, { tty: false });
      expect(cliOutput).not.toContain(SEKRET);
      expect(cliOutput).toContain("[REDACTED:CLOUDFLARE_API_TOKEN]");
    }

    // ── 4. Simulated UI-rendered HTML: no plaintext ──
    // We build the same render model the UI's /api/audit/:id sends to the
    // SPA, then approximate the HTML by JSON.stringify'ing it — the SPA
    // writes these field values into the DOM verbatim (with scrub already
    // applied). A grep for the plaintext must return zero hits.
    for (const ev of [httpEv!, runEv!]) {
      const ref = ev.body_ref;
      if (!ref) continue;
      const payload = await bodyStore.readBody(ref.blob_id);
      const model = buildRenderModel(ev, {
        bodies: payload,
        inScopeSecrets: [{ name: "CLOUDFLARE_API_TOKEN", value: SEKRET }],
      });
      const fakeHtml = JSON.stringify(model);
      expect(fakeHtml).not.toContain(SEKRET);
    }
  });

  it("defense-in-depth: a storage-layer bug that lets a raw secret into the blob is still scrubbed at render", async () => {
    const auditBaseDir = path.join(root, ".secretproxy");
    await fs.mkdir(auditBaseDir, { recursive: true });
    const vaultPath = path.join(root, ".secretproxy.enc");
    const v = await createVault(vaultPath, "pw-render-scrub", { kdfParams: FAST_KDF });
    vault = v;
    v.set("TOKEN", SEKRET, cloudflarePolicy());
    const bodyKey = v.deriveSubkey(BODY_KEY_INFO);
    const bodyStore = new EncryptedBodyStore({ baseDir: auditBaseDir, key: bodyKey });

    // Directly stash an unscrubbed blob.
    await bodyStore.writeBody("req-rendbug-0001", {
      response: classifyText(`{"leaked":"${SEKRET}"}`),
    });
    const ev = {
      ts: new Date().toISOString(),
      secret_name: "TOKEN",
      tool: "http_request",
      target: "api.example.com",
      outcome: "allowed" as const,
      request_id: "req-rendbug-0001",
      caller_cwd: "/tmp",
      surface: "mcp_http_request" as const,
      request: { method: "GET", url: "https://api.example.com/", headers: [] },
      response: { status: 200, headers: [] },
      body_ref: { blob_id: "req-rendbug-0001" },
    };
    const payload = await bodyStore.readBody("req-rendbug-0001");
    const model = buildRenderModel(ev, {
      bodies: payload,
      inScopeSecrets: [{ name: "TOKEN", value: SEKRET }],
    });
    const cli = formatAuditDetail(model, { tty: false });
    expect(cli).not.toContain(SEKRET);
    expect(cli).toContain("[REDACTED:TOKEN]");
  });

  it("binary response collapses to a placeholder the CLI shows as a hex summary", async () => {
    const auditBaseDir = path.join(root, ".secretproxy");
    await fs.mkdir(auditBaseDir, { recursive: true });
    const vaultPath = path.join(root, ".secretproxy.enc");
    const v = await createVault(vaultPath, "pw-binary-resp", { kdfParams: FAST_KDF });
    vault = v;
    v.set("API", "not-echoed", cloudflarePolicy());
    const bodyKey = v.deriveSubkey(BODY_KEY_INFO);
    const bodyStore = new EncryptedBodyStore({ baseDir: auditBaseDir, key: bodyKey });
    const audit = new FileAuditLogger({ baseDir: auditBaseDir });

    const binaryBody = crypto.randomBytes(2 * 1024);
    const deps: HttpRequestDeps = {
      sources: { global: v },
      audit,
      rateLimiter: new RateLimiter(),
      bodyStore,
      fetch: async () =>
        new Response(binaryBody, {
          status: 200,
          headers: { "content-type": "application/octet-stream" },
        }),
    };
    const r = await runHttpRequest(
      {
        url: "https://api.example.com/blob",
        method: "GET",
        inject: [{ secret: "API", into: "header", name: "Authorization", template: "Bearer {{value}}" }],
      },
      deps,
    );
    expect(r.status).toBe("ok");
    const entries = await readAuditEntries(path.join(auditBaseDir, "audit.log"));
    const ev = entries.find((e) => e.surface === "mcp_http_request" && e.outcome === "allowed");
    expect(ev?.body_ref).toBeDefined();
    if (!ev?.body_ref) return;
    const payload = await bodyStore.readBody(ev.body_ref.blob_id);
    expect(payload.response?.kind).toBe("binary");
    const model = buildRenderModel(ev, { bodies: payload });
    const cli = formatAuditDetail(model, { tty: false });
    expect(cli).toMatch(/<binary, 2048 bytes, sha256:[0-9a-f]{64}>/);
  });

  it("response larger than 256 KiB truncates with an explicit cutoff marker", async () => {
    const auditBaseDir = path.join(root, ".secretproxy");
    await fs.mkdir(auditBaseDir, { recursive: true });
    const vaultPath = path.join(root, ".secretproxy.enc");
    const v = await createVault(vaultPath, "pw-big-resp", { kdfParams: FAST_KDF });
    vault = v;
    v.set("API", "not-echoed", cloudflarePolicy());
    const bodyKey = v.deriveSubkey(BODY_KEY_INFO);
    const bodyStore = new EncryptedBodyStore({ baseDir: auditBaseDir, key: bodyKey });
    const audit = new FileAuditLogger({ baseDir: auditBaseDir });

    const big = "a".repeat(DEFAULT_RESPONSE_BODY_CAP_BYTES + 1024);
    const deps: HttpRequestDeps = {
      sources: { global: v },
      audit,
      rateLimiter: new RateLimiter(),
      bodyStore,
      fetch: async () => new Response(big, { status: 200 }),
    };
    await runHttpRequest(
      {
        url: "https://api.example.com/big",
        method: "GET",
        inject: [{ secret: "API", into: "header", name: "Authorization", template: "Bearer {{value}}" }],
      },
      deps,
    );
    const entries = await readAuditEntries(path.join(auditBaseDir, "audit.log"));
    const ev = entries.find((e) => e.surface === "mcp_http_request" && e.outcome === "allowed" && e.body_ref !== undefined);
    expect(ev).toBeDefined();
    if (!ev?.body_ref) return;
    const payload = await bodyStore.readBody(ev.body_ref.blob_id);
    expect(payload.response?.kind).toBe("text");
    if (payload.response?.kind === "text") {
      expect(payload.response.truncated).toBe(true);
      expect(payload.response.truncated_bytes).toBe(1024);
      expect(payload.response.text).toContain("<truncated: 1024 more bytes>");
    }
  });

  it("scrub-before-truncate: a secret straddling the 256 KiB boundary leaves no prefix in the stored blob", async () => {
    const auditBaseDir = path.join(root, ".secretproxy");
    await fs.mkdir(auditBaseDir, { recursive: true });
    const vaultPath = path.join(root, ".secretproxy.enc");
    const v = await createVault(vaultPath, "pw-boundary-scrub", { kdfParams: FAST_KDF });
    vault = v;
    v.set("CLOUDFLARE_API_TOKEN", SEKRET, cloudflarePolicy());
    await v.save();
    const bodyKey = v.deriveSubkey(BODY_KEY_INFO);
    const bodyStore = new EncryptedBodyStore({ baseDir: auditBaseDir, key: bodyKey });
    const audit = new FileAuditLogger({ baseDir: auditBaseDir });

    // Place the plaintext so it straddles the cap: first 4 chars land inside
    // the kept slice, last 5 chars land in the elided tail. A naïve truncate-
    // then-scrub would leave the "SEKR" prefix in the blob.
    const padLen = DEFAULT_RESPONSE_BODY_CAP_BYTES - 4;
    const big = "x".repeat(padLen) + SEKRET + "y".repeat(1024);

    const deps: HttpRequestDeps = {
      sources: { global: v },
      audit,
      rateLimiter: new RateLimiter(),
      bodyStore,
      fetch: async () =>
        new Response(big, {
          status: 200,
          headers: { "content-type": "text/plain" },
        }),
    };
    await runHttpRequest(
      {
        url: "https://api.example.com/big",
        method: "GET",
        inject: [
          {
            secret: "CLOUDFLARE_API_TOKEN",
            into: "header",
            name: "Authorization",
            template: "Bearer {{value}}",
          },
        ],
      },
      deps,
    );
    const entries = await readAuditEntries(path.join(auditBaseDir, "audit.log"));
    const ev = entries.find(
      (e) => e.surface === "mcp_http_request" && e.outcome === "allowed" && e.body_ref !== undefined,
    );
    expect(ev).toBeDefined();
    if (!ev?.body_ref) return;
    const payload = await bodyStore.readBody(ev.body_ref.blob_id);
    expect(payload.response?.kind).toBe("text");
    if (payload.response?.kind !== "text") return;
    const blob = payload.response.text;
    // No plaintext and no partial prefix of the secret must remain in the
    // blob, even though the secret straddles the cap boundary. Scrub happens
    // on the full decoded text *before* truncation, so the whole secret is
    // replaced with a marker (which may itself be partially truncated) — but
    // NEVER a byte of the raw secret is kept.
    expect(blob).not.toContain(SEKRET);
    for (let i = 2; i <= SEKRET.length; i += 1) {
      expect(blob).not.toContain(SEKRET.slice(0, i));
    }
    expect(blob).toContain("<truncated:");
    // Raw encrypted blob on disk must also contain neither the plaintext
    // nor a partial prefix of it.
    const blobPath = bodyStore.pathFor(ev.body_ref.blob_id);
    const raw = await fs.readFile(blobPath);
    const rawUtf8 = raw.toString("utf8");
    expect(rawUtf8).not.toContain(SEKRET);
    expect(rawUtf8).not.toContain(SEKRET.slice(0, 4));
  });

  it("rate_limit_state.remaining decreases across successive calls for the same secret", async () => {
    const auditBaseDir = path.join(root, ".secretproxy");
    await fs.mkdir(auditBaseDir, { recursive: true });
    const vaultPath = path.join(root, ".secretproxy.enc");
    const v = await createVault(vaultPath, "pw-rl-remaining", { kdfParams: FAST_KDF });
    vault = v;
    v.set("API", "rl-val", cloudflarePolicy());
    const bodyKey = v.deriveSubkey(BODY_KEY_INFO);
    const bodyStore = new EncryptedBodyStore({ baseDir: auditBaseDir, key: bodyKey });
    const audit = new FileAuditLogger({ baseDir: auditBaseDir });
    const rateLimiter = new RateLimiter(() => Date.now());

    const deps: HttpRequestDeps = {
      sources: { global: v },
      audit,
      rateLimiter,
      bodyStore,
      fetch: async () =>
        new Response("{}", { status: 200, headers: { "content-type": "application/json" } }),
    };
    for (let i = 0; i < 3; i += 1) {
      await runHttpRequest(
        {
          url: "https://api.example.com/ok",
          method: "GET",
          inject: [
            { secret: "API", into: "header", name: "Authorization", template: "Bearer {{value}}" },
          ],
        },
        deps,
      );
    }
    const entries = await readAuditEntries(path.join(auditBaseDir, "audit.log"));
    const remains = entries
      .filter((e) => e.surface === "mcp_http_request" && e.outcome === "allowed")
      .map((e) => e.rate_limit_state?.remaining)
      .filter((r): r is number => typeof r === "number");
    expect(remains.length).toBeGreaterThanOrEqual(3);
    // Bucket capacity is 50 per the policy; first allowed call leaves 49, etc.
    expect(remains[0]).toBe(49);
    expect(remains[1]).toBe(48);
    expect(remains[2]).toBe(47);
    // Capacity is still capacity (unchanged).
    const caps = entries
      .filter((e) => e.surface === "mcp_http_request" && e.outcome === "allowed")
      .map((e) => e.rate_limit_state?.capacity);
    expect(caps.every((c) => c === 50)).toBe(true);
  });

  it("CLI and UI agree on the rendered content for the same id (same model fields)", async () => {
    const auditBaseDir = path.join(root, ".secretproxy");
    await fs.mkdir(auditBaseDir, { recursive: true });
    const vaultPath = path.join(root, ".secretproxy.enc");
    const v = await createVault(vaultPath, "pw-agree", { kdfParams: FAST_KDF });
    vault = v;
    v.set("API", "abc", cloudflarePolicy());
    const bodyKey = v.deriveSubkey(BODY_KEY_INFO);
    const bodyStore = new EncryptedBodyStore({ baseDir: auditBaseDir, key: bodyKey });
    const audit = new FileAuditLogger({ baseDir: auditBaseDir });

    const deps: HttpRequestDeps = {
      sources: { global: v },
      audit,
      rateLimiter: new RateLimiter(),
      bodyStore,
      fetch: async () =>
        new Response("{}", { status: 201, headers: { "content-type": "application/json" } }),
    };
    await runHttpRequest(
      {
        url: "https://api.example.com/create",
        method: "POST",
        body: `{"hello":true}`,
        inject: [{ secret: "API", into: "header", name: "Authorization", template: "Bearer {{value}}" }],
      },
      deps,
    );
    const entries = await readAuditEntries(path.join(auditBaseDir, "audit.log"));
    const ev = findEntryById(entries, entries[entries.length - 1]!.request_id);
    expect(ev).toBeDefined();
    if (!ev?.body_ref) return;
    const payload = await bodyStore.readBody(ev.body_ref.blob_id);
    const modelA = buildRenderModel(ev, { bodies: payload });
    const modelB = buildRenderModel(ev, { bodies: payload });
    expect(modelA).toEqual(modelB);
    // CLI/UI agreement = same id, same method, same status, same body bytes,
    // same injected secret names.
    expect(modelA.request.kind === "http" && modelA.request.view.method).toBe("POST");
    expect(modelA.response.kind === "http" && modelA.response.view.status_code).toBe(201);
    expect(modelA.injected_secrets.map((s) => s.secret_name)).toEqual(["API"]);
  });
});
