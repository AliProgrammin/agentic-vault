import { promises as fs } from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { classifyText, EncryptedBodyStore } from "../../audit/index.js";
import { createPopulatedGlobalVault, makeTestDeps, makeTmpDir } from "../test-helpers.js";
import { cmdAuditShow } from "./audit-show.js";
import { CliError } from "../errors.js";

const BODY_KEY_INFO = "secretproxy/audit-body-v1";

describe("cmdAuditShow", () => {
  let tmp: string;
  beforeEach(async () => { tmp = await makeTmpDir(); });
  afterEach(async () => { await fs.rm(tmp, { recursive: true, force: true }); });

  it("errors when no entry matches the given id", async () => {
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, env: { SECRETPROXY_PASSWORD: "pw" } });
    const dir = path.dirname(harness.deps.auditLogPath);
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(harness.deps.auditLogPath, "");
    await expect(cmdAuditShow(harness.deps, { id: "req-nope" })).rejects.toBeInstanceOf(CliError);
  });

  it("--json emits the raw record", async () => {
    const password = "pw-show";
    await createPopulatedGlobalVault(path.join(tmp, ".secretproxy.enc"), password, []);
    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      password,
      keychainPopulated: true,
      env: { SECRETPROXY_PASSWORD: password },
    });
    const dir = path.dirname(harness.deps.auditLogPath);
    await fs.mkdir(dir, { recursive: true });
    const rec = {
      ts: "2026-04-18T10:00:00.000Z",
      secret_name: "X",
      tool: "http_request",
      target: "api.example.com",
      outcome: "allowed",
      request_id: "req-json-0001",
      caller_cwd: "/",
    };
    await fs.writeFile(harness.deps.auditLogPath, JSON.stringify(rec) + "\n");
    await cmdAuditShow(harness.deps, { id: "req-json-0001", json: true });
    const out = harness.stdout.text();
    expect(JSON.parse(out.trim())).toMatchObject(rec);
  });

  it("renders sectioned detail (no ANSI when not a TTY)", async () => {
    const password = "pw-show2";
    const vault = await createPopulatedGlobalVault(path.join(tmp, ".secretproxy.enc"), password, []);
    vault.close();
    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      password,
      keychainPopulated: true,
      env: { SECRETPROXY_PASSWORD: password },
    });
    const dir = path.dirname(harness.deps.auditLogPath);
    await fs.mkdir(dir, { recursive: true });
    const rec = {
      ts: "2026-04-18T10:00:00.000Z",
      secret_name: "X",
      tool: "http_request",
      target: "api.example.com",
      outcome: "allowed",
      request_id: "req-show-0002",
      caller_cwd: "/",
      surface: "mcp_http_request",
      request: { method: "GET", url: "https://api.example.com/hello", headers: [] },
      response: { status: 200, headers: [] },
    };
    await fs.writeFile(harness.deps.auditLogPath, JSON.stringify(rec) + "\n");
    await cmdAuditShow(harness.deps, { id: "req-show-0002" });
    const out = harness.stdout.text();
    expect(out).toContain("Summary");
    expect(out).toContain("req-show-0002");
    expect(out).not.toMatch(/\x1b\[/);
  });

  it("decrypts and renders the body blob when the vault unlocks", async () => {
    const password = "pw-show3";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const vault = await createPopulatedGlobalVault(vaultPath, password, []);
    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      password,
      keychainPopulated: true,
      env: { SECRETPROXY_PASSWORD: password },
    });
    const dir = path.dirname(harness.deps.auditLogPath);
    await fs.mkdir(dir, { recursive: true });
    const bodyKey = vault.deriveSubkey(BODY_KEY_INFO);
    vault.close();
    const store = new EncryptedBodyStore({ baseDir: dir, key: bodyKey });
    const id = "req-show-withbody";
    await store.writeBody(id, { response: classifyText("hello-body") });
    const rec = {
      ts: "2026-04-18T10:00:00.000Z",
      secret_name: "X",
      tool: "http_request",
      target: "api.example.com",
      outcome: "allowed",
      request_id: id,
      caller_cwd: "/",
      surface: "mcp_http_request",
      request: { method: "GET", url: "https://api.example.com/", headers: [] },
      response: { status: 200, headers: [] },
      body_ref: { blob_id: id },
    };
    await fs.writeFile(harness.deps.auditLogPath, JSON.stringify(rec) + "\n");
    await cmdAuditShow(harness.deps, { id });
    const out = harness.stdout.text();
    expect(out).toContain("hello-body");
  });
});
