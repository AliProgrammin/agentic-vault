import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { startUiServer, type UiServerHandle } from "./index.js";
import { createVault, type KdfParams } from "../vault/index.js";

const FAST_KDF: KdfParams = { memory: 1024, iterations: 2, parallelism: 1 };
const PW = "ui-test-pw-correct-horse";

interface TestEnv {
  homedir: string;
  cwd: string;
  handle: UiServerHandle;
  url: string;
}

async function bootstrap(createGlobal: boolean = true): Promise<TestEnv> {
  const homedir = await fs.realpath(
    await fs.mkdtemp(path.join(os.tmpdir(), "secretproxy-ui-")),
  );
  const cwd = await fs.realpath(
    await fs.mkdtemp(path.join(os.tmpdir(), "secretproxy-ui-cwd-")),
  );
  if (createGlobal) {
    const vaultPath = path.join(homedir, ".secretproxy.enc");
    const v = await createVault(vaultPath, PW, { kdfParams: FAST_KDF });
    v.set("EXISTING_SECRET", "prior-value");
    await v.save();
    v.close();
  }
  const handle = await startUiServer({ homedir, cwd, port: 0 });
  return { homedir, cwd, handle, url: handle.url };
}

async function teardown(env: TestEnv): Promise<void> {
  await env.handle.close();
  await fs.rm(env.homedir, { recursive: true, force: true });
  await fs.rm(env.cwd, { recursive: true, force: true });
}

async function postJson(
  url: string,
  body: unknown,
  cookie?: string,
): Promise<{ status: number; body: unknown; cookie?: string }> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (cookie !== undefined) headers["Cookie"] = cookie;
  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  const raw = await res.text();
  const out: { status: number; body: unknown; cookie?: string } = {
    status: res.status,
    body: raw.length > 0 ? JSON.parse(raw) : null,
  };
  const setCookie = res.headers.get("set-cookie");
  if (setCookie !== null) out.cookie = setCookie.split(";")[0]!;
  return out;
}

async function getJson(
  url: string,
  cookie?: string,
): Promise<{ status: number; body: unknown }> {
  const headers: Record<string, string> = {};
  if (cookie !== undefined) headers["Cookie"] = cookie;
  const res = await fetch(url, { headers });
  const raw = await res.text();
  return { status: res.status, body: raw.length > 0 ? JSON.parse(raw) : null };
}

describe("UI HTTP server", () => {
  let env: TestEnv;

  beforeEach(async () => {
    env = await bootstrap();
  });
  afterEach(async () => {
    await teardown(env);
  });

  it("serves the SPA at GET /", async () => {
    const res = await fetch(env.url + "/");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("<title>Agentic Vault</title>");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
  });

  it("refuses API calls without a session cookie", async () => {
    const r = await getJson(env.url + "/api/secrets");
    expect(r.status).toBe(401);
  });

  it("POST /api/login with wrong password returns 401", async () => {
    const r = await postJson(env.url + "/api/login", { password: "nope" });
    expect(r.status).toBe(401);
  });

  it("POST /api/login with correct password issues an HttpOnly SameSite=Strict cookie", async () => {
    const res = await fetch(env.url + "/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: PW }),
    });
    expect(res.status).toBe(200);
    const setCookie = res.headers.get("set-cookie") ?? "";
    expect(setCookie).toMatch(/HttpOnly/i);
    expect(setCookie).toMatch(/SameSite=Strict/i);
    expect(setCookie).toMatch(/secretproxy\.session=/);
  });

  it("authenticated session can list secrets, add, reveal, and remove", async () => {
    const login = await postJson(env.url + "/api/login", { password: PW });
    expect(login.status).toBe(200);
    const cookie = login.cookie!;

    const list1 = await getJson(env.url + "/api/secrets", cookie);
    expect(list1.status).toBe(200);
    const names1 = (list1.body as { secrets: { name: string }[] }).secrets.map(
      (s) => s.name,
    );
    expect(names1).toContain("EXISTING_SECRET");

    const add = await postJson(
      env.url + "/api/secrets",
      {
        name: "NEW_SECRET",
        value: "new-value",
        scope: "global",
        policy: {
          allowed_http_hosts: ["api.example.com"],
          allowed_commands: [],
          allowed_env_vars: ["NEW_SECRET"],
          rate_limit: { requests: 10, window_seconds: 60 },
        },
      },
      cookie,
    );
    expect(add.status).toBe(200);

    const reveal = await getJson(
      env.url + "/api/secrets/NEW_SECRET/reveal?scope=global",
      cookie,
    );
    expect(reveal.status).toBe(200);
    expect((reveal.body as { value: string }).value).toBe("new-value");

    const del = await fetch(env.url + "/api/secrets/NEW_SECRET?scope=global", {
      method: "DELETE",
      headers: { Cookie: cookie },
    });
    expect(del.status).toBe(200);

    const list2 = await getJson(env.url + "/api/secrets", cookie);
    const names2 = (list2.body as { secrets: { name: string }[] }).secrets.map(
      (s) => s.name,
    );
    expect(names2).not.toContain("NEW_SECRET");
  });

  it("policy PUT rejects invalid (wildcard) input", async () => {
    const login = await postJson(env.url + "/api/login", { password: PW });
    const cookie = login.cookie!;
    const bad = await fetch(env.url + "/api/secrets/EXISTING_SECRET/policy", {
      method: "PUT",
      headers: { "Content-Type": "application/json", Cookie: cookie },
      body: JSON.stringify({
        scope: "global",
        policy: {
          allowed_http_hosts: ["*"],
          allowed_commands: [],
          allowed_env_vars: ["EXISTING_SECRET"],
          rate_limit: { requests: 1, window_seconds: 1 },
        },
      }),
    });
    expect(bad.status).toBe(400);
  });

  it("GET /api/policy-templates returns templates sorted", async () => {
    const login = await postJson(env.url + "/api/login", { password: PW });
    const r = await getJson(env.url + "/api/policy-templates", login.cookie);
    expect(r.status).toBe(200);
    const templates = (r.body as { templates: { name: string }[] }).templates;
    expect(templates.length).toBeGreaterThanOrEqual(10);
    expect(templates.some((t) => t.name === "OPENAI_API_KEY")).toBe(true);
  });

  it("logout clears the session cookie and subsequent requests are 401", async () => {
    const login = await postJson(env.url + "/api/login", { password: PW });
    const cookie = login.cookie!;
    const out = await fetch(env.url + "/api/logout", {
      method: "POST",
      headers: { Cookie: cookie },
    });
    expect(out.status).toBe(200);
    expect(out.headers.get("set-cookie") ?? "").toMatch(/Max-Age=0/);
    const after = await getJson(env.url + "/api/secrets", cookie);
    expect(after.status).toBe(401);
  });

  it("only binds to 127.0.0.1 (not 0.0.0.0)", async () => {
    expect(env.url).toMatch(/^http:\/\/127\.0\.0\.1:/);
  });
});
