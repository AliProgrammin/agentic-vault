import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createVault, type KdfParams, type VaultHandle } from "../vault/index.js";
import type { Policy } from "../policy/index.js";
import { RateLimiter } from "../ratelimit/index.js";
import { InMemoryAuditLogger } from "../audit/index.js";
import {
  runHttpRequest,
  httpRequestInputSchema,
  registerHttpRequest,
  type HttpRequestDeps,
  type HttpRequestInput,
} from "./http_request.js";

const FAST_KDF: KdfParams = { memory: 1024, iterations: 2, parallelism: 1 };

async function mkTmpDir(prefix: string): Promise<string> {
  return fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), prefix)));
}

function makePolicy(overrides: Partial<Policy> = {}): Policy {
  return {
    allowed_http_hosts: overrides.allowed_http_hosts ?? ["api.example.com"],
    allowed_commands: overrides.allowed_commands ?? [],
    allowed_env_vars: overrides.allowed_env_vars ?? [],
    rate_limit: overrides.rate_limit ?? { requests: 5, window_seconds: 60 },
  };
}

interface FakeFetchCall {
  url: string;
  init: RequestInit;
}

function makeRecordingFetch(
  responder: (url: string, init: RequestInit) => Response,
): { fetch: typeof fetch; calls: FakeFetchCall[] } {
  const calls: FakeFetchCall[] = [];
  const impl: typeof fetch = async (input, init) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;
    calls.push({ url, init: init ?? {} });
    return responder(url, init ?? {});
  };
  return { fetch: impl, calls };
}

function stalledFetch(): typeof fetch {
  return (_input, init) =>
    new Promise((_resolve, reject) => {
      const signal = init?.signal;
      if (signal?.aborted) {
        reject(new DOMException("aborted", "AbortError"));
        return;
      }
      signal?.addEventListener("abort", () => {
        reject(new DOMException("aborted", "AbortError"));
      });
    });
}

describe("http_request", () => {
  let root: string;
  const handles: VaultHandle[] = [];

  beforeEach(async () => {
    root = await mkTmpDir("http-request-");
  });

  afterEach(async () => {
    for (const h of handles) {
      if (!h.isClosed()) h.close();
    }
    handles.length = 0;
    await fs.rm(root, { recursive: true, force: true });
  });

  async function mkVault(name: string): Promise<VaultHandle> {
    const v = await createVault(path.join(root, name), "pw-correct-horse", {
      kdfParams: FAST_KDF,
    });
    handles.push(v);
    return v;
  }

  async function mkDeps(
    vault: VaultHandle,
    fetchImpl: typeof fetch,
    overrides: Partial<HttpRequestDeps> = {},
  ): Promise<HttpRequestDeps> {
    const audit = overrides.audit ?? new InMemoryAuditLogger();
    const rateLimiter = overrides.rateLimiter ?? new RateLimiter();
    const deps: HttpRequestDeps = {
      sources: { global: vault },
      audit,
      rateLimiter,
      fetch: fetchImpl,
      ...(overrides.requestTimeoutMs !== undefined
        ? { requestTimeoutMs: overrides.requestTimeoutMs }
        : {}),
    };
    return deps;
  }

  it("allowed host with valid policy issues request and audits allowed", async () => {
    const vault = await mkVault("v.enc");
    vault.set("API", "abcd", makePolicy());
    const audit = new InMemoryAuditLogger();
    const { fetch: fetchImpl, calls } = makeRecordingFetch(
      () => new Response("ok-body", { status: 200 }),
    );
    const deps = await mkDeps(vault, fetchImpl, { audit });

    const result = await runHttpRequest(
      {
        url: "https://api.example.com/path",
        method: "GET",
        inject: [
          {
            secret: "API",
            into: "header",
            name: "Authorization",
            template: "Bearer {{value}}",
          },
        ],
      },
      deps,
    );

    expect(result.status).toBe("ok");
    expect(calls).toHaveLength(1);
    const call = calls[0];
    if (!call) throw new Error("no fetch call");
    const headers = call.init.headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer abcd");
    expect(audit.events).toHaveLength(1);
    const ev = audit.events[0];
    if (!ev) throw new Error("no audit event");
    expect(ev.outcome).toBe("allowed");
    expect(ev.secret_name).toBe("API");
    expect(ev.target).toBe("api.example.com");
    expect(ev.tool).toBe("http_request");
    expect(ev.detail?.method).toBe("GET");
    expect(ev.detail?.url).toContain("api.example.com");
    expect(ev.detail?.response_status).toBe(200);
    expect(ev.detail?.response_body).toBe("ok-body");
  });

  it("denied HTTP host blocks request", async () => {
    const vault = await mkVault("v.enc");
    vault.set(
      "API",
      "abcd",
      makePolicy({ allowed_http_hosts: ["api.example.com"] }),
    );
    const audit = new InMemoryAuditLogger();
    const { fetch: fetchImpl, calls } = makeRecordingFetch(
      () => new Response("should-not-be-called"),
    );
    const deps = await mkDeps(vault, fetchImpl, { audit });

    const result = await runHttpRequest(
      {
        url: "https://api.attacker.com/steal",
        method: "GET",
        inject: [
          {
            secret: "API",
            into: "header",
            name: "Authorization",
            template: "Bearer {{value}}",
          },
        ],
      },
      deps,
    );

    expect(result.status).toBe("error");
    if (result.status !== "error") throw new Error("expected error");
    expect(result.code).toBe("POLICY_DENIED");
    expect(calls).toHaveLength(0);
    expect(audit.events).toHaveLength(1);
    const ev = audit.events[0];
    if (!ev) throw new Error("no audit event");
    expect(ev.outcome).toBe("denied");
    expect(ev.code).toBe("POLICY_DENIED");
    expect(ev.target).toBe("api.attacker.com");
  });

  it("rate-limit exceeded denies with RATE_LIMITED code", async () => {
    const vault = await mkVault("v.enc");
    vault.set(
      "API",
      "abcd",
      makePolicy({ rate_limit: { requests: 1, window_seconds: 60 } }),
    );
    const audit = new InMemoryAuditLogger();
    const { fetch: fetchImpl, calls } = makeRecordingFetch(
      () => new Response("ok", { status: 200 }),
    );
    const deps = await mkDeps(vault, fetchImpl, { audit });

    const input: HttpRequestInput = {
      url: "https://api.example.com/",
      method: "GET",
      inject: [
        {
          secret: "API",
          into: "header",
          name: "Authorization",
          template: "Bearer {{value}}",
        },
      ],
    };

    const first = await runHttpRequest(input, deps);
    expect(first.status).toBe("ok");

    const second = await runHttpRequest(input, deps);
    expect(second.status).toBe("error");
    if (second.status !== "error") throw new Error("expected error");
    expect(second.code).toBe("RATE_LIMITED");
    expect(typeof second.retry_after_seconds).toBe("number");

    expect(calls).toHaveLength(1);
    const denied = audit.events.filter((e) => e.outcome === "denied");
    expect(denied).toHaveLength(1);
    const deniedEv = denied[0];
    if (!deniedEv) throw new Error("no denied audit event");
    expect(deniedEv.code).toBe("RATE_LIMITED");
  });

  it("timeout aborts request and returns TIMEOUT code", async () => {
    const vault = await mkVault("v.enc");
    vault.set("API", "abcd", makePolicy());
    const audit = new InMemoryAuditLogger();
    const deps = await mkDeps(vault, stalledFetch(), {
      audit,
      requestTimeoutMs: 25,
    });

    const result = await runHttpRequest(
      {
        url: "https://api.example.com/slow",
        method: "GET",
        inject: [
          {
            secret: "API",
            into: "header",
            name: "Authorization",
            template: "Bearer {{value}}",
          },
        ],
      },
      deps,
    );

    expect(result.status).toBe("error");
    if (result.status !== "error") throw new Error("expected error");
    expect(result.code).toBe("TIMEOUT");
    const denied = audit.events.filter((e) => e.outcome === "denied");
    expect(denied).toHaveLength(1);
    const deniedEv = denied[0];
    if (!deniedEv) throw new Error("no denied audit event");
    expect(deniedEv.code).toBe("TIMEOUT");
  });

  it("caps response body at 10 MB, marks truncated, emits SIZE_LIMIT annotation, still scrubs", async () => {
    const vault = await mkVault("v.enc");
    const secretValue = "SEKRET123";
    vault.set("API", secretValue, makePolicy());
    const audit = new InMemoryAuditLogger();

    const cap = 10 * 1024 * 1024;
    const overhead = 1024 * 1024;
    const total = cap + overhead;
    const fillByte = 0x41;
    const filler = new Uint8Array(1024).fill(fillByte);
    const secretBytes = new TextEncoder().encode(secretValue);
    const secretAfterPos = cap - 5000;

    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        let written = 0;
        let secretEmitted = false;
        while (written < total) {
          if (!secretEmitted && written >= secretAfterPos) {
            controller.enqueue(secretBytes);
            written += secretBytes.length;
            secretEmitted = true;
            continue;
          }
          controller.enqueue(filler);
          written += filler.length;
        }
        controller.close();
      },
    });

    const { fetch: fetchImpl } = makeRecordingFetch(
      () => new Response(body, { status: 200 }),
    );
    const deps = await mkDeps(vault, fetchImpl, { audit });

    const result = await runHttpRequest(
      {
        url: "https://api.example.com/big",
        method: "GET",
        inject: [
          {
            secret: "API",
            into: "header",
            name: "Authorization",
            template: "Bearer {{value}}",
          },
        ],
      },
      deps,
    );

    expect(result.status).toBe("ok");
    if (result.status !== "ok") throw new Error("expected ok");
    expect(result.truncated).toBe(true);
    // Raw body was capped at `cap` bytes; after scrubbing the body may grow
    // by at most a bounded number of replacement-length-delta bytes (13 here:
    // "[REDACTED:API]" is 14 chars vs 9-char "SEKRET123"). Bound the result
    // generously to a small multiple of the cap to confirm no runaway growth.
    expect(Buffer.byteLength(result.body, "utf8")).toBeLessThan(cap + 1024);
    expect(result.body).not.toContain(secretValue);
    expect(result.body).toContain("[REDACTED:API]");

    const sizeLimitRec = audit.events.find((e) => e.code === "SIZE_LIMIT");
    expect(sizeLimitRec).toBeDefined();
    expect(sizeLimitRec?.outcome).toBe("allowed");
  });

  it("scrubs secret value echoed back in response body", async () => {
    const vault = await mkVault("v.enc");
    vault.set("API", "SEKRET123", makePolicy());
    const { fetch: fetchImpl } = makeRecordingFetch(
      () => new Response("echoed SEKRET123 from server", { status: 200 }),
    );
    const deps = await mkDeps(vault, fetchImpl);

    const result = await runHttpRequest(
      {
        url: "https://api.example.com/echo",
        method: "GET",
        inject: [
          {
            secret: "API",
            into: "header",
            name: "Authorization",
            template: "Bearer {{value}}",
          },
        ],
      },
      deps,
    );

    expect(result.status).toBe("ok");
    if (result.status !== "ok") throw new Error("expected ok");
    expect(result.body).not.toContain("SEKRET123");
    expect(result.body).toContain("[REDACTED:API]");
  });

  it("rejects templates with placeholders other than {{value}} at schema validation", () => {
    const parsed = httpRequestInputSchema.safeParse({
      url: "https://api.example.com/",
      method: "GET",
      inject: [
        {
          secret: "API",
          into: "header",
          name: "Authorization",
          template: "Bearer {{foo}}",
        },
      ],
    });
    expect(parsed.success).toBe(false);
  });

  it("URL-encodes query-param injection values containing special characters", async () => {
    const vault = await mkVault("v.enc");
    vault.set("API", "foo&bar=baz", makePolicy());
    const { fetch: fetchImpl, calls } = makeRecordingFetch(
      () => new Response("ok", { status: 200 }),
    );
    const deps = await mkDeps(vault, fetchImpl);

    const result = await runHttpRequest(
      {
        url: "https://api.example.com/path",
        method: "GET",
        inject: [
          {
            secret: "API",
            into: "query",
            name: "token",
            template: "{{value}}",
          },
        ],
      },
      deps,
    );

    expect(result.status).toBe("ok");
    expect(calls).toHaveLength(1);
    const call = calls[0];
    if (!call) throw new Error("no fetch call");
    const u = new URL(call.url);
    expect(u.searchParams.get("token")).toBe("foo&bar=baz");
    expect(call.url).toContain("token=foo%26bar%3Dbaz");
  });

  it("rejects non-http(s) URLs with INVALID_INJECTION", async () => {
    const vault = await mkVault("v.enc");
    vault.set("API", "abcd", makePolicy());
    const { fetch: fetchImpl, calls } = makeRecordingFetch(
      () => new Response("should-not-be-called"),
    );
    const deps = await mkDeps(vault, fetchImpl);

    const result = await runHttpRequest(
      {
        url: "ftp://api.example.com/file",
        method: "GET",
        inject: [
          {
            secret: "API",
            into: "header",
            name: "Authorization",
            template: "Bearer {{value}}",
          },
        ],
      },
      deps,
    );

    expect(result.status).toBe("error");
    if (result.status !== "error") throw new Error("expected error");
    expect(result.code).toBe("INVALID_INJECTION");
    expect(calls).toHaveLength(0);
  });

  it("returns SECRET_NOT_FOUND when a referenced secret is missing", async () => {
    const vault = await mkVault("v.enc");
    vault.set("OTHER", "v", makePolicy());
    const audit = new InMemoryAuditLogger();
    const { fetch: fetchImpl, calls } = makeRecordingFetch(
      () => new Response("should-not-be-called"),
    );
    const deps = await mkDeps(vault, fetchImpl, { audit });

    const result = await runHttpRequest(
      {
        url: "https://api.example.com/",
        method: "GET",
        inject: [
          {
            secret: "MISSING",
            into: "header",
            name: "Authorization",
            template: "Bearer {{value}}",
          },
        ],
      },
      deps,
    );

    expect(result.status).toBe("error");
    if (result.status !== "error") throw new Error("expected error");
    expect(result.code).toBe("SECRET_NOT_FOUND");
    expect(calls).toHaveLength(0);
    expect(audit.events).toHaveLength(1);
    const ev = audit.events[0];
    if (!ev) throw new Error("no audit event");
    expect(ev.code).toBe("SECRET_NOT_FOUND");
    expect(ev.outcome).toBe("denied");
  });

  it("scrubs secret values that appear in response header values", async () => {
    const vault = await mkVault("v.enc");
    vault.set("API", "SEKRET123", makePolicy());
    const { fetch: fetchImpl } = makeRecordingFetch(
      () =>
        new Response("body", {
          status: 200,
          headers: { "x-echo": "saw SEKRET123 here" },
        }),
    );
    const deps = await mkDeps(vault, fetchImpl);

    const result = await runHttpRequest(
      {
        url: "https://api.example.com/",
        method: "GET",
        inject: [
          {
            secret: "API",
            into: "header",
            name: "Authorization",
            template: "Bearer {{value}}",
          },
        ],
      },
      deps,
    );

    expect(result.status).toBe("ok");
    if (result.status !== "ok") throw new Error("expected ok");
    for (const v of Object.values(result.headers)) {
      expect(v).not.toContain("SEKRET123");
    }
    expect(JSON.stringify(result.headers)).toContain("[REDACTED:API]");
  });

  it("never leaks the secret value into audit records even on denial paths", async () => {
    const vault = await mkVault("v.enc");
    vault.set("API", "SEKRET123", makePolicy());
    const audit = new InMemoryAuditLogger();
    const { fetch: fetchImpl } = makeRecordingFetch(
      () => new Response("x", { status: 200 }),
    );
    const deps = await mkDeps(vault, fetchImpl, { audit });

    await runHttpRequest(
      {
        url: "https://not-allowed.example/",
        method: "GET",
        inject: [
          {
            secret: "API",
            into: "header",
            name: "Authorization",
            template: "Bearer {{value}}",
          },
        ],
      },
      deps,
    );

    const serialized = JSON.stringify(audit.events);
    expect(serialized).not.toContain("SEKRET123");
  });

  it("registerHttpRequest is a function usable with createMcpServer extraTools", () => {
    expect(registerHttpRequest).toBeTypeOf("function");
  });
});
