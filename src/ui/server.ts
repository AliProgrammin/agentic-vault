// Localhost UI HTTP server.
//
// Binds to 127.0.0.1 only (never 0.0.0.0). Single in-memory session, keyed
// by an HttpOnly SameSite=Strict cookie. Login endpoint verifies the master
// password by attempting to unlock the global vault — the unlocked handle
// is cached for the life of the session. All mutating endpoints require
// the cookie. Session TTL is rolling: each request extends it.
//
// The server does not serve static files from disk. The single-page app
// is inlined (src/ui/app.ts) and served as one GET /. This keeps the
// bundle to a single binary and removes filesystem-traversal concerns.

import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  EncryptedBodyStore,
  BodyStoreError,
  FileAuditLogger,
  buildRenderModel,
  findEntryById,
  readAuditEntries,
  type AuditEvent,
  type BodyBlobPayload,
  type BuildRenderOptions,
} from "../audit/index.js";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import { RateLimiter } from "../ratelimit/index.js";
import { listMerged, resolveSecret } from "../scope/index.js";
import { listPolicyTemplates, policySchema, type Policy } from "../policy/index.js";
import type { ScrubbableSecret } from "../scrub/index.js";
import {
  discoverProjectVault,
  ensureProjectVault as ensureProjectVaultFn,
  getGlobalVaultPath,
  type ProjectVaultLocation,
} from "../scope/index.js";
import {
  createVault,
  unlockVault,
  VaultExistsError,
  WrongPasswordError,
  type VaultHandle,
} from "../vault/index.js";
import { INDEX_HTML } from "./app.js";

const SESSION_TTL_MS = 15 * 60 * 1000;
const COOKIE_NAME = "secretproxy.session";
const DEFAULT_PORT = 7381;
const BODY_KEY_INFO = "secretproxy/audit-body-v1";

export interface UiServerOptions {
  homedir: string;
  cwd: string;
  port?: number;
  onIdle?: () => void;
  idleTimeoutMs?: number;
}

interface Session {
  id: string;
  global: VaultHandle | null;
  project: { handle: VaultHandle; location: ProjectVaultLocation } | null;
  password: string;
  expiresAt: number;
}

export interface UiServerHandle {
  readonly port: number;
  readonly url: string;
  close(): Promise<void>;
}

interface RequestContext {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  body: unknown;
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(json).toString(),
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(json);
}

function sendHtml(res: ServerResponse, status: number, body: string): void {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": Buffer.byteLength(body).toString(),
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
  });
  res.end(body);
}

function parseCookies(header: string | undefined): Map<string, string> {
  const out = new Map<string, string>();
  if (header === undefined) return out;
  for (const part of header.split(";")) {
    const [rawName, ...rest] = part.split("=");
    if (rawName === undefined) continue;
    const name = rawName.trim();
    if (name.length === 0) continue;
    out.set(name, rest.join("=").trim());
  }
  return out;
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  const MAX_BYTES = 1024 * 1024;
  for await (const chunk of req) {
    const buf = typeof chunk === "string" ? Buffer.from(chunk) : (chunk as Buffer);
    total += buf.length;
    if (total > MAX_BYTES) {
      throw new Error("request body too large");
    }
    chunks.push(buf);
  }
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (raw.length === 0) return null;
  return JSON.parse(raw);
}

function setSessionCookie(res: ServerResponse, sessionId: string): void {
  const attrs = [
    `${COOKIE_NAME}=${sessionId}`,
    "HttpOnly",
    "SameSite=Strict",
    "Path=/",
    `Max-Age=${String(Math.floor(SESSION_TTL_MS / 1000))}`,
  ];
  res.setHeader("Set-Cookie", attrs.join("; "));
}

function clearSessionCookie(res: ServerResponse): void {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`,
  );
}

async function readVaultSummary(
  handle: VaultHandle,
  scope: "global" | "project",
  vaultPath: string,
): Promise<Array<Record<string, unknown>>> {
  return handle.list().map((rec) => {
    const policy = rec.policy as Policy | undefined;
    return {
      name: rec.name,
      scope,
      vault_path: vaultPath,
      created_at: rec.created_at,
      updated_at: rec.updated_at,
      hosts_count: policy?.allowed_http_hosts.length ?? 0,
      commands_count: policy?.allowed_commands.length ?? 0,
      env_vars_count: policy?.allowed_env_vars.length ?? 0,
      has_policy: policy !== undefined,
    };
  });
}

export async function startUiServer(opts: UiServerOptions): Promise<UiServerHandle> {
  const sessions = new Map<string, Session>();
  const port = opts.port ?? DEFAULT_PORT;
  const globalVaultPath = getGlobalVaultPath(opts.homedir);
  const auditBaseDir = path.join(opts.homedir, ".secretproxy");
  const audit = new FileAuditLogger({ baseDir: auditBaseDir });
  const rateLimiter = new RateLimiter();
  void rateLimiter;
  let lastActivity = Date.now();

  function touchSession(session: Session): void {
    session.expiresAt = Date.now() + SESSION_TTL_MS;
    lastActivity = Date.now();
  }

  function getSession(req: IncomingMessage): Session | null {
    const cookies = parseCookies(req.headers["cookie"]);
    const id = cookies.get(COOKIE_NAME);
    if (id === undefined) return null;
    const session = sessions.get(id);
    if (session === undefined) return null;
    if (session.expiresAt < Date.now()) {
      closeSession(id);
      return null;
    }
    touchSession(session);
    return session;
  }

  function closeSession(id: string): void {
    const session = sessions.get(id);
    if (session === undefined) return;
    session.global?.close();
    session.project?.handle.close();
    sessions.delete(id);
  }

  async function fileExists(p: string): Promise<boolean> {
    try {
      const st = await fs.stat(p);
      return st.isFile();
    } catch {
      return false;
    }
  }

  async function handleLogin(ctx: RequestContext): Promise<void> {
    const body = ctx.body as { password?: unknown } | null;
    const password = body?.password;
    if (typeof password !== "string" || password.length === 0) {
      sendJson(ctx.res, 400, { error: "password required" });
      return;
    }
    let global: VaultHandle | null = null;
    try {
      if (await fileExists(globalVaultPath)) {
        global = await unlockVault(globalVaultPath, password);
      } else {
        global = await createVault(globalVaultPath, password);
      }
    } catch (err) {
      if (err instanceof WrongPasswordError) {
        sendJson(ctx.res, 401, { error: "wrong password" });
        return;
      }
      if (err instanceof VaultExistsError) {
        global = await unlockVault(globalVaultPath, password);
      } else {
        sendJson(ctx.res, 500, { error: (err as Error).message });
        return;
      }
    }
    let project: Session["project"] = null;
    const loc = await discoverProjectVault(opts.cwd, opts.homedir);
    if (loc !== null) {
      try {
        const ph = await unlockVault(loc.vaultPath, password);
        project = { handle: ph, location: loc };
      } catch {
        // project vault exists but password doesn't match — ignore,
        // fall back to global-only session
      }
    }
    const id = randomBytes(32).toString("base64url");
    const session: Session = {
      id,
      global,
      project,
      password,
      expiresAt: Date.now() + SESSION_TTL_MS,
    };
    sessions.set(id, session);
    setSessionCookie(ctx.res, id);
    sendJson(ctx.res, 200, { ok: true });
  }

  function handleLogout(ctx: RequestContext, session: Session): void {
    closeSession(session.id);
    clearSessionCookie(ctx.res);
    sendJson(ctx.res, 200, { ok: true });
  }

  async function handleListSecrets(ctx: RequestContext, session: Session): Promise<void> {
    const rows: Array<Record<string, unknown>> = [];
    if (session.global !== null) {
      rows.push(...(await readVaultSummary(session.global, "global", globalVaultPath)));
    }
    if (session.project !== null) {
      rows.push(
        ...(await readVaultSummary(session.project.handle, "project", session.project.location.vaultPath)),
      );
    }
    sendJson(ctx.res, 200, { secrets: rows });
  }

  async function handleReveal(
    ctx: RequestContext,
    session: Session,
    name: string,
  ): Promise<void> {
    const scope = ctx.url.searchParams.get("scope") ?? "global";
    const handle = resolveHandle(session, scope);
    if (handle === null) {
      sendJson(ctx.res, 404, { error: "scope not open in this session" });
      return;
    }
    const rec = handle.getRecord(name);
    if (rec === undefined) {
      sendJson(ctx.res, 404, { error: "not found" });
      return;
    }
    const value = handle.get(name);
    sendJson(ctx.res, 200, {
      name,
      value,
      scope,
      created_at: rec.created_at,
      updated_at: rec.updated_at,
    });
  }

  function resolveHandle(session: Session, scope: string): VaultHandle | null {
    if (scope === "global") return session.global;
    if (scope === "project") return session.project?.handle ?? null;
    return null;
  }

  async function handleAddSecret(ctx: RequestContext, session: Session): Promise<void> {
    const body = ctx.body as {
      name?: unknown;
      value?: unknown;
      scope?: unknown;
      policy?: unknown;
    } | null;
    const name = typeof body?.name === "string" ? body.name : null;
    const value = typeof body?.value === "string" ? body.value : null;
    const scope = body?.scope === "project" ? "project" : "global";
    if (name === null || value === null) {
      sendJson(ctx.res, 400, { error: "name and value required" });
      return;
    }
    let policyParsed: Policy | undefined;
    if (body?.policy !== undefined && body.policy !== null) {
      const parsed = policySchema.safeParse(body.policy);
      if (!parsed.success) {
        sendJson(ctx.res, 400, {
          error: "invalid policy",
          details: parsed.error.issues,
        });
        return;
      }
      policyParsed = parsed.data;
    }
    let handle: VaultHandle | null = null;
    let vaultPath = "";
    if (scope === "project") {
      if (session.project !== null) {
        handle = session.project.handle;
        vaultPath = session.project.location.vaultPath;
      } else {
        const result = await ensureProjectVaultFn(opts.cwd, session.password);
        session.project = {
          handle: result.handle,
          location: { vaultPath: result.vaultPath, projectRoot: opts.cwd },
        };
        handle = result.handle;
        vaultPath = result.vaultPath;
      }
    } else {
      if (session.global === null) {
        sendJson(ctx.res, 500, { error: "no global vault open" });
        return;
      }
      handle = session.global;
      vaultPath = globalVaultPath;
    }
    handle.set(name, value, policyParsed);
    await handle.save();
    sendJson(ctx.res, 200, { ok: true, scope, vault_path: vaultPath });
  }

  async function handleRemoveSecret(
    ctx: RequestContext,
    session: Session,
    name: string,
  ): Promise<void> {
    const scope = ctx.url.searchParams.get("scope") ?? "global";
    const handle = resolveHandle(session, scope);
    if (handle === null) {
      sendJson(ctx.res, 404, { error: "scope not open in this session" });
      return;
    }
    const removed = handle.remove(name);
    if (!removed) {
      sendJson(ctx.res, 404, { error: "not found" });
      return;
    }
    await handle.save();
    sendJson(ctx.res, 200, { ok: true });
  }

  async function handleGetPolicy(
    ctx: RequestContext,
    session: Session,
    name: string,
  ): Promise<void> {
    const scope = ctx.url.searchParams.get("scope") ?? "global";
    const handle = resolveHandle(session, scope);
    if (handle === null) {
      sendJson(ctx.res, 404, { error: "scope not open in this session" });
      return;
    }
    const rec = handle.getRecord(name);
    if (rec === undefined) {
      sendJson(ctx.res, 404, { error: "not found" });
      return;
    }
    sendJson(ctx.res, 200, { name, policy: rec.policy ?? null });
  }

  async function handleSetPolicy(
    ctx: RequestContext,
    session: Session,
    name: string,
  ): Promise<void> {
    const body = ctx.body as { policy?: unknown; scope?: unknown } | null;
    const scope = body?.scope === "project" ? "project" : "global";
    const handle = resolveHandle(session, scope);
    if (handle === null) {
      sendJson(ctx.res, 404, { error: "scope not open in this session" });
      return;
    }
    const existing = handle.getRecord(name);
    if (existing === undefined) {
      sendJson(ctx.res, 404, { error: "not found" });
      return;
    }
    if (body?.policy === null || body?.policy === undefined) {
      const value = handle.get(name);
      if (value === undefined) {
        sendJson(ctx.res, 500, { error: "internal: value missing" });
        return;
      }
      handle.set(name, value);
      await handle.save();
      sendJson(ctx.res, 200, { ok: true });
      return;
    }
    const parsed = policySchema.safeParse(body.policy);
    if (!parsed.success) {
      sendJson(ctx.res, 400, { error: "invalid policy", details: parsed.error.issues });
      return;
    }
    const value = handle.get(name);
    if (value === undefined) {
      sendJson(ctx.res, 500, { error: "internal: value missing" });
      return;
    }
    handle.set(name, value, parsed.data);
    await handle.save();
    sendJson(ctx.res, 200, { ok: true });
  }

  function handleTemplates(ctx: RequestContext): void {
    const entries = listPolicyTemplates();
    sendJson(ctx.res, 200, { templates: entries });
  }

  async function handleAuditDetail(
    ctx: RequestContext,
    session: Session,
    id: string,
  ): Promise<void> {
    const entries = await readAuditEntries(path.join(auditBaseDir, "audit.log"));
    const event = findEntryById(entries, id);
    if (event === undefined) {
      sendJson(ctx.res, 404, { error: `no audit entry with id '${id}'` });
      return;
    }
    const inScope = collectSessionInScopeSecrets(session);
    const buildOpts: BuildRenderOptions = {};
    if (inScope.length > 0) {
      (buildOpts as { inScopeSecrets: readonly ScrubbableSecret[] }).inScopeSecrets = inScope;
    }
    const keyHolder = session.global ?? session.project?.handle ?? null;
    const bodyRef = event.body_ref;
    if (keyHolder !== null && bodyRef !== undefined) {
      const key = keyHolder.deriveSubkey(BODY_KEY_INFO);
      const store = new EncryptedBodyStore({ baseDir: auditBaseDir, key });
      try {
        if (await store.hasBody(bodyRef.blob_id)) {
          const payload: BodyBlobPayload = await store.readBody(bodyRef.blob_id);
          (buildOpts as { bodies?: BodyBlobPayload }).bodies = payload;
        } else {
          (buildOpts as { pruned?: boolean }).pruned = true;
        }
      } catch (err) {
        if (err instanceof BodyStoreError) {
          (buildOpts as { bodiesError?: BodyStoreError }).bodiesError = err;
        } else {
          throw err;
        }
      }
    }
    const model = buildRenderModel(event, buildOpts);
    sendJson(ctx.res, 200, { model, event });
  }

  function collectSessionInScopeSecrets(session: Session): readonly ScrubbableSecret[] {
    const sources = {
      global: session.global,
      project: session.project?.handle ?? null,
    };
    const out: ScrubbableSecret[] = [];
    for (const entry of listMerged(sources)) {
      const r = resolveSecret(entry.name, sources);
      if (r !== undefined) {
        out.push({ name: r.name, value: r.value });
      }
    }
    return out;
  }

  async function handleAudit(ctx: RequestContext): Promise<void> {
    const logPath = path.join(auditBaseDir, "audit.log");
    let raw = "";
    try {
      raw = await fs.readFile(logPath, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        sendJson(ctx.res, 200, { events: [] });
        return;
      }
      throw err;
    }
    const lines = raw.split("\n").filter((l) => l.length > 0);
    const limit = Math.min(
      Number.parseInt(ctx.url.searchParams.get("limit") ?? "100", 10) || 100,
      500,
    );
    const tail = lines.slice(-limit);
    const filterSecret = ctx.url.searchParams.get("secret");
    const filterTool = ctx.url.searchParams.get("tool");
    const filterOutcome = ctx.url.searchParams.get("outcome");
    const events: AuditEvent[] = [];
    for (const line of tail) {
      try {
        const ev = JSON.parse(line) as AuditEvent;
        if (filterSecret !== null && ev.secret_name !== filterSecret) continue;
        if (filterTool !== null && ev.tool !== filterTool) continue;
        if (filterOutcome !== null && ev.outcome !== filterOutcome) continue;
        events.push(ev);
      } catch {
        // skip malformed line
      }
    }
    sendJson(ctx.res, 200, { events });
  }

  // Prevents an "unused" audit logger warning. The UI itself does not
  // write audit entries; it only reads them. The audit variable is kept
  // so we can add explicit "ui.reveal" entries later without touching
  // the startup signature.
  void audit;

  const server: Server = createServer((req, res) => {
    void (async (): Promise<void> => {
      try {
        const host = req.headers["host"] ?? "";
        if (!host.startsWith("127.0.0.1") && !host.startsWith("localhost")) {
          res.writeHead(403).end();
          return;
        }
        const url = new URL(req.url ?? "/", `http://${host}`);
        const pathname = url.pathname;

        if (req.method === "GET" && pathname === "/") {
          sendHtml(res, 200, INDEX_HTML);
          return;
        }

        if (req.method === "GET" && pathname === "/healthz") {
          sendJson(res, 200, { ok: true });
          return;
        }

        let body: unknown = null;
        if (req.method === "POST" || req.method === "PUT" || req.method === "PATCH") {
          try {
            body = await readJsonBody(req);
          } catch (err) {
            sendJson(res, 400, { error: (err as Error).message });
            return;
          }
        }

        const ctx: RequestContext = { req, res, url, body };

        if (req.method === "POST" && pathname === "/api/login") {
          await handleLogin(ctx);
          return;
        }

        const session = getSession(req);
        if (session === null) {
          sendJson(res, 401, { error: "not authenticated" });
          return;
        }

        if (req.method === "GET" && pathname === "/api/session") {
          sendJson(res, 200, {
            ok: true,
            has_project: session.project !== null,
            expires_at: session.expiresAt,
          });
          return;
        }

        if (req.method === "POST" && pathname === "/api/logout") {
          handleLogout(ctx, session);
          return;
        }

        if (req.method === "GET" && pathname === "/api/secrets") {
          await handleListSecrets(ctx, session);
          return;
        }

        if (req.method === "POST" && pathname === "/api/secrets") {
          await handleAddSecret(ctx, session);
          return;
        }

        const revealMatch = /^\/api\/secrets\/([^/]+)\/reveal$/.exec(pathname);
        if (req.method === "GET" && revealMatch !== null) {
          await handleReveal(ctx, session, decodeURIComponent(revealMatch[1]!));
          return;
        }

        const deleteMatch = /^\/api\/secrets\/([^/]+)$/.exec(pathname);
        if (req.method === "DELETE" && deleteMatch !== null) {
          await handleRemoveSecret(ctx, session, decodeURIComponent(deleteMatch[1]!));
          return;
        }

        const policyGetMatch = /^\/api\/secrets\/([^/]+)\/policy$/.exec(pathname);
        if (req.method === "GET" && policyGetMatch !== null) {
          await handleGetPolicy(ctx, session, decodeURIComponent(policyGetMatch[1]!));
          return;
        }

        const policyPutMatch = /^\/api\/secrets\/([^/]+)\/policy$/.exec(pathname);
        if (req.method === "PUT" && policyPutMatch !== null) {
          await handleSetPolicy(ctx, session, decodeURIComponent(policyPutMatch[1]!));
          return;
        }

        if (req.method === "GET" && pathname === "/api/policy-templates") {
          handleTemplates(ctx);
          return;
        }

        if (req.method === "GET" && pathname === "/api/audit") {
          await handleAudit(ctx);
          return;
        }

        const auditDetailMatch = /^\/api\/audit\/([^/]+)$/.exec(pathname);
        if (req.method === "GET" && auditDetailMatch !== null) {
          await handleAuditDetail(ctx, session, decodeURIComponent(auditDetailMatch[1]!));
          return;
        }

        sendJson(res, 404, { error: "not found" });
      } catch (err) {
        sendJson(res, 500, { error: (err as Error).message });
      }
    })();
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });

  let idleTimer: NodeJS.Timeout | null = null;
  if (opts.onIdle !== undefined) {
    const idleMs = opts.idleTimeoutMs ?? SESSION_TTL_MS;
    const checkIdle = (): void => {
      if (Date.now() - lastActivity > idleMs) {
        opts.onIdle?.();
      } else {
        idleTimer = setTimeout(checkIdle, Math.max(5000, idleMs / 4));
      }
    };
    idleTimer = setTimeout(checkIdle, idleMs);
  }

  const actualPort =
    typeof server.address() === "object" && server.address() !== null
      ? (server.address() as { port: number }).port
      : port;

  return {
    port: actualPort,
    url: `http://127.0.0.1:${String(actualPort)}`,
    close: async (): Promise<void> => {
      if (idleTimer !== null) clearTimeout(idleTimer);
      for (const id of [...sessions.keys()]) {
        closeSession(id);
      }
      await new Promise<void>((resolve) => {
        server.close(() => {
          resolve();
        });
      });
    },
  };
}
