// Shared rendering model for the F13 audit detail view.
//
// CLI `audit show` and the UI detail route both consume `RenderModel`.
// The model is a plain data structure — no ANSI codes, no HTML — so the
// two surfaces cannot disagree on what an entry says even if their
// formatting conventions differ.
//
// Scrubbing is applied at render time as a SECOND pass (defense-in-depth);
// the primary scrub pass runs at persist time in F10/F11. Render-pass
// scrubbing exists so a storage-layer bug that lets a raw secret slip into
// the encrypted body blob still cannot leak to the operator.
//
// Pre-F13 records (those lacking the new fields) render as a "not captured"
// block for the affected sections — migration is not required.

import { scrub, type ScrubbableSecret } from "../scrub/index.js";
import type {
  BodyArtifact,
  BinaryBodyArtifact,
  TextBodyArtifact,
} from "./body-artifact.js";
import { isBinaryArtifact, isTextArtifact } from "./body-artifact.js";
import type {
  BodyBlobPayload,
  BodyStoreError,
} from "./body-store.js";
import type {
  AuditCommandRequest,
  AuditCommandResponse,
  AuditEvent,
  AuditHeader,
  AuditHttpRequest,
  AuditHttpResponse,
} from "./types.js";

export type SectionStatus = "present" | "not_captured" | "pruned" | "decrypt_failed";

export interface RenderSectionBase {
  readonly status: SectionStatus;
}

export interface RenderBodySection extends RenderSectionBase {
  readonly artifact?: BodyArtifact;
  readonly error?: string;
}

export interface RenderHttpRequestView extends RenderSectionBase {
  readonly method?: string;
  readonly url?: string;
  readonly headers: readonly AuditHeader[];
  readonly body: RenderBodySection;
}

export interface RenderHttpResponseView extends RenderSectionBase {
  readonly status_code?: number;
  readonly headers: readonly AuditHeader[];
  readonly body: RenderBodySection;
}

export interface RenderCommandRequestView extends RenderSectionBase {
  readonly binary?: string;
  readonly args: readonly string[];
  readonly cwd?: string;
  readonly env_keys: readonly string[];
}

export interface RenderCommandResponseView extends RenderSectionBase {
  readonly exit_code?: number;
  readonly stdout: RenderBodySection;
  readonly stderr: RenderBodySection;
}

export interface RenderStage {
  readonly name: string;
  readonly ts?: string;
  readonly delta_ms?: number;
}

export interface RenderTimeline {
  readonly stages: readonly RenderStage[];
  readonly total_ms?: number;
}

export interface RenderProcess {
  readonly pid?: number;
  readonly cwd: string;
  readonly argv?: readonly string[];
  readonly tool_name?: string;
  readonly ts: string;
  readonly surface: string;
}

export interface RenderRateLimit {
  readonly remaining: number;
  readonly capacity: number;
  readonly window_seconds: number;
}

export interface RenderInjectedSecret {
  readonly secret_name: string;
  readonly scope: string;
  readonly target: string;
}

export type RenderRequestView =
  | { kind: "http"; view: RenderHttpRequestView }
  | { kind: "command"; view: RenderCommandRequestView }
  | { kind: "none"; status: SectionStatus };

export type RenderResponseView =
  | { kind: "http"; view: RenderHttpResponseView }
  | { kind: "command"; view: RenderCommandResponseView }
  | { kind: "none"; status: SectionStatus };

export interface RenderModel {
  readonly id: string;
  readonly ts: string;
  readonly surface: string;
  readonly outcome: "allowed" | "denied";
  readonly code?: string;
  readonly reason?: string;
  readonly secret_name: string;
  readonly target: string;
  readonly process: RenderProcess;
  readonly timeline: RenderTimeline;
  readonly rate_limit?: RenderRateLimit;
  readonly injected_secrets: readonly RenderInjectedSecret[];
  readonly request: RenderRequestView;
  readonly response: RenderResponseView;
}

export interface BuildRenderOptions {
  /** Blob payload from the encrypted body store, if available. */
  readonly bodies?: BodyBlobPayload;
  /** If reading the blob failed, the typed error so the UI can state why. */
  readonly bodiesError?: BodyStoreError;
  /**
   * If the blob was pruned (present in JSONL but no file on disk), the
   * caller passes `{ pruned: true }` so the renderer can show a dedicated
   * state rather than a generic "not captured."
   */
  readonly pruned?: boolean;
  /** Secrets currently in scope — used for the second-pass scrub. */
  readonly inScopeSecrets?: readonly ScrubbableSecret[];
}

// ──────────────────────────────────────────────────────────────────────────
// Helpers

function isHttpRequest(
  r: AuditHttpRequest | AuditCommandRequest | undefined,
): r is AuditHttpRequest {
  return r !== undefined && typeof (r as AuditHttpRequest).method === "string";
}

function isCommandRequest(
  r: AuditHttpRequest | AuditCommandRequest | undefined,
): r is AuditCommandRequest {
  return r !== undefined && typeof (r as AuditCommandRequest).binary === "string";
}

function isHttpResponse(
  r: AuditHttpResponse | AuditCommandResponse | undefined,
): r is AuditHttpResponse {
  return r !== undefined && typeof (r as AuditHttpResponse).status === "number";
}

function isCommandResponse(
  r: AuditHttpResponse | AuditCommandResponse | undefined,
): r is AuditCommandResponse {
  return r !== undefined && typeof (r as AuditCommandResponse).exit_code === "number";
}

function scrubIfNeeded(
  text: string,
  secrets: readonly ScrubbableSecret[] | undefined,
): string {
  if (secrets === undefined || secrets.length === 0) return text;
  return scrub(text, secrets);
}

function scrubArtifact(
  a: BodyArtifact | undefined,
  secrets: readonly ScrubbableSecret[] | undefined,
): BodyArtifact | undefined {
  if (a === undefined) return undefined;
  if (isTextArtifact(a)) {
    const scrubbed = scrubIfNeeded(a.text, secrets);
    const out: TextBodyArtifact = {
      kind: "text",
      text: scrubbed,
      original_bytes: a.original_bytes,
      truncated: a.truncated,
      truncated_bytes: a.truncated_bytes,
    };
    return out;
  }
  if (isBinaryArtifact(a)) {
    const out: BinaryBodyArtifact = {
      kind: "binary",
      bytes: a.bytes,
      sha256: a.sha256,
    };
    return out;
  }
  return a;
}

function scrubHeaders(
  hs: readonly AuditHeader[] | undefined,
  secrets: readonly ScrubbableSecret[] | undefined,
): readonly AuditHeader[] {
  if (hs === undefined) return [];
  return hs.map((h) => ({
    name: scrubIfNeeded(h.name, secrets),
    value: scrubIfNeeded(h.value, secrets),
    scrubbed: h.scrubbed,
  }));
}

function bodySection(
  present: boolean,
  artifact: BodyArtifact | undefined,
  opts: BuildRenderOptions,
  errorHint?: string,
): RenderBodySection {
  if (!present) {
    return { status: "not_captured" };
  }
  if (opts.pruned === true) {
    return { status: "pruned" };
  }
  if (opts.bodiesError !== undefined) {
    const result: RenderBodySection = {
      status: "decrypt_failed",
      error: opts.bodiesError.message,
    };
    return result;
  }
  if (artifact === undefined) {
    return { status: "not_captured", ...(errorHint !== undefined ? { error: errorHint } : {}) };
  }
  return { status: "present", artifact: scrubArtifact(artifact, opts.inScopeSecrets) ?? artifact };
}

function stagesFromTiming(
  timing: AuditEvent["timing"],
): RenderTimeline {
  if (timing === undefined) {
    return { stages: [] };
  }
  const entries: Array<{ name: string; ts: string }> = [];
  entries.push({ name: "received", ts: timing.received_at });
  if (timing.policy_checked_at !== undefined)
    entries.push({ name: "policy_checked", ts: timing.policy_checked_at });
  if (timing.upstream_started_at !== undefined)
    entries.push({ name: "upstream_started", ts: timing.upstream_started_at });
  if (timing.upstream_finished_at !== undefined)
    entries.push({ name: "upstream_finished", ts: timing.upstream_finished_at });
  entries.push({ name: "returned", ts: timing.returned_at });

  const stages: RenderStage[] = [];
  let prev: number | undefined;
  for (const e of entries) {
    const t = Date.parse(e.ts);
    const stage: RenderStage = Number.isNaN(t)
      ? { name: e.name, ts: e.ts }
      : prev === undefined
        ? { name: e.name, ts: e.ts }
        : { name: e.name, ts: e.ts, delta_ms: t - prev };
    stages.push(stage);
    if (!Number.isNaN(t)) prev = t;
  }
  const firstTs = Date.parse(entries[0]?.ts ?? "");
  const lastTs = Date.parse(entries[entries.length - 1]?.ts ?? "");
  const total =
    !Number.isNaN(firstTs) && !Number.isNaN(lastTs) ? lastTs - firstTs : undefined;
  return total !== undefined ? { stages, total_ms: total } : { stages };
}

// ──────────────────────────────────────────────────────────────────────────
// Main entry

export function buildRenderModel(
  event: AuditEvent,
  opts: BuildRenderOptions = {},
): RenderModel {
  const secrets = opts.inScopeSecrets;
  const surface = event.surface ?? inferSurface(event);
  const process: RenderProcess = {
    cwd:
      event.process_context?.cwd !== undefined
        ? event.process_context.cwd
        : event.caller_cwd,
    ts: event.ts,
    surface,
    ...(event.process_context?.pid !== undefined ? { pid: event.process_context.pid } : {}),
    ...(event.process_context?.argv !== undefined
      ? { argv: event.process_context.argv.map((a) => scrubIfNeeded(a, secrets)) }
      : {}),
    ...(event.process_context?.tool_name !== undefined
      ? { tool_name: event.process_context.tool_name }
      : {}),
  };

  const timeline = stagesFromTiming(event.timing);

  const injected: RenderInjectedSecret[] = (event.injected_secrets ?? []).map(
    (s) => ({
      secret_name: s.secret_name,
      scope: s.scope,
      target: s.target,
    }),
  );

  const request = buildRequestView(event, opts);
  const response = buildResponseView(event, opts);

  const model: RenderModel = {
    id: event.request_id,
    ts: event.ts,
    surface,
    outcome: event.outcome,
    ...(event.code !== undefined ? { code: event.code } : {}),
    ...(event.reason !== undefined
      ? { reason: scrubIfNeeded(event.reason, secrets) }
      : {}),
    secret_name: event.secret_name,
    target: event.target,
    process,
    timeline,
    ...(event.rate_limit_state !== undefined
      ? {
          rate_limit: {
            remaining: event.rate_limit_state.remaining,
            capacity: event.rate_limit_state.capacity,
            window_seconds: event.rate_limit_state.window_seconds,
          },
        }
      : {}),
    injected_secrets: injected,
    request,
    response,
  };
  return model;
}

function inferSurface(event: AuditEvent): string {
  if (event.surface !== undefined) return event.surface;
  if (event.tool === "http_request") return "mcp_http_request";
  if (event.tool === "run_command") return "mcp_run_command";
  return event.tool.length > 0 ? event.tool : "cli";
}

function buildRequestView(
  event: AuditEvent,
  opts: BuildRenderOptions,
): RenderRequestView {
  const secrets = opts.inScopeSecrets;
  const req = event.request;
  const bodies = opts.bodies;
  if (isHttpRequest(req)) {
    const view: RenderHttpRequestView = {
      status: "present",
      method: req.method,
      url: scrubIfNeeded(req.url, secrets),
      headers: scrubHeaders(req.headers, secrets),
      body: bodySection(true, bodies?.request, opts),
    };
    return { kind: "http", view };
  }
  if (isCommandRequest(req)) {
    const view: RenderCommandRequestView = {
      status: "present",
      binary: req.binary,
      args: req.args.map((a) => scrubIfNeeded(a, secrets)),
      env_keys: [...req.env_keys],
      ...(req.cwd !== undefined ? { cwd: req.cwd } : {}),
    };
    return { kind: "command", view };
  }
  // Pre-F13 fallback: synthesize a minimal view from legacy `detail`.
  if (event.detail !== undefined) {
    if (event.detail.method !== undefined || event.detail.url !== undefined) {
      const view: RenderHttpRequestView = {
        status: "not_captured",
        ...(event.detail.method !== undefined ? { method: event.detail.method } : {}),
        ...(event.detail.url !== undefined ? { url: scrubIfNeeded(event.detail.url, secrets) } : {}),
        headers: [],
        body: bodySection(false, undefined, opts),
      };
      return { kind: "http", view };
    }
    if (event.detail.argv !== undefined) {
      const view: RenderCommandRequestView = {
        status: "not_captured",
        binary: event.target,
        args: event.detail.argv.map((a) => scrubIfNeeded(a, secrets)),
        env_keys: [],
      };
      return { kind: "command", view };
    }
  }
  return { kind: "none", status: "not_captured" };
}

function buildResponseView(
  event: AuditEvent,
  opts: BuildRenderOptions,
): RenderResponseView {
  const secrets = opts.inScopeSecrets;
  const res = event.response;
  const bodies = opts.bodies;
  if (isHttpResponse(res)) {
    const view: RenderHttpResponseView = {
      status: "present",
      status_code: res.status,
      headers: scrubHeaders(res.headers, secrets),
      body: bodySection(true, bodies?.response, opts),
    };
    return { kind: "http", view };
  }
  if (isCommandResponse(res)) {
    const view: RenderCommandResponseView = {
      status: "present",
      exit_code: res.exit_code,
      stdout: bodySection(true, bodies?.stdout, opts),
      stderr: bodySection(true, bodies?.stderr, opts),
    };
    return { kind: "command", view };
  }
  if (event.detail !== undefined) {
    if (event.detail.response_status !== undefined) {
      const view: RenderHttpResponseView = {
        status: "not_captured",
        status_code: event.detail.response_status,
        headers: [],
        body: bodySection(false, undefined, opts),
      };
      return { kind: "http", view };
    }
    if (event.detail.exit_code !== undefined) {
      const view: RenderCommandResponseView = {
        status: "not_captured",
        exit_code: event.detail.exit_code,
        stdout: bodySection(false, undefined, opts),
        stderr: bodySection(false, undefined, opts),
      };
      return { kind: "command", view };
    }
  }
  return { kind: "none", status: "not_captured" };
}
