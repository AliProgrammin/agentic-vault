// http_request — MCP tool with secret injection.
//
// Injects named secrets from the vault into HTTP headers or query params
// at request time, enforcing each secret's policy (host allowlist) and
// rate limit, then scrubbing the response body against every in-scope
// secret before returning it to the agent.
//
// Any policy deny, rate-limit deny, timeout, or missing secret aborts
// the entire request with a typed error code. Scrubbing of the response
// is defense-in-depth for accidental leakage — not an anti-exfiltration
// control; the real anti-exfil boundary is the policy layer (Feature 4).
//
// The Zod input schema adds a `name` field to each `inject` entry
// (beyond the brief's `{ secret, into, template }` triple) because the
// brief's example template `"Bearer {{value}}"` is value-only and
// carries no destination name: a header injection must know which
// header name to set, and a query injection must know which query
// parameter name to append. The deviation is intentional.
//
// An `inject` array with at least one entry is required: without any
// injection, the tool would be a policy-free generic HTTP client,
// contradicting the deny-by-default posture of SecretProxy.
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  createRequestId,
  AUDIT_DETAIL_CAP_BYTES,
  DEFAULT_REQUEST_BODY_CAP_BYTES,
  DEFAULT_RESPONSE_BODY_CAP_BYTES,
  classifyBody,
  classifyText,
  type AuditErrorCode,
  type AuditEvent,
  type AuditEventDetail,
  type AuditHeader,
  type AuditHttpRequest,
  type AuditHttpResponse,
  type AuditInjectedSecret,
  type AuditLogger,
  type AuditPolicyDecision,
  type AuditProcessContext,
  type AuditRateLimitState,
  type AuditTiming,
  type BodyArtifact,
  type BodyBlobPayload,
  type EncryptedBodyStore,
} from "../audit/index.js";
import { checkHttp, policySchema, type Policy } from "../policy/index.js";
import type { RateLimiter } from "../ratelimit/index.js";
import { listMerged, resolveSecret } from "../scope/index.js";
import { scrub as defaultScrub, type ScrubbableSecret } from "../scrub/index.js";
import type { McpServerDeps } from "./server.js";

export interface HttpRequestDeps extends McpServerDeps {
  readonly audit: AuditLogger;
  readonly rateLimiter: RateLimiter;
  readonly scrub?: typeof defaultScrub;
  readonly fetch?: typeof fetch;
  readonly requestTimeoutMs?: number;
  readonly clock?: () => number;
  /**
   * Optional encrypted body-blob store for F13's audit detail view. When
   * present, the tool writes the (scrubbed, capped) request + response
   * bodies to the store and attaches a `body_ref` to the allowed audit
   * record. Absent in unit tests that only care about the summary record.
   */
  readonly bodyStore?: EncryptedBodyStore;
  /** Injected in tests for deterministic process-context/argv. */
  readonly processContextProvider?: () => AuditProcessContext;
}

const TOOL_NAME = "http_request";
const RESPONSE_BODY_CAP_BYTES = 10 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 60_000;

const HTTP_METHODS = [
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
] as const;

const PLACEHOLDER_SCAN = /\{\{([^}]*)\}\}/g;

function templateUsesOnlyValuePlaceholder(template: string): boolean {
  const matches = template.matchAll(PLACEHOLDER_SCAN);
  for (const m of matches) {
    if (m[1] !== "value") {
      return false;
    }
  }
  return true;
}

const injectEntrySchema = z
  .object({
    secret: z.string().min(1, { message: "secret name must not be empty" }),
    into: z.enum(["header", "query"]),
    name: z
      .string()
      .min(1, { message: "injection target name must not be empty" }),
    template: z.string().refine(templateUsesOnlyValuePlaceholder, {
      message: "template must use only {{value}} as a placeholder",
    }),
  })
  .strict();

export const HTTP_REQUEST_INPUT_SHAPE = {
  url: z.string().min(1, { message: "url must not be empty" }),
  method: z.enum(HTTP_METHODS),
  headers: z.record(z.string()).optional(),
  body: z.string().optional(),
  inject: z
    .array(injectEntrySchema)
    .min(1, { message: "inject must contain at least one entry" }),
} as const;

export const httpRequestInputSchema = z
  .object(HTTP_REQUEST_INPUT_SHAPE)
  .strict();

export type HttpRequestInput = z.infer<typeof httpRequestInputSchema>;

export interface HttpRequestOk {
  status: "ok";
  http_status: number;
  headers: Record<string, string>;
  body: string;
  truncated: boolean;
}

export interface HttpRequestError {
  status: "error";
  code: AuditErrorCode;
  reason: string;
  secret_name?: string;
  retry_after_seconds?: number;
}

export type HttpRequestResult = HttpRequestOk | HttpRequestError;

interface PreparedInjection {
  secretName: string;
  value: string;
  into: "header" | "query";
  name: string;
  template: string;
  scope: "global" | "project";
  rateSnapshot?: AuditRateLimitState;
}

function truncate(s: string): string {
  if (Buffer.byteLength(s, "utf8") <= AUDIT_DETAIL_CAP_BYTES) return s;
  return Buffer.from(s, "utf8")
    .subarray(0, AUDIT_DETAIL_CAP_BYTES)
    .toString("utf8") + "\u2026";
}

function buildEvent(
  base: {
    requestId: string;
    callerCwd: string;
    secretName: string;
    target: string;
    outcome: "allowed" | "denied";
  },
  extra: {
    code?: AuditErrorCode;
    reason?: string;
    detail?: AuditEventDetail;
  },
): AuditEvent {
  const event: AuditEvent = {
    ts: new Date().toISOString(),
    secret_name: base.secretName,
    tool: TOOL_NAME,
    target: base.target,
    outcome: base.outcome,
    request_id: base.requestId,
    caller_cwd: base.callerCwd,
    ...(extra.code !== undefined ? { code: extra.code } : {}),
    ...(extra.reason !== undefined ? { reason: extra.reason } : {}),
    ...(extra.detail !== undefined ? { detail: extra.detail } : {}),
  };
  return event;
}

async function readCappedBody(
  response: Response,
  cap: number,
): Promise<{ bytes: Uint8Array; truncated: boolean }> {
  if (!response.body) {
    const buf = new Uint8Array(await response.arrayBuffer());
    if (buf.byteLength > cap) {
      return { bytes: buf.subarray(0, cap), truncated: true };
    }
    return { bytes: buf, truncated: false };
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      break;
    }
    if (!value) {
      continue;
    }
    const remaining = cap - total;
    if (value.byteLength > remaining) {
      if (remaining > 0) {
        chunks.push(value.subarray(0, remaining));
        total += remaining;
      }
      truncated = true;
      await reader.cancel();
      break;
    }
    chunks.push(value);
    total += value.byteLength;
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    bytes.set(c, offset);
    offset += c.byteLength;
  }
  return { bytes, truncated };
}

export async function runHttpRequest(
  input: HttpRequestInput,
  deps: HttpRequestDeps,
): Promise<HttpRequestResult> {
  const scrubFn = deps.scrub ?? defaultScrub;
  const fetchImpl: typeof fetch =
    deps.fetch ?? globalThis.fetch.bind(globalThis);
  const clock = deps.clock ?? ((): number => Date.now());
  const timeoutMs = deps.requestTimeoutMs ?? DEFAULT_TIMEOUT_MS;
  const requestId = createRequestId();
  const callerCwd = process.cwd();
  const receivedAt = new Date(clock()).toISOString();
  const processContext: AuditProcessContext =
    deps.processContextProvider !== undefined
      ? deps.processContextProvider()
      : { pid: process.pid, cwd: callerCwd, tool_name: TOOL_NAME };

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(input.url);
  } catch {
    return {
      status: "error",
      code: "INVALID_INJECTION",
      reason: `url '${input.url}' could not be parsed`,
    };
  }
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    return {
      status: "error",
      code: "INVALID_INJECTION",
      reason: `scheme '${parsedUrl.protocol.replace(/:$/, "")}' is not http or https`,
    };
  }

  const target = parsedUrl.hostname;

  const recordAudit = async (
    secretName: string,
    outcome: "allowed" | "denied",
    extra: {
      code?: AuditErrorCode;
      reason?: string;
      detail?: AuditEventDetail;
    } = {},
  ): Promise<void> => {
    await deps.audit.record(
      buildEvent(
        { requestId, callerCwd, secretName, target, outcome },
        extra,
      ),
    );
  };

  const prepared: PreparedInjection[] = [];

  for (const inj of input.inject) {
    const resolved = resolveSecret(inj.secret, deps.sources);
    if (!resolved) {
      const reason = `secret '${inj.secret}' not found in any scope`;
      await recordAudit(inj.secret, "denied", {
        code: "SECRET_NOT_FOUND",
        reason,
      });
      return {
        status: "error",
        code: "SECRET_NOT_FOUND",
        reason,
        secret_name: inj.secret,
      };
    }

    const policyParse = policySchema.safeParse(resolved.policy);
    const policy: Policy | undefined = policyParse.success
      ? policyParse.data
      : undefined;

    const httpDecision = checkHttp(policy, input.url);
    if (!httpDecision.allowed) {
      await recordAudit(inj.secret, "denied", {
        code: "POLICY_DENIED",
        reason: httpDecision.reason,
      });
      return {
        status: "error",
        code: "POLICY_DENIED",
        reason: httpDecision.reason,
        secret_name: inj.secret,
      };
    }

    if (!policy) {
      // Unreachable — checkHttp denies when policy is undefined — but this
      // keeps TypeScript narrow for the rate-limit call below.
      const reason = "no policy attached to secret";
      await recordAudit(inj.secret, "denied", {
        code: "POLICY_DENIED",
        reason,
      });
      return {
        status: "error",
        code: "POLICY_DENIED",
        reason,
        secret_name: inj.secret,
      };
    }

    const rateDecision = await deps.rateLimiter.tryConsume(inj.secret, policy);
    if (!rateDecision.allowed) {
      const reason = `rate limit exceeded for secret '${inj.secret}' (retry after ${String(rateDecision.retry_after_seconds)}s)`;
      await recordAudit(inj.secret, "denied", {
        code: "RATE_LIMITED",
        reason,
      });
      return {
        status: "error",
        code: "RATE_LIMITED",
        reason,
        secret_name: inj.secret,
        retry_after_seconds: rateDecision.retry_after_seconds,
      };
    }

    const rateSnapshot: AuditRateLimitState | undefined = rateDecision.allowed
      ? {
          remaining: Math.max(0, rateDecision.remaining),
          capacity: policy.rate_limit.requests,
          window_seconds: policy.rate_limit.window_seconds,
        }
      : undefined;
    prepared.push({
      secretName: inj.secret,
      value: resolved.value,
      into: inj.into,
      name: inj.name,
      template: inj.template,
      scope: resolved.scope,
      ...(rateSnapshot !== undefined ? { rateSnapshot } : {}),
    });
  }

  const policyCheckedAt = new Date(clock()).toISOString();

  const finalHeaders = new Headers();
  if (input.headers) {
    for (const [k, v] of Object.entries(input.headers)) {
      finalHeaders.set(k, v);
    }
  }
  const finalUrl = new URL(parsedUrl.toString());
  for (const p of prepared) {
    const rendered = p.template.split("{{value}}").join(p.value);
    if (p.into === "header") {
      finalHeaders.set(p.name, rendered);
    } else {
      finalUrl.searchParams.append(p.name, rendered);
    }
  }

  const scrubSecrets: ScrubbableSecret[] = [];
  for (const entry of listMerged(deps.sources)) {
    const r = resolveSecret(entry.name, deps.sources);
    if (r) {
      scrubSecrets.push({ name: r.name, value: r.value });
    }
  }

  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => {
    controller.abort();
  }, timeoutMs);
  const upstreamStartedAt = new Date(clock()).toISOString();
  let response: Response;
  try {
    const init: RequestInit = {
      method: input.method,
      headers: finalHeaders,
      signal: controller.signal,
    };
    if (
      input.body !== undefined &&
      input.method !== "GET" &&
      input.method !== "HEAD"
    ) {
      (init as { body?: string }).body = input.body;
    }
    response = await fetchImpl(finalUrl.toString(), init);
  } catch (err) {
    clearTimeout(timeoutHandle);
    if (controller.signal.aborted) {
      const reason = `request exceeded ${String(timeoutMs)}ms timeout`;
      for (const p of prepared) {
        await recordAudit(p.secretName, "denied", {
          code: "TIMEOUT",
          reason,
        });
      }
      return {
        status: "error",
        code: "TIMEOUT",
        reason,
      };
    }
    const message = err instanceof Error ? err.message : String(err);
    for (const p of prepared) {
      await recordAudit(p.secretName, "denied", {
        code: "POLICY_DENIED",
        reason: `fetch failed: ${message}`,
      });
    }
    return {
      status: "error",
      code: "POLICY_DENIED",
      reason: `fetch failed: ${message}`,
    };
  }
  clearTimeout(timeoutHandle);

  const { bytes, truncated } = await readCappedBody(
    response,
    RESPONSE_BODY_CAP_BYTES,
  );
  const upstreamFinishedAt = new Date(clock()).toISOString();
  const rawBody = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const scrubbedBody = scrubFn(rawBody, scrubSecrets);

  const scrubbedHeaders: Record<string, string> = {};
  for (const [k, v] of response.headers.entries()) {
    const scrubbedName = scrubFn(k, scrubSecrets);
    scrubbedHeaders[scrubbedName] = scrubFn(v, scrubSecrets);
  }

  const scrubbedRequestBody =
    input.body !== undefined && input.method !== "GET" && input.method !== "HEAD"
      ? scrubFn(input.body, scrubSecrets)
      : undefined;
  const detail: AuditEventDetail = {
    method: input.method,
    url: scrubFn(finalUrl.toString(), scrubSecrets),
    ...(scrubbedRequestBody !== undefined
      ? { request_body: truncate(scrubbedRequestBody) }
      : {}),
    response_status: response.status,
    response_body: truncate(scrubbedBody),
  };

  // ── F13 enrichment ────────────────────────────────────────────────────
  // Classify + cap + persist bodies to the encrypted body store.
  // Metadata (scrubbed headers + status + sizes) lives on the plaintext
  // JSONL entry so filtering does not require unlock.

  // Track which header names were populated by an injected secret so the
  // UI can badge them as "scrubbed" without relying on color alone.
  const injectedHeaderNames = new Set(
    prepared
      .filter((p) => p.into === "header")
      .map((p) => p.name.toLowerCase()),
  );
  const scrubbedRequestHeaders: AuditHeader[] = [];
  for (const [k, v] of finalHeaders.entries()) {
    scrubbedRequestHeaders.push({
      name: scrubFn(k, scrubSecrets),
      value: scrubFn(v, scrubSecrets),
      scrubbed: injectedHeaderNames.has(k.toLowerCase()),
    });
  }
  const scrubbedResponseHeaders: AuditHeader[] = [];
  for (const [k, v] of response.headers.entries()) {
    scrubbedResponseHeaders.push({
      name: scrubFn(k, scrubSecrets),
      value: scrubFn(v, scrubSecrets),
      scrubbed: false,
    });
  }

  const contentType = response.headers.get("content-type") ?? undefined;
  // Binary-probe first (uncapped) so binary detection sees the full payload.
  // For text: scrub the FULL decoded text, then cap — this ensures a secret
  // straddling the cap boundary cannot leave a partial prefix in the blob.
  const binaryProbe: BodyArtifact = classifyBody(bytes, {
    cap: Number.MAX_SAFE_INTEGER,
    ...(contentType !== undefined ? { contentType } : {}),
  });
  const scrubbedResponseArtifact: BodyArtifact =
    binaryProbe.kind === "text"
      ? classifyText(scrubFn(binaryProbe.text, scrubSecrets), {
          cap: DEFAULT_RESPONSE_BODY_CAP_BYTES,
        })
      : binaryProbe;
  const requestArtifact: BodyArtifact | undefined =
    scrubbedRequestBody !== undefined
      ? classifyText(scrubbedRequestBody, {
          cap: DEFAULT_REQUEST_BODY_CAP_BYTES,
        })
      : undefined;

  const requestView: AuditHttpRequest = {
    method: input.method,
    url: scrubFn(finalUrl.toString(), scrubSecrets),
    headers: scrubbedRequestHeaders,
    ...(requestArtifact !== undefined && requestArtifact.kind === "text"
      ? { body_size: requestArtifact.original_bytes }
      : requestArtifact !== undefined && requestArtifact.kind === "binary"
        ? { body_size: requestArtifact.bytes }
        : {}),
  };
  const responseView: AuditHttpResponse = {
    status: response.status,
    headers: scrubbedResponseHeaders,
    body_size:
      scrubbedResponseArtifact.kind === "text"
        ? scrubbedResponseArtifact.original_bytes
        : scrubbedResponseArtifact.kind === "binary"
          ? scrubbedResponseArtifact.bytes
          : 0,
  };

  const injectedSecretsList: AuditInjectedSecret[] = prepared.map((p) => ({
    secret_name: p.secretName,
    scope: p.scope,
    target: p.into === "header" ? p.name : `query:${p.name}`,
  }));

  const policyDecision: AuditPolicyDecision = {
    outcome: "allowed",
  };

  const returnedAt = new Date(clock()).toISOString();
  const timing: AuditTiming = {
    received_at: receivedAt,
    policy_checked_at: policyCheckedAt,
    upstream_started_at: upstreamStartedAt,
    upstream_finished_at: upstreamFinishedAt,
    returned_at: returnedAt,
  };
  const firstRate = prepared.find((p) => p.rateSnapshot !== undefined)?.rateSnapshot;

  // Write the body blob (scrubbed + capped) if the store is present.
  let blobWritten = false;
  if (deps.bodyStore !== undefined) {
    const payload: BodyBlobPayload = {
      ...(requestArtifact !== undefined
        ? {
            request:
              requestArtifact.kind === "text"
                ? {
                    kind: "text",
                    text: scrubFn(requestArtifact.text, scrubSecrets),
                    original_bytes: requestArtifact.original_bytes,
                    truncated: requestArtifact.truncated,
                    truncated_bytes: requestArtifact.truncated_bytes,
                  }
                : requestArtifact,
          }
        : {}),
      response: scrubbedResponseArtifact,
    };
    try {
      await deps.bodyStore.writeBody(requestId, payload);
      blobWritten = true;
    } catch {
      // If the body store fails, the metadata record is still written;
      // the render view will show "not captured" for the body section.
    }
  }

  const f13Extras = {
    surface: "mcp_http_request" as const,
    request: requestView,
    response: responseView,
    injected_secrets: injectedSecretsList,
    policy_decision: policyDecision,
    timing,
    process_context: processContext,
    ...(firstRate !== undefined ? { rate_limit_state: firstRate } : {}),
    ...(blobWritten ? { body_ref: { blob_id: requestId } } : {}),
  };

  for (const p of prepared) {
    await recordAuditExtended(
      deps.audit,
      { requestId, callerCwd, secretName: p.secretName, target, outcome: "allowed" },
      { detail },
      f13Extras,
    );
  }
  if (truncated) {
    const annotationSecret = prepared[0];
    if (annotationSecret) {
      await recordAuditExtended(
        deps.audit,
        {
          requestId,
          callerCwd,
          secretName: annotationSecret.secretName,
          target,
          outcome: "allowed",
        },
        {
          code: "SIZE_LIMIT",
          reason: `response body exceeded ${String(RESPONSE_BODY_CAP_BYTES)} bytes and was truncated`,
        },
        f13Extras,
      );
    }
  }

  return {
    status: "ok",
    http_status: response.status,
    headers: scrubbedHeaders,
    body: scrubbedBody,
    truncated,
  };
}

// Local helper that layers F13 fields on top of the legacy event shape.
async function recordAuditExtended(
  logger: AuditLogger,
  base: {
    requestId: string;
    callerCwd: string;
    secretName: string;
    target: string;
    outcome: "allowed" | "denied";
  },
  extra: {
    code?: AuditErrorCode;
    reason?: string;
    detail?: AuditEventDetail;
  },
  f13: Partial<AuditEvent>,
): Promise<void> {
  const built = buildEvent(base, extra);
  await logger.record({ ...built, ...f13 });
}

export function registerHttpRequest(
  server: McpServer,
  deps: HttpRequestDeps,
): void {
  server.registerTool(
    "http_request",
    {
      description: `Perform an HTTP request with named secrets injected into headers or query parameters at call time. Each injected secret's policy allowlist and rate limit are enforced; the response body and headers are scrubbed against every in-scope secret before return. Response body is capped at 10MB; requests exceeding a 60s timeout are aborted.

USAGE EXAMPLES:

Bearer token (most APIs — OpenAI, Anthropic, OpenRouter, etc.):
  inject: [{ secret: "OPENROUTER_API_KEY", into: "header", name: "Authorization", template: "Bearer {{value}}" }]

Raw API key header (e.g. X-API-Key style):
  inject: [{ secret: "MY_KEY", into: "header", name: "X-API-Key", template: "{{value}}" }]

Query parameter (e.g. ?api_key=...):
  inject: [{ secret: "MY_KEY", into: "query", name: "api_key", template: "{{value}}" }]

IMPORTANT: The placeholder is always exactly {{value}} — no other placeholders are supported. For Bearer tokens you MUST write "Bearer {{value}}" (with the "Bearer " prefix) in the template field — do NOT write just "{{value}}" for Authorization headers that require Bearer scheme.`,
      inputSchema: HTTP_REQUEST_INPUT_SHAPE,
    },
    async (args) => {
      const result = await runHttpRequest(args as HttpRequestInput, deps);
      return {
        content: [{ type: "text", text: JSON.stringify(result) }],
        structuredContent: { ...result },
        isError: result.status === "error",
      };
    },
  );
}
