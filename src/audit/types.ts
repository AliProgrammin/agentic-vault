export type AuditOutcome = "allowed" | "denied";

export const AUDIT_ERROR_CODES = [
  "POLICY_DENIED",
  "RATE_LIMITED",
  "SECRET_NOT_FOUND",
  "VAULT_LOCKED",
  "SIZE_LIMIT",
  "TIMEOUT",
  "INVALID_INJECTION",
] as const satisfies readonly string[];

export type AuditErrorCode = (typeof AUDIT_ERROR_CODES)[number];

export const AUDIT_SURFACES = [
  "cli",
  "mcp_http_request",
  "mcp_run_command",
] as const satisfies readonly string[];

export type AuditSurface = (typeof AUDIT_SURFACES)[number];

/**
 * Scrubbed injected-secret record persisted on the audit entry. Only metadata
 * — never the value, never the policy.
 */
export interface AuditInjectedSecret {
  readonly secret_name: string;
  readonly scope: string;
  readonly target: string;
}

export interface AuditPolicyDecision {
  readonly outcome: AuditOutcome;
  readonly code?: AuditErrorCode;
  readonly reason?: string;
}

/**
 * Per-injection rate-limiter state at decision time. Captured best-effort; in
 * rare failure paths (secret not found, invalid policy) callers may omit.
 */
export interface AuditRateLimitState {
  readonly remaining: number;
  readonly capacity: number;
  readonly window_seconds: number;
}

/**
 * Lifecycle stage timestamps. All ISO-8601 UTC. Downstream renderers compute
 * per-stage durations from these.
 */
export interface AuditTiming {
  readonly received_at: string;
  readonly policy_checked_at?: string;
  readonly upstream_started_at?: string;
  readonly upstream_finished_at?: string;
  readonly returned_at: string;
}

export interface AuditProcessContext {
  readonly pid: number;
  readonly cwd: string;
  readonly argv?: readonly string[];
  readonly tool_name?: string;
}

/**
 * Pointer to the encrypted body-blob store for this audit entry. Present when
 * a body store is configured; readers without the unlock key see metadata
 * only.
 */
export interface AuditBodyRef {
  readonly blob_id: string;
}

/**
 * HTTP request artifact captured on the audit entry. Body-bearing fields are
 * NOT serialized on the JSONL record — they live in the encrypted body store,
 * referenced via `body_ref`. The lightweight fields below (method, url,
 * scrubbed headers, header count) remain on the record so filtering/tailing
 * works without an unlock.
 */
export interface AuditHttpRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: readonly AuditHeader[];
  readonly body_size?: number;
}

export interface AuditHttpResponse {
  readonly status: number;
  readonly headers: readonly AuditHeader[];
  readonly body_size?: number;
}

export interface AuditHeader {
  readonly name: string;
  readonly value: string;
  readonly scrubbed: boolean;
}

export interface AuditCommandRequest {
  readonly binary: string;
  readonly args: readonly string[];
  readonly cwd?: string;
  readonly env_keys: readonly string[];
}

export interface AuditCommandResponse {
  readonly exit_code: number;
  readonly stdout_truncated?: boolean;
  readonly stderr_truncated?: boolean;
}

export interface AuditEvent {
  ts: string;
  secret_name: string;
  tool: string;
  target: string;
  outcome: AuditOutcome;
  reason?: string;
  code?: AuditErrorCode;
  request_id: string;
  caller_cwd: string;
  /**
   * Optional per-tool detail payload. Values are ALWAYS scrubbed — every
   * in-scope secret replaced with [REDACTED:NAME] before the event is
   * recorded. Each string is truncated to AUDIT_DETAIL_CAP_BYTES.
   *
   * http_request populates: method, url, request_body, response_status,
   * response_body.
   *
   * run_command populates: argv, exit_code, stdout, stderr.
   *
   * NOTE: retained for backward compatibility with F5/F10/F11 consumers;
   * F13's richer view uses the `request` / `response` / `body_ref` fields
   * below.
   */
  detail?: AuditEventDetail;

  // F13 fields — all optional for forward/backward compatibility with older
  // records that pre-date the audit-detail view.
  surface?: AuditSurface;
  request?: AuditHttpRequest | AuditCommandRequest;
  response?: AuditHttpResponse | AuditCommandResponse;
  injected_secrets?: readonly AuditInjectedSecret[];
  policy_decision?: AuditPolicyDecision;
  timing?: AuditTiming;
  rate_limit_state?: AuditRateLimitState;
  process_context?: AuditProcessContext;
  body_ref?: AuditBodyRef;
}

export interface AuditEventDetail {
  readonly method?: string;
  readonly url?: string;
  readonly request_body?: string;
  readonly response_status?: number;
  readonly response_body?: string;
  readonly argv?: readonly string[];
  readonly exit_code?: number;
  readonly stdout?: string;
  readonly stderr?: string;
}

export const AUDIT_DETAIL_CAP_BYTES = 2048;

export interface AuditLogger {
  record(event: AuditEvent): Promise<void>;
}
