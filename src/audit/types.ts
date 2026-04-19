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
   */
  detail?: AuditEventDetail;
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
