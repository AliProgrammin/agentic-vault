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
}

export interface AuditLogger {
  record(event: AuditEvent): Promise<void>;
}
