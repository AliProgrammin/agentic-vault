import { z, type ZodError, type ZodType } from "zod";

export const FORBIDDEN_ENV_VAR_NAMES = [
  "LD_PRELOAD",
  "LD_LIBRARY_PATH",
  "DYLD_INSERT_LIBRARIES",
  "DYLD_LIBRARY_PATH",
  "NODE_OPTIONS",
  "PYTHONPATH",
] as const satisfies readonly string[];

const FORBIDDEN_ENV_VAR_SET: ReadonlySet<string> = new Set(FORBIDDEN_ENV_VAR_NAMES);

const FQDN_PATTERN =
  /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;
const FQDN_LABEL_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
const ENV_VAR_PATTERN = /^[A-Z_][A-Z0-9_]*$/;
// Affix-span character class for env var wildcards — the '*' may cover only
// uppercase letters, digits, and underscores (matches the ENV_VAR identifier
// class). Documented here so downstream readers can trace the constraint.
const ENV_WILDCARD_SPAN_PATTERN = /^[A-Z0-9_]+$/;

export type WildcardKind = "unrestricted" | "subdomain" | "affix";

type EntryClassification =
  | { kind: "exact" }
  | { kind: "wildcard"; wildcard_kind: WildcardKind }
  | { kind: "invalid"; reason: string };

/**
 * A wildcard-form entry in an allowlist. Exact entries stay plain strings;
 * only the wildcarded entries carry this object shape. Downstream code MUST
 * narrow via `isWildcardEntry` rather than re-parsing the string.
 */
export interface PolicyWildcardEntry {
  readonly value: string;
  readonly wildcard: true;
  readonly wildcard_kind: WildcardKind;
}

export type PolicyEntry = string | PolicyWildcardEntry;

export function isWildcardEntry(e: PolicyEntry): e is PolicyWildcardEntry {
  return typeof e === "object" && e !== null && e.wildcard === true;
}

/** Extract the literal string value of an entry regardless of shape. */
export function entryValue(e: PolicyEntry): string {
  return typeof e === "string" ? e : e.value;
}

function hasWhitespace(value: string): boolean {
  return /\s/.test(value);
}

function isValidFqdn(value: string): boolean {
  return FQDN_PATTERN.test(value);
}

/**
 * Classify a raw string as exact, wildcard, or invalid for the HTTP host
 * dimension. Pure classifier — no Zod wiring so it can be reused by helpers.
 */
export function classifyHost(
  raw: string,
): EntryClassification {
  if (raw.length === 0) return { kind: "invalid", reason: "host must not be empty" };
  if (hasWhitespace(raw)) return { kind: "invalid", reason: "host must not contain whitespace" };
  if (raw === "*") return { kind: "wildcard", wildcard_kind: "unrestricted" };
  if (raw.startsWith("*.")) {
    const rest = raw.slice(2);
    if (rest.length === 0) {
      return { kind: "invalid", reason: "subdomain wildcard must have at least two labels after '*'" };
    }
    if (rest.includes("*")) {
      return { kind: "invalid", reason: "host may contain at most one leading '*' label" };
    }
    const labels = rest.split(".");
    if (labels.length < 2) {
      return { kind: "invalid", reason: "subdomain wildcard must have at least two labels after '*' (e.g. '*.example.com')" };
    }
    for (const label of labels) {
      if (!FQDN_LABEL_PATTERN.test(label)) {
        return { kind: "invalid", reason: `invalid DNS label '${label}' in wildcard host` };
      }
    }
    // Final TLD must be letters-only, like the strict FQDN rule.
    const tld = labels[labels.length - 1];
    if (tld === undefined || !/^[A-Za-z]{2,63}$/.test(tld)) {
      return { kind: "invalid", reason: "subdomain wildcard TLD must be 2-63 letters" };
    }
    return { kind: "wildcard", wildcard_kind: "subdomain" };
  }
  if (raw.includes("*")) {
    return { kind: "invalid", reason: "host must not contain '*' except as a leading label '*.domain.tld'" };
  }
  if (!isValidFqdn(raw)) {
    return {
      kind: "invalid",
      reason:
        "host must be a plain FQDN without scheme, path, or port (e.g. 'api.example.com')",
    };
  }
  return { kind: "exact" };
}

/**
 * Classify a raw binary string. Binaries accept bare '*' and affix
 * (prefix-* or *-suffix) where the '*' span is constrained at MATCH time,
 * not in the literal pattern — the pattern itself just must have exactly
 * one edge '*'.
 */
export function classifyBinary(
  raw: string,
): EntryClassification {
  if (raw.length === 0) return { kind: "invalid", reason: "binary must not be empty" };
  if (hasWhitespace(raw)) return { kind: "invalid", reason: "binary must not contain whitespace" };
  if (raw === "*") return { kind: "wildcard", wildcard_kind: "unrestricted" };
  const starCount = (raw.match(/\*/g) ?? []).length;
  if (starCount === 0) return { kind: "exact" };
  if (starCount > 1) {
    return { kind: "invalid", reason: "binary may contain at most one '*'" };
  }
  if (raw.startsWith("*") && raw.length > 1) {
    const suffix = raw.slice(1);
    if (suffix.length === 0) {
      return { kind: "invalid", reason: "'*-suffix' pattern requires a non-empty suffix" };
    }
    return { kind: "wildcard", wildcard_kind: "affix" };
  }
  if (raw.endsWith("*") && raw.length > 1) {
    const prefix = raw.slice(0, -1);
    if (prefix.length === 0) {
      return { kind: "invalid", reason: "'prefix-*' pattern requires a non-empty prefix" };
    }
    return { kind: "wildcard", wildcard_kind: "affix" };
  }
  return { kind: "invalid", reason: "binary wildcard must be bare '*', 'prefix-*', or '*-suffix'" };
}

/**
 * Classify a raw env var name. Env vars accept bare '*' and affix forms
 * where the literal portion matches the ENV_VAR identifier class. The
 * wildcard span itself may match only `[A-Z0-9_]+` — checked at MATCH time
 * in enforce.ts so the pattern may be stored in its canonical literal form.
 */
export function classifyEnvVar(
  raw: string,
): EntryClassification {
  if (raw.length === 0) return { kind: "invalid", reason: "env var name must not be empty" };
  if (hasWhitespace(raw)) return { kind: "invalid", reason: "env var name must not contain whitespace" };
  if (raw === "*") return { kind: "wildcard", wildcard_kind: "unrestricted" };
  if (FORBIDDEN_ENV_VAR_SET.has(raw)) {
    return {
      kind: "invalid",
      reason:
        "env var name appears in the forbidden-inject list (e.g. LD_PRELOAD, NODE_OPTIONS)",
    };
  }
  const starCount = (raw.match(/\*/g) ?? []).length;
  if (starCount === 0) {
    if (!ENV_VAR_PATTERN.test(raw)) {
      return { kind: "invalid", reason: "env var name must match ^[A-Z_][A-Z0-9_]*$" };
    }
    return { kind: "exact" };
  }
  if (starCount > 1) {
    return { kind: "invalid", reason: "env var wildcard may contain at most one '*'" };
  }
  if (raw.startsWith("*")) {
    const suffix = raw.slice(1);
    if (suffix.length === 0) {
      return { kind: "invalid", reason: "'*-suffix' env wildcard requires a non-empty suffix" };
    }
    // Suffix literal must match a suffix of a valid env var name. It must
    // therefore be composed of [A-Z0-9_] characters.
    if (!ENV_WILDCARD_SPAN_PATTERN.test(suffix)) {
      return { kind: "invalid", reason: "env var wildcard suffix must be uppercase letters, digits, or underscores" };
    }
    return { kind: "wildcard", wildcard_kind: "affix" };
  }
  if (raw.endsWith("*")) {
    const prefix = raw.slice(0, -1);
    if (prefix.length === 0) {
      return { kind: "invalid", reason: "'prefix-*' env wildcard requires a non-empty prefix" };
    }
    // Prefix must itself be a valid partial env var name (starts with
    // [A-Z_], subsequent chars in [A-Z0-9_]).
    if (!/^[A-Z_][A-Z0-9_]*$/.test(prefix)) {
      return { kind: "invalid", reason: "env var wildcard prefix must match ^[A-Z_][A-Z0-9_]*$" };
    }
    return { kind: "wildcard", wildcard_kind: "affix" };
  }
  return { kind: "invalid", reason: "env var wildcard must be bare '*', 'PREFIX_*', or '*_SUFFIX'" };
}

function canonicalWildcard(value: string, kind: WildcardKind): PolicyWildcardEntry {
  return { value, wildcard: true, wildcard_kind: kind };
}

interface DimSchemaOptions {
  readonly strictMode: boolean;
  readonly dimension: string;
  readonly classify: (raw: string) => EntryClassification;
  readonly preParsedWildcard?: ZodType<PolicyWildcardEntry>;
}

// Accept either a raw string (exact or wildcard literal) or an already-shaped
// PolicyWildcardEntry object. Raw strings are classified; if they resolve to
// a wildcard and strictMode is true, the entry is rejected with a named error.
function makeEntrySchema(opts: DimSchemaOptions): ZodType<PolicyEntry> {
  return z.preprocess((input, ctx) => {
    if (typeof input === "string") {
      const cls = opts.classify(input);
      if (cls.kind === "invalid") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${opts.dimension}: ${cls.reason} (entry: ${JSON.stringify(input)})`,
        });
        return z.NEVER;
      }
      if (cls.kind === "exact") {
        return input;
      }
      // wildcard
      if (opts.strictMode) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${opts.dimension}: wildcard entry ${JSON.stringify(input)} rejected because vault strict_mode is true`,
        });
        return z.NEVER;
      }
      return canonicalWildcard(input, cls.wildcard_kind);
    }
    if (input !== null && typeof input === "object") {
      // Treat as pre-shaped wildcard; validate it.
      const obj = input as Record<string, unknown>;
      const value = obj["value"];
      const wildcard = obj["wildcard"];
      const kind = obj["wildcard_kind"];
      if (typeof value !== "string" || wildcard !== true || typeof kind !== "string") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${opts.dimension}: invalid wildcard entry shape (expected {value, wildcard: true, wildcard_kind})`,
        });
        return z.NEVER;
      }
      const cls = opts.classify(value);
      if (cls.kind !== "wildcard" || cls.wildcard_kind !== kind) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${opts.dimension}: wildcard entry ${JSON.stringify(value)} does not classify as ${String(kind)}`,
        });
        return z.NEVER;
      }
      if (opts.strictMode) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${opts.dimension}: wildcard entry ${JSON.stringify(value)} rejected because vault strict_mode is true`,
        });
        return z.NEVER;
      }
      return canonicalWildcard(value, cls.wildcard_kind);
    }
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: `${opts.dimension}: entry must be a string or wildcard object`,
    });
    return z.NEVER;
  }, z.union([
    z.string(),
    z.object({
      value: z.string(),
      wildcard: z.literal(true),
      wildcard_kind: z.enum(["unrestricted", "subdomain", "affix"]),
    }),
  ])) as unknown as ZodType<PolicyEntry>;
}

const argPatternSchema = z
  .string()
  .min(1, { message: "arg pattern must not be empty" })
  .refine((v) => v.startsWith("^") && v.endsWith("$"), {
    message: "arg pattern must be anchored with '^' at start and '$' at end",
  })
  .refine(
    (v) => {
      try {
        new RegExp(v);
        return true;
      } catch {
        return false;
      }
    },
    { message: "arg pattern must be a valid regular expression" },
  );

const rateLimitSchema = z.object({
  requests: z.number().int().positive({ message: "requests must be a positive integer" }),
  window_seconds: z
    .number()
    .int()
    .positive({ message: "window_seconds must be a positive integer" }),
});

export interface CommandPolicy {
  readonly binary: PolicyEntry;
  readonly allowed_args_patterns: readonly string[];
  readonly forbidden_args_patterns?: readonly string[];
}

export interface Policy {
  readonly allowed_http_hosts: readonly PolicyEntry[];
  readonly allowed_commands: readonly CommandPolicy[];
  readonly allowed_env_vars: readonly PolicyEntry[];
  readonly rate_limit: {
    readonly requests: number;
    readonly window_seconds: number;
  };
}

export interface PolicySchemaOptions {
  readonly strictMode: boolean;
}

export function makePolicySchema(
  options: PolicySchemaOptions,
): ZodType<Policy> {
  const hostEntrySchema = makeEntrySchema({
    strictMode: options.strictMode,
    dimension: "allowed_http_hosts",
    classify: classifyHost,
  });
  const binarySchema = makeEntrySchema({
    strictMode: options.strictMode,
    dimension: "allowed_commands[].binary",
    classify: classifyBinary,
  });
  const envSchema = makeEntrySchema({
    strictMode: options.strictMode,
    dimension: "allowed_env_vars",
    classify: classifyEnvVar,
  });

  const commandSchema = z.object({
    binary: binarySchema,
    allowed_args_patterns: z.array(argPatternSchema),
    forbidden_args_patterns: z.array(argPatternSchema).optional(),
  });

  return z
    .object({
      allowed_http_hosts: z.array(hostEntrySchema),
      allowed_commands: z.array(commandSchema),
      allowed_env_vars: z.array(envSchema),
      rate_limit: rateLimitSchema,
    })
    .strict() as unknown as ZodType<Policy>;
}

/**
 * Back-compat non-strict schema. Accepts wildcard entries and decorates
 * them with `{wildcard, wildcard_kind}`. The vault's stored `strict_mode`
 * gates the strict-mode rejection path; callers that operate on already-
 * validated in-memory policies (enforce.ts, audit wiring) go through this
 * schema via the Policy type.
 */
export const policySchema: ZodType<Policy> = makePolicySchema({
  strictMode: false,
});

export function validatePolicy(
  input: unknown,
  options: PolicySchemaOptions = { strictMode: false },
): Policy | ZodError {
  const schema = makePolicySchema(options);
  const result = schema.safeParse(input);
  if (result.success) {
    return result.data;
  }
  return result.error;
}
