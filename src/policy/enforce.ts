import {
  entryValue,
  isWildcardEntry,
  type CommandPolicy,
  type Policy,
  type PolicyEntry,
  type WildcardKind,
} from "./schema.js";

export interface WildcardMatch {
  readonly pattern: string;
  readonly kind: WildcardKind;
}

export type Decision =
  | { allowed: true; wildcard_matched?: WildcardMatch }
  | { allowed: false; reason: string };

const PATH_SEPARATOR_PATTERN = /[/\\]/;

function deny(reason: string): Decision {
  return { allowed: false, reason };
}

const ALLOW: Decision = { allowed: true };

function allowWithWildcard(entry: PolicyEntry): Decision {
  if (isWildcardEntry(entry)) {
    return {
      allowed: true,
      wildcard_matched: { pattern: entry.value, kind: entry.wildcard_kind },
    };
  }
  return ALLOW;
}

// ── Host matching ────────────────────────────────────────────────────────

function hostMatches(entry: PolicyEntry, requestHost: string): boolean {
  if (isWildcardEntry(entry)) {
    if (entry.wildcard_kind === "unrestricted") return true;
    if (entry.wildcard_kind === "subdomain") {
      // `*.example.com` matches any strict subdomain, NOT the apex.
      const suffix = entry.value.slice(1).toLowerCase(); // '.example.com'
      // Apex ("example.com") must not match a subdomain wildcard.
      const bare = suffix.slice(1); // 'example.com'
      if (requestHost === bare) return false;
      return requestHost.endsWith(suffix);
    }
    // affix does not apply to hosts per the brief.
    return false;
  }
  return entry.toLowerCase() === requestHost;
}

export function checkHttp(policy: Policy | undefined, url: string): Decision {
  if (!policy) {
    return deny("no policy attached to secret (deny-by-default)");
  }
  if (policy.allowed_http_hosts.length === 0) {
    return deny("policy allows no HTTP hosts");
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return deny("URL could not be parsed");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return deny(`scheme '${parsed.protocol.replace(/:$/, "")}' is not http or https`);
  }

  const requestHost = parsed.hostname.toLowerCase();

  // Consider every entry; if any matches we allow. Exact matches are
  // preferred over wildcard matches for audit attribution — the brief
  // specifies that an exact match MUST NOT produce a `wildcard_matched`
  // field. Walk exact entries first, then wildcards.
  for (const entry of policy.allowed_http_hosts) {
    if (!isWildcardEntry(entry) && hostMatches(entry, requestHost)) {
      return ALLOW;
    }
  }
  for (const entry of policy.allowed_http_hosts) {
    if (isWildcardEntry(entry) && hostMatches(entry, requestHost)) {
      return allowWithWildcard(entry);
    }
  }
  return deny(`host '${parsed.hostname}' is not in the allowed HTTP host list`);
}

// ── Command matching ─────────────────────────────────────────────────────

// Binary equality is case-sensitive. Rationale: on case-insensitive filesystems
// (default macOS, Windows) 'RM' would execute 'rm'. Case-sensitive comparison
// denies any case-variant that isn't exactly in the allowlist, refusing the
// implicit-rename attack rather than silently treating 'RM' as allowlisted 'rm'.
function matchesBinaryExact(policyEntry: string, requested: string): boolean {
  if (policyEntry !== requested) {
    return false;
  }
  const requestedHasSep = PATH_SEPARATOR_PATTERN.test(requested);
  const policyHasSep = PATH_SEPARATOR_PATTERN.test(policyEntry);
  if (requestedHasSep && !policyHasSep) {
    return false;
  }
  return true;
}

function matchesBinaryWildcard(
  entry: { value: string; wildcard_kind: WildcardKind },
  requested: string,
): boolean {
  if (entry.wildcard_kind === "unrestricted") {
    return true;
  }
  if (entry.wildcard_kind !== "affix") {
    return false;
  }
  const pat = entry.value;
  // prefix-*
  if (pat.endsWith("*")) {
    const prefix = pat.slice(0, -1);
    if (!requested.startsWith(prefix)) return false;
    const span = requested.slice(prefix.length);
    // Forbid '/' or '.' in the wildcard-covered span for binaries.
    if (span.includes("/") || span.includes("\\") || span.includes(".")) {
      return false;
    }
    return span.length > 0;
  }
  // *-suffix
  if (pat.startsWith("*")) {
    const suffix = pat.slice(1);
    if (!requested.endsWith(suffix)) return false;
    const span = requested.slice(0, requested.length - suffix.length);
    if (span.includes("/") || span.includes("\\") || span.includes(".")) {
      return false;
    }
    return span.length > 0;
  }
  return false;
}

function findCommandEntry(
  policy: Policy,
  binary: string,
): { entry: CommandPolicy; matchedBy: PolicyEntry } | undefined {
  // Exact first, then wildcard.
  for (const entry of policy.allowed_commands) {
    if (!isWildcardEntry(entry.binary) && matchesBinaryExact(entry.binary, binary)) {
      return { entry, matchedBy: entry.binary };
    }
  }
  for (const entry of policy.allowed_commands) {
    if (isWildcardEntry(entry.binary)) {
      if (matchesBinaryWildcard(entry.binary, binary)) {
        return { entry, matchedBy: entry.binary };
      }
    }
  }
  return undefined;
}

export function checkCommand(
  policy: Policy | undefined,
  binary: string,
  args: readonly string[],
): Decision {
  if (!policy) {
    return deny("no policy attached to secret (deny-by-default)");
  }
  if (policy.allowed_commands.length === 0) {
    return deny("policy allows no commands");
  }

  const matched = findCommandEntry(policy, binary);
  if (!matched) {
    return deny(`binary '${binary}' is not in the allowed command list`);
  }
  const entry = matched.entry;

  const allowedPatterns = entry.allowed_args_patterns.map((p) => new RegExp(p));
  const forbiddenPatterns = (entry.forbidden_args_patterns ?? []).map(
    (p) => new RegExp(p),
  );

  const binaryLabel = entryValue(entry.binary);
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === undefined) {
      return deny(`argument at position ${String(i)} is missing`);
    }
    for (const forbidden of forbiddenPatterns) {
      if (forbidden.test(arg)) {
        return deny(
          `argument '${arg}' matches a forbidden pattern for '${binaryLabel}'`,
        );
      }
    }
    let matchedArg = false;
    for (const allowed of allowedPatterns) {
      if (allowed.test(arg)) {
        matchedArg = true;
        break;
      }
    }
    if (!matchedArg) {
      return deny(
        `argument '${arg}' does not match any allowed pattern for '${binaryLabel}'`,
      );
    }
  }

  return allowWithWildcard(matched.matchedBy);
}

// ── Env var matching ─────────────────────────────────────────────────────

function envMatches(entry: PolicyEntry, requested: string): boolean {
  if (isWildcardEntry(entry)) {
    if (entry.wildcard_kind === "unrestricted") return true;
    if (entry.wildcard_kind !== "affix") return false;
    const pat = entry.value;
    if (pat.endsWith("*")) {
      const prefix = pat.slice(0, -1);
      if (!requested.startsWith(prefix)) return false;
      const span = requested.slice(prefix.length);
      return span.length > 0 && /^[A-Z0-9_]+$/.test(span);
    }
    if (pat.startsWith("*")) {
      const suffix = pat.slice(1);
      if (!requested.endsWith(suffix)) return false;
      const span = requested.slice(0, requested.length - suffix.length);
      return span.length > 0 && /^[A-Z_][A-Z0-9_]*$/.test(span);
    }
    return false;
  }
  return entry === requested;
}

export function checkEnvInjection(
  policy: Policy | undefined,
  envVarName: string,
): Decision {
  if (!policy) {
    return deny("no policy attached to secret (deny-by-default)");
  }
  if (policy.allowed_env_vars.length === 0) {
    return deny("policy allows no env var injection targets");
  }
  for (const entry of policy.allowed_env_vars) {
    if (!isWildcardEntry(entry) && envMatches(entry, envVarName)) {
      return ALLOW;
    }
  }
  for (const entry of policy.allowed_env_vars) {
    if (isWildcardEntry(entry) && envMatches(entry, envVarName)) {
      return allowWithWildcard(entry);
    }
  }
  return deny(`env var '${envVarName}' is not in the allowed env var list`);
}
