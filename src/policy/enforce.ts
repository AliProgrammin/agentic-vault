import type { CommandPolicy, Policy } from "./schema.js";

export type Decision = { allowed: true } | { allowed: false; reason: string };

const PATH_SEPARATOR_PATTERN = /[/\\]/;

function deny(reason: string): Decision {
  return { allowed: false, reason };
}

const ALLOW: Decision = { allowed: true };

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
  for (const allowed of policy.allowed_http_hosts) {
    if (allowed.toLowerCase() === requestHost) {
      return ALLOW;
    }
  }
  return deny(`host '${parsed.hostname}' is not in the allowed HTTP host list`);
}

// Binary equality is case-sensitive. Rationale: on case-insensitive filesystems
// (default macOS, Windows) 'RM' would execute 'rm'. Case-sensitive comparison
// denies any case-variant that isn't exactly in the allowlist, refusing the
// implicit-rename attack rather than silently treating 'RM' as allowlisted 'rm'.
function matchesBinary(policyEntry: string, requested: string): boolean {
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

function findCommandEntry(
  policy: Policy,
  binary: string,
): CommandPolicy | undefined {
  for (const entry of policy.allowed_commands) {
    if (matchesBinary(entry.binary, binary)) {
      return entry;
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

  const entry = findCommandEntry(policy, binary);
  if (!entry) {
    return deny(`binary '${binary}' is not in the allowed command list`);
  }

  const allowedPatterns = entry.allowed_args_patterns.map((p) => new RegExp(p));
  const forbiddenPatterns = (entry.forbidden_args_patterns ?? []).map(
    (p) => new RegExp(p),
  );

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === undefined) {
      return deny(`argument at position ${String(i)} is missing`);
    }
    for (const forbidden of forbiddenPatterns) {
      if (forbidden.test(arg)) {
        return deny(
          `argument '${arg}' matches a forbidden pattern for '${entry.binary}'`,
        );
      }
    }
    let matched = false;
    for (const allowed of allowedPatterns) {
      if (allowed.test(arg)) {
        matched = true;
        break;
      }
    }
    if (!matched) {
      return deny(
        `argument '${arg}' does not match any allowed pattern for '${entry.binary}'`,
      );
    }
  }

  return ALLOW;
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
  if (!policy.allowed_env_vars.includes(envVarName)) {
    return deny(`env var '${envVarName}' is not in the allowed env var list`);
  }
  return ALLOW;
}
