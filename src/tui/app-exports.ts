import {
  buildRenderModel,
  type AuditEvent,
  type BuildRenderOptions,
  type RenderModel,
} from "../audit/index.js";
import {
  isWildcardEntry,
  wildcardBadge,
  type Policy,
  type PolicyEntry,
} from "../policy/index.js";

function collectWildcardKinds(entries: readonly PolicyEntry[]): readonly string[] {
  const tokens = new Set<string>();
  for (const entry of entries) {
    if (isWildcardEntry(entry)) {
      tokens.add(wildcardBadge(entry.wildcard_kind, { tty: false }));
    }
  }
  return [...tokens];
}

export function policyBadgeTokens(policy: Policy | undefined): readonly string[] {
  if (policy === undefined) {
    return [];
  }
  const tokens = new Set<string>();
  for (const token of collectWildcardKinds(policy.allowed_http_hosts)) tokens.add(token);
  for (const command of policy.allowed_commands) {
    for (const token of collectWildcardKinds([command.binary])) tokens.add(token);
  }
  for (const token of collectWildcardKinds(policy.allowed_env_vars)) tokens.add(token);
  return [...tokens];
}

export function hasWildcardPolicy(policy: Policy | undefined): boolean {
  return policyBadgeTokens(policy).length > 0;
}

export function buildAuditDetailModelForTui(
  event: AuditEvent,
  opts: BuildRenderOptions = {},
): RenderModel {
  return buildRenderModel(event, opts);
}
