// Output scrubbing: defense-in-depth for accidental leakage — not an anti-exfiltration control.
// The real anti-exfiltration boundary is the policy layer. This module exists only to catch
// literal, accidental echoing of secret values through subprocess output or HTTP response bodies
// before they are returned to the calling agent.

export interface ScrubbableSecret {
  readonly name: string;
  readonly value: string;
}

/**
 * Replace every literal occurrence of each secret's `value` in `text` with `[REDACTED:${name}]`.
 *
 * This is defense-in-depth for accidental leakage — not an anti-exfiltration control.
 *
 * Replacement order is longest-value-first so that a shorter secret cannot accidentally
 * match inside a longer secret's bytes. The function uses plain string `split`/`join` and
 * never derives a regex from a secret value, which keeps it binary-safe for arbitrary
 * UTF-8 input (including emojis) and avoids any regex-escaping pitfalls.
 *
 * The function is pure: it does not mutate `text` or `secretsInScope`. An empty
 * `secretsInScope` returns `text` unchanged.
 */
export function scrub(text: string, secretsInScope: readonly ScrubbableSecret[]): string {
  if (secretsInScope.length === 0) {
    return text;
  }

  const sorted = [...secretsInScope]
    .filter((s) => s.value.length > 0)
    .sort((a, b) => b.value.length - a.value.length);

  let result = text;
  for (const { name, value } of sorted) {
    if (result.indexOf(value) === -1) {
      continue;
    }
    result = result.split(value).join(`[REDACTED:${name}]`);
  }
  return result;
}
