// Shared badge renderer for wildcarded policy entries.
//
// Single source of truth for every surface that displays a wildcard risk tag:
// - CLI `policy show` / `policy set` confirmation preview
// - CLI `audit show` / `audit list`
// - Future TUI (F15) — imports from THIS file, does not re-implement
//
// Pipe-mode (non-TTY) output is plain ASCII — bracket tokens are spelled
// exactly `[UNRESTRICTED]` and `[RISKY]` so scripts can grep for them. TTY
// output adds ANSI inverse-video with a red (unrestricted) or yellow
// (risky) foreground so operators cannot miss them.
//
// The compact variants (`[!]` / `[R]`) are used by `audit list` so a single
// grep-friendly glyph appears next to rows whose record has a
// `wildcard_matched` field.
//
// A dedicated test asserts both CLI and any other future caller pulling
// the same record through `wildcardBadge()` gets the same exact token.

import type { WildcardKind } from "./schema.js";

const ESC = "\x1b[";
const RESET = `${ESC}0m`;
const INVERSE = `${ESC}7m`;
const FG_RED = `${ESC}31m`;
const FG_YELLOW = `${ESC}33m`;
const BOLD = `${ESC}1m`;

export const BADGE_UNRESTRICTED = "[UNRESTRICTED]";
export const BADGE_RISKY = "[RISKY]";
export const COMPACT_UNRESTRICTED = "[!]";
export const COMPACT_RISKY = "[R]";

export interface BadgeRenderOptions {
  readonly tty: boolean;
}

/**
 * Full bracket-tag badge for an entry of the given wildcard kind.
 * Always returns the literal bracket token; TTY mode wraps it in ANSI.
 */
export function wildcardBadge(
  kind: WildcardKind,
  opts: BadgeRenderOptions,
): string {
  if (kind === "unrestricted") {
    return opts.tty
      ? `${INVERSE}${FG_RED}${BOLD}${BADGE_UNRESTRICTED}${RESET}`
      : BADGE_UNRESTRICTED;
  }
  // subdomain / affix both render as [RISKY]
  return opts.tty
    ? `${INVERSE}${FG_YELLOW}${BOLD}${BADGE_RISKY}${RESET}`
    : BADGE_RISKY;
}

/**
 * Compact badge used in row-dense views (e.g. `audit list`). Still spelled
 * with ASCII brackets so grep works in pipe mode. TTY mode adds the same
 * inverse-video color as the full badge.
 */
export function wildcardBadgeCompact(
  kind: WildcardKind,
  opts: BadgeRenderOptions,
): string {
  if (kind === "unrestricted") {
    return opts.tty
      ? `${INVERSE}${FG_RED}${BOLD}${COMPACT_UNRESTRICTED}${RESET}`
      : COMPACT_UNRESTRICTED;
  }
  return opts.tty
    ? `${INVERSE}${FG_YELLOW}${BOLD}${COMPACT_RISKY}${RESET}`
    : COMPACT_RISKY;
}
