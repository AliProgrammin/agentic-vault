// CLI formatter for the F13 audit detail view. Consumes `RenderModel` from
// `render.ts` so CLI and UI cannot drift.
//
// TTY-aware: when `tty` is false, all ANSI escape sequences are stripped so
// piping to `less` or a file yields clean ASCII. When `tty` is true, key
// spans are highlighted (ANSI 16-color only — no truecolor, so it works on
// every terminal).
//
// Redaction markers are rendered both as text (`[REDACTED:NAME]`, preserved
// from the scrubber) AND with an inverse-video run when colored, so the
// distinction is conveyable without color.

import type { AuditHeader } from "./types.js";
import type {
  RenderBodySection,
  RenderCommandRequestView,
  RenderCommandResponseView,
  RenderHttpRequestView,
  RenderHttpResponseView,
  RenderModel,
  RenderStage,
} from "./render.js";
import {
  isBinaryArtifact,
  isTextArtifact,
} from "./body-artifact.js";

const ESC = "\x1b[";
const RESET = `${ESC}0m`;
const BOLD = `${ESC}1m`;
const DIM = `${ESC}2m`;
const INVERSE = `${ESC}7m`;
const FG_CYAN = `${ESC}36m`;
const FG_GREEN = `${ESC}32m`;
const FG_YELLOW = `${ESC}33m`;
const FG_RED = `${ESC}31m`;
const FG_MAGENTA = `${ESC}35m`;
const FG_GRAY = `${ESC}90m`;

// Strip any ANSI if the caller does not pass tty=true.
const ANSI_STRIP = /\x1b\[[0-9;]*m/g;

export interface CliRenderOptions {
  readonly tty: boolean;
  readonly width?: number;
}

export function formatAuditDetail(
  model: RenderModel,
  opts: CliRenderOptions,
): string {
  const out: string[] = [];
  const color = opts.tty;
  const section = (title: string, body: string): void => {
    out.push(colorize(`━━ ${title} ━━`, BOLD, color));
    out.push(body);
    out.push("");
  };

  section("Summary", renderSummary(model, color));
  section("Timeline", renderTimeline(model.timeline.stages, color));
  if (model.rate_limit !== undefined) {
    section(
      "Rate limit",
      `${String(model.rate_limit.remaining)} / ${String(model.rate_limit.capacity)} tokens (window ${String(model.rate_limit.window_seconds)}s)`,
    );
  }
  section("Injected secrets", renderInjected(model, color));
  section(
    "Policy",
    `outcome: ${model.outcome}${model.code !== undefined ? ` (${model.code})` : ""}${model.reason !== undefined ? `\nreason: ${model.reason}` : ""}`,
  );
  section("Request", renderRequestBlock(model, color));
  section("Response", renderResponseBlock(model, color));
  section("Process", renderProcess(model));

  const final = out.join("\n");
  return color ? final : final.replace(ANSI_STRIP, "");
}

function colorize(text: string, code: string, enabled: boolean): string {
  return enabled ? `${code}${text}${RESET}` : text;
}

function renderSummary(model: RenderModel, color: boolean): string {
  const outcomeTag = model.outcome === "allowed"
    ? colorize(model.outcome.toUpperCase(), FG_GREEN + BOLD, color)
    : colorize(model.outcome.toUpperCase(), FG_RED + BOLD, color);
  const lines: string[] = [];
  lines.push(`id:      ${model.id}`);
  lines.push(`ts:      ${model.ts}`);
  lines.push(`surface: ${model.surface}`);
  lines.push(`tool:    ${model.surface === "mcp_http_request" ? "http_request" : model.surface === "mcp_run_command" ? "run_command" : "cli"}`);
  lines.push(`secret:  ${model.secret_name}`);
  lines.push(`target:  ${model.target}`);
  lines.push(`outcome: ${outcomeTag}${model.code !== undefined ? ` [${model.code}]` : ""}`);
  if (model.reason !== undefined) {
    lines.push(`reason:  ${model.reason}`);
  }
  return lines.join("\n");
}

function renderTimeline(stages: readonly RenderStage[], color: boolean): string {
  if (stages.length === 0) {
    return colorize("(no timing captured)", FG_GRAY, color);
  }
  const lines: string[] = [];
  for (const s of stages) {
    const delta = s.delta_ms !== undefined
      ? ` ${colorize(`(+${String(s.delta_ms)}ms)`, FG_GRAY, color)}`
      : "";
    lines.push(`• ${colorize(s.name, FG_CYAN, color)}  ${s.ts ?? "?"}${delta}`);
  }
  return lines.join("\n");
}

function renderInjected(model: RenderModel, color: boolean): string {
  if (model.injected_secrets.length === 0) {
    return colorize("(none)", FG_GRAY, color);
  }
  return model.injected_secrets
    .map(
      (s) =>
        `• ${colorize(s.secret_name, FG_MAGENTA, color)} (scope: ${s.scope}, target: ${s.target})`,
    )
    .join("\n");
}

function renderProcess(model: RenderModel): string {
  const lines: string[] = [];
  if (model.process.pid !== undefined) lines.push(`pid:  ${String(model.process.pid)}`);
  lines.push(`cwd:  ${model.process.cwd}`);
  if (model.process.argv !== undefined) {
    lines.push(`argv: ${JSON.stringify(model.process.argv)}`);
  }
  if (model.process.tool_name !== undefined) {
    lines.push(`tool: ${model.process.tool_name}`);
  }
  return lines.join("\n");
}

function renderRequestBlock(model: RenderModel, color: boolean): string {
  const r = model.request;
  if (r.kind === "none") {
    return colorize("(not captured in this record)", FG_GRAY, color);
  }
  if (r.kind === "http") return renderHttpRequestView(r.view, color);
  return renderCommandRequestView(r.view, color);
}

function renderResponseBlock(model: RenderModel, color: boolean): string {
  const r = model.response;
  if (r.kind === "none") {
    return colorize("(not captured in this record)", FG_GRAY, color);
  }
  if (r.kind === "http") return renderHttpResponseView(r.view, color);
  return renderCommandResponseView(r.view, color);
}

function renderHttpRequestView(
  view: RenderHttpRequestView,
  color: boolean,
): string {
  const lines: string[] = [];
  const method = view.method ?? "?";
  const url = view.url ?? "?";
  lines.push(`${colorize(method, BOLD, color)} ${url}`);
  lines.push(renderHeaders(view.headers, color));
  lines.push("");
  lines.push(colorize("body:", BOLD, color));
  lines.push(renderBody(view.body, color));
  if (view.status === "not_captured") {
    lines.push(colorize("(headers not captured in this record)", FG_GRAY, color));
  }
  return lines.join("\n");
}

function renderCommandRequestView(
  view: RenderCommandRequestView,
  color: boolean,
): string {
  const lines: string[] = [];
  lines.push(`${colorize("binary:", BOLD, color)} ${view.binary ?? "?"}`);
  lines.push(`${colorize("args:  ", BOLD, color)} ${JSON.stringify(view.args)}`);
  if (view.cwd !== undefined) {
    lines.push(`${colorize("cwd:   ", BOLD, color)} ${view.cwd}`);
  }
  lines.push(`${colorize("env:   ", BOLD, color)} ${JSON.stringify(view.env_keys)}`);
  if (view.status === "not_captured") {
    lines.push(colorize("(captured from legacy fields; env_keys unavailable)", FG_GRAY, color));
  }
  return lines.join("\n");
}

function renderHttpResponseView(
  view: RenderHttpResponseView,
  color: boolean,
): string {
  const lines: string[] = [];
  lines.push(`${colorize("status:", BOLD, color)} ${String(view.status_code ?? "?")}`);
  lines.push(renderHeaders(view.headers, color));
  lines.push("");
  lines.push(colorize("body:", BOLD, color));
  lines.push(renderBody(view.body, color));
  if (view.status === "not_captured") {
    lines.push(colorize("(headers not captured in this record)", FG_GRAY, color));
  }
  return lines.join("\n");
}

function renderCommandResponseView(
  view: RenderCommandResponseView,
  color: boolean,
): string {
  const lines: string[] = [];
  lines.push(`${colorize("exit:", BOLD, color)} ${String(view.exit_code ?? "?")}`);
  lines.push("");
  lines.push(colorize("stdout:", BOLD, color));
  lines.push(renderBody(view.stdout, color));
  lines.push("");
  lines.push(colorize("stderr:", BOLD, color));
  lines.push(renderBody(view.stderr, color));
  return lines.join("\n");
}

function renderHeaders(hs: readonly AuditHeader[], color: boolean): string {
  if (hs.length === 0) {
    return colorize("(no headers)", FG_GRAY, color);
  }
  const lines: string[] = [];
  for (const h of hs) {
    const badge = h.scrubbed ? ` ${colorize("[SCRUBBED]", INVERSE + FG_YELLOW, color)}` : "";
    lines.push(`  ${h.name}: ${h.value}${badge}`);
  }
  return lines.join("\n");
}

function renderBody(section: RenderBodySection, color: boolean): string {
  if (section.status === "not_captured") {
    return colorize("(not captured in this record)", FG_GRAY, color);
  }
  if (section.status === "pruned") {
    return colorize(
      "(body pruned — metadata retained, contents removed per retention policy)",
      FG_GRAY,
      color,
    );
  }
  if (section.status === "decrypt_failed") {
    return colorize(
      `(decryption failed: ${section.error ?? "authenticated-decrypt error"})`,
      FG_RED,
      color,
    );
  }
  const a = section.artifact;
  if (a === undefined) return colorize("(empty)", FG_GRAY, color);
  if (a.kind === "empty") return colorize("(empty body)", FG_GRAY, color);
  if (isBinaryArtifact(a)) {
    const line = `<binary, ${String(a.bytes)} bytes, sha256:${a.sha256}>`;
    return colorize(line, DIM, color);
  }
  if (isTextArtifact(a)) {
    const body = highlightRedactions(a.text, color);
    const suffix = a.truncated
      ? `\n${colorize(`[truncated: ${String(a.truncated_bytes)} bytes elided]`, FG_YELLOW + BOLD, color)}`
      : "";
    return body + suffix;
  }
  return "";
}

function highlightRedactions(text: string, color: boolean): string {
  if (!color) return text;
  return text.replace(
    /\[REDACTED:[^\]]+\]/g,
    (m) => `${INVERSE}${FG_YELLOW}${m}${RESET}`,
  );
}

export function hexDump(bytes: Uint8Array, cap: number = 256): string {
  const lines: string[] = [];
  const end = Math.min(bytes.byteLength, cap);
  for (let offset = 0; offset < end; offset += 16) {
    const slice = bytes.subarray(offset, Math.min(offset + 16, end));
    const hex = Array.from(slice)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
    const ascii = Array.from(slice)
      .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."))
      .join("");
    lines.push(`${offset.toString(16).padStart(8, "0")}  ${hex.padEnd(47, " ")}  ${ascii}`);
  }
  if (bytes.byteLength > cap) {
    lines.push(`... (${String(bytes.byteLength - cap)} more bytes)`);
  }
  return lines.join("\n");
}
