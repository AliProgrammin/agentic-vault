import { isValidSecretName } from "../vault/index.js";

export interface BulkImportEntry {
  readonly line: number;
  readonly name: string;
  readonly value: string;
}

export interface BulkImportSkip {
  readonly line: number;
  readonly reason: string;
}

export interface BulkImportPreview {
  readonly added: readonly BulkImportEntry[];
  readonly skipped: readonly BulkImportSkip[];
}

function parseQuotedValue(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed.startsWith('"')) {
    return null;
  }
  if (!trimmed.endsWith('"') || trimmed.length < 2) {
    return null;
  }
  return trimmed.slice(1, -1);
}

function parseLine(raw: string, line: number): BulkImportEntry | BulkImportSkip | null {
  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed.startsWith("#")) {
    return null;
  }
  const eq = raw.indexOf("=");
  if (eq <= 0) {
    return { line, reason: "expected KEY=value" };
  }
  const name = raw.slice(0, eq).trim();
  if (!isValidSecretName(name)) {
    return { line, reason: "invalid secret name" };
  }
  const rawValue = raw.slice(eq + 1);
  const quoted = parseQuotedValue(rawValue);
  if (rawValue.trimStart().startsWith('"') && quoted === null) {
    return { line, reason: "unterminated quoted value" };
  }
  return {
    line,
    name,
    value: (quoted ?? rawValue).replace(/[\r\n]+$/u, ""),
  };
}

export function parseBulkSecretInput(raw: string): BulkImportPreview {
  const added: BulkImportEntry[] = [];
  const skipped: BulkImportSkip[] = [];
  const lines = raw.split(/\r?\n/u);
  for (const [index, line] of lines.entries()) {
    const parsed = parseLine(line, index + 1);
    if (parsed === null) {
      continue;
    }
    if ("name" in parsed) {
      added.push(parsed);
    } else {
      skipped.push(parsed);
    }
  }
  return { added, skipped };
}
