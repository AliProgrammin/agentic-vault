// Body artifact normalization for the F13 audit detail view.
//
// Responsibilities:
//   - UTF-8 / binary classification (UTF-8 validation + content-type heuristic)
//   - Size capping with an explicit truncation marker for text bodies
//   - Placeholder construction for binary bodies ({ kind, bytes, sha256 })
//
// All I/O-free and deterministic; the body-blob store composes these pieces.

import { createHash } from "node:crypto";

export const DEFAULT_REQUEST_BODY_CAP_BYTES = 64 * 1024;
export const DEFAULT_RESPONSE_BODY_CAP_BYTES = 256 * 1024;
export const TRUNCATION_MARKER_PREFIX = "<truncated: ";

export interface TextBodyArtifact {
  readonly kind: "text";
  readonly text: string;
  readonly original_bytes: number;
  readonly truncated: boolean;
  readonly truncated_bytes: number;
}

export interface BinaryBodyArtifact {
  readonly kind: "binary";
  readonly bytes: number;
  readonly sha256: string;
}

export interface EmptyBodyArtifact {
  readonly kind: "empty";
}

export type BodyArtifact = TextBodyArtifact | BinaryBodyArtifact | EmptyBodyArtifact;

export interface ClassifyOptions {
  /** Cap for text bodies. Binary bodies always collapse to the placeholder. */
  readonly cap?: number;
  /** Optional content-type header for binary detection. */
  readonly contentType?: string;
}

const BINARY_CONTENT_TYPE_PREFIXES = [
  "image/",
  "audio/",
  "video/",
  "application/octet-stream",
  "application/pdf",
  "application/zip",
  "application/gzip",
  "application/x-tar",
  "application/vnd.ms-",
  "application/msword",
  "font/",
];

function contentTypeIndicatesBinary(contentType?: string): boolean {
  if (contentType === undefined) return false;
  const lower = contentType.toLowerCase();
  for (const prefix of BINARY_CONTENT_TYPE_PREFIXES) {
    if (lower.startsWith(prefix)) return true;
  }
  return false;
}

function looksLikeUtf8(bytes: Uint8Array): boolean {
  try {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    decoder.decode(bytes);
    return true;
  } catch {
    return false;
  }
}

function sha256Hex(bytes: Uint8Array): string {
  const h = createHash("sha256");
  h.update(bytes);
  return h.digest("hex");
}

/**
 * Classify raw body bytes as text / binary / empty and cap text bodies at
 * `cap` bytes. Binary bodies are represented only by size + sha256; the raw
 * bytes are NOT returned (and are not stored by the body-blob store).
 */
export function classifyBody(
  bytes: Uint8Array,
  opts: ClassifyOptions = {},
): BodyArtifact {
  if (bytes.byteLength === 0) {
    return { kind: "empty" };
  }
  if (contentTypeIndicatesBinary(opts.contentType) || !looksLikeUtf8(bytes)) {
    return {
      kind: "binary",
      bytes: bytes.byteLength,
      sha256: sha256Hex(bytes),
    };
  }
  const cap = opts.cap ?? DEFAULT_RESPONSE_BODY_CAP_BYTES;
  if (bytes.byteLength <= cap) {
    const text = new TextDecoder("utf-8").decode(bytes);
    return {
      kind: "text",
      text,
      original_bytes: bytes.byteLength,
      truncated: false,
      truncated_bytes: 0,
    };
  }
  // UTF-8-safe slicing: walk back from `cap` until we land on a boundary so
  // we never split a multi-byte codepoint. Longest UTF-8 sequence is 4 bytes.
  let end = cap;
  for (let back = 0; back < 4 && end > 0; back++) {
    const b = bytes[end];
    if (b === undefined) break;
    if ((b & 0xc0) !== 0x80) break; // current byte is NOT a continuation
    end -= 1;
  }
  const slice = bytes.subarray(0, end);
  const text = new TextDecoder("utf-8").decode(slice);
  const elided = bytes.byteLength - end;
  const marker = `${TRUNCATION_MARKER_PREFIX}${String(elided)} more bytes>`;
  return {
    kind: "text",
    text: text + marker,
    original_bytes: bytes.byteLength,
    truncated: true,
    truncated_bytes: elided,
  };
}

/**
 * Classify a string as a (text) body artifact. Used for inputs that are
 * already UTF-8 strings (e.g. a pre-built JSON request body).
 */
export function classifyText(
  raw: string,
  opts: Omit<ClassifyOptions, "contentType"> = {},
): BodyArtifact {
  if (raw.length === 0) {
    return { kind: "empty" };
  }
  const bytes = Buffer.from(raw, "utf8");
  return classifyBody(bytes, opts);
}

export function isTextArtifact(a: BodyArtifact): a is TextBodyArtifact {
  return a.kind === "text";
}

export function isBinaryArtifact(a: BodyArtifact): a is BinaryBodyArtifact {
  return a.kind === "binary";
}
