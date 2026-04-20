import { describe, it, expect } from "vitest";
import {
  DEFAULT_RESPONSE_BODY_CAP_BYTES,
  TRUNCATION_MARKER_PREFIX,
  classifyBody,
  classifyText,
  isBinaryArtifact,
  isTextArtifact,
} from "./body-artifact.js";

describe("classifyBody", () => {
  it("empty bytes yield an empty artifact", () => {
    const a = classifyBody(new Uint8Array(0));
    expect(a.kind).toBe("empty");
  });

  it("short UTF-8 bytes yield a text artifact under the cap", () => {
    const bytes = new TextEncoder().encode("hello world");
    const a = classifyBody(bytes, { cap: 64 });
    expect(isTextArtifact(a)).toBe(true);
    if (isTextArtifact(a)) {
      expect(a.text).toBe("hello world");
      expect(a.truncated).toBe(false);
      expect(a.original_bytes).toBe(bytes.byteLength);
    }
  });

  it("binary content-type forces a binary placeholder regardless of bytes", () => {
    const bytes = new TextEncoder().encode("this is printable text");
    const a = classifyBody(bytes, { contentType: "application/octet-stream" });
    expect(isBinaryArtifact(a)).toBe(true);
    if (isBinaryArtifact(a)) {
      expect(a.bytes).toBe(bytes.byteLength);
      expect(a.sha256).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("non-UTF-8 bytes fall back to a binary placeholder", () => {
    const bytes = new Uint8Array([0xff, 0xfe, 0xff, 0xfe, 0x00]);
    const a = classifyBody(bytes);
    expect(isBinaryArtifact(a)).toBe(true);
  });

  it("oversized text is truncated with an explicit marker and elided-byte count", () => {
    const payload = "a".repeat(DEFAULT_RESPONSE_BODY_CAP_BYTES + 512);
    const bytes = new TextEncoder().encode(payload);
    const a = classifyBody(bytes);
    expect(isTextArtifact(a)).toBe(true);
    if (isTextArtifact(a)) {
      expect(a.truncated).toBe(true);
      expect(a.truncated_bytes).toBe(512);
      expect(a.text.endsWith(`${TRUNCATION_MARKER_PREFIX}512 more bytes>`)).toBe(true);
      expect(a.original_bytes).toBe(bytes.byteLength);
    }
  });

  it("truncation respects UTF-8 boundaries (never splits a codepoint)", () => {
    // Repeat a 3-byte character so the cap likely lands mid-codepoint.
    const glyph = "€"; // 3 bytes in UTF-8
    const payload = glyph.repeat(100);
    const bytes = new TextEncoder().encode(payload);
    const cap = 7; // odd cap that lands mid-codepoint
    const a = classifyBody(bytes, { cap });
    expect(isTextArtifact(a)).toBe(true);
    if (isTextArtifact(a)) {
      // All complete codepoints must decode cleanly.
      const body = a.text.replace(/<truncated: \d+ more bytes>$/, "");
      expect([...body].every((ch) => ch === glyph)).toBe(true);
    }
  });
});

describe("classifyText", () => {
  it("empty string → empty artifact", () => {
    const a = classifyText("");
    expect(a.kind).toBe("empty");
  });
  it("cap applies and annotates truncation", () => {
    const a = classifyText("hello world, this is longer than the cap", { cap: 4 });
    expect(isTextArtifact(a)).toBe(true);
    if (isTextArtifact(a)) {
      expect(a.truncated).toBe(true);
      expect(a.text).toContain(TRUNCATION_MARKER_PREFIX);
    }
  });
});
