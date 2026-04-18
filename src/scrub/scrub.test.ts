import { describe, it, expect } from "vitest";
import { scrub } from "./scrub.js";

describe("scrub — defense-in-depth for accidental leakage — not an anti-exfiltration control", () => {
  it("replaces a single literal secret value with [REDACTED:NAME]", () => {
    expect(scrub("token=abcd", [{ name: "API", value: "abcd" }])).toBe(
      "token=[REDACTED:API]",
    );
  });

  it("replaces every occurrence of the same secret value", () => {
    expect(scrub("a=abcd b=abcd c=abcd", [{ name: "K", value: "abcd" }])).toBe(
      "a=[REDACTED:K] b=[REDACTED:K] c=[REDACTED:K]",
    );
  });

  it("returns the input unchanged when secretsInScope is empty", () => {
    const input = "nothing to redact here: abcd 1234";
    expect(scrub(input, [])).toBe(input);
  });

  it("returns the input unchanged when no secret value appears in the text", () => {
    expect(scrub("hello world", [{ name: "API", value: "nope" }])).toBe("hello world");
  });

  it("does not mutate the secretsInScope array", () => {
    const secrets = [
      { name: "SHORT", value: "ab" },
      { name: "LONG", value: "abcdef" },
    ];
    const snapshot = JSON.parse(JSON.stringify(secrets)) as unknown;
    scrub("abcdef and ab", secrets);
    expect(JSON.parse(JSON.stringify(secrets))).toEqual(snapshot);
  });

  it("replaces the longest secret first so a shorter substring does not re-match inside", () => {
    // "ab" is a substring of "abcdef". If we replaced "ab" first, it would destroy the longer
    // secret's bytes. Longest-first ordering must redact "abcdef" before considering "ab".
    const out = scrub("value=abcdef standalone=ab", [
      { name: "SHORT", value: "ab" },
      { name: "LONG", value: "abcdef" },
    ]);
    expect(out).toBe("value=[REDACTED:LONG] standalone=[REDACTED:SHORT]");
  });

  it("does not let a shorter secret re-match inside the redaction marker produced for a longer secret", () => {
    // If "RED" were a secret value, a naive implementation that re-scanned the output after
    // inserting "[REDACTED:LONG]" could match "RED" inside the marker. Longest-first ordering
    // plus a single pass per secret over the current result prevents that here.
    const out = scrub("x=abcdef", [
      { name: "LONG", value: "abcdef" },
      { name: "SHORT", value: "cde" },
    ]);
    expect(out).toBe("x=[REDACTED:LONG]");
  });

  it("is binary-safe for arbitrary UTF-8 including emojis", () => {
    const secret = "🔑-sEcReT-📦-ünïcødé";
    const text = `prefix ${secret} middle ${secret} suffix`;
    const out = scrub(text, [{ name: "UTF8", value: secret }]);
    expect(out).toBe("prefix [REDACTED:UTF8] middle [REDACTED:UTF8] suffix");
    expect(out.includes(secret)).toBe(false);
  });

  it("ignores zero-length secret values without infinite-looping or corrupting text", () => {
    const text = "anything at all";
    expect(scrub(text, [{ name: "EMPTY", value: "" }])).toBe(text);
  });

  it("handles multiple distinct secrets in the same text", () => {
    const out = scrub("A=alpha B=beta C=gamma", [
      { name: "A", value: "alpha" },
      { name: "B", value: "beta" },
      { name: "C", value: "gamma" },
    ]);
    expect(out).toBe("A=[REDACTED:A] B=[REDACTED:B] C=[REDACTED:C]");
  });
});
