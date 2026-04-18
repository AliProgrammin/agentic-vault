import { describe, it, expect } from "vitest";
import { assertValidSecretName, isValidSecretName } from "./identifier.js";
import { VaultIdentifierError } from "./errors.js";

describe("secret name identifier validation", () => {
  it("accepts common valid names", () => {
    for (const name of ["FOO", "foo", "_bar", "API_KEY", "A1", "name-with-dash"]) {
      expect(() => {
        assertValidSecretName(name);
      }).not.toThrow();
      expect(isValidSecretName(name)).toBe(true);
    }
  });

  it("rejects empty string", () => {
    expect(() => {
      assertValidSecretName("");
    }).toThrow(VaultIdentifierError);
  });

  it("rejects whitespace-only name", () => {
    expect(() => {
      assertValidSecretName("   ");
    }).toThrow(VaultIdentifierError);
  });

  it("rejects names containing whitespace", () => {
    expect(() => {
      assertValidSecretName("foo bar");
    }).toThrow(VaultIdentifierError);
  });

  it("rejects names containing control chars", () => {
    expect(() => {
      assertValidSecretName("foo\u0000bar");
    }).toThrow(VaultIdentifierError);
    expect(() => {
      assertValidSecretName("foo\nbar");
    }).toThrow(VaultIdentifierError);
  });

  it("rejects names containing path separators", () => {
    expect(() => {
      assertValidSecretName("../bad");
    }).toThrow(VaultIdentifierError);
    expect(() => {
      assertValidSecretName("a/b");
    }).toThrow(VaultIdentifierError);
    expect(() => {
      assertValidSecretName("a\\b");
    }).toThrow(VaultIdentifierError);
  });

  it("rejects names starting with a digit", () => {
    expect(() => {
      assertValidSecretName("1foo");
    }).toThrow(VaultIdentifierError);
  });

  it("rejects names that are too long", () => {
    expect(() => {
      assertValidSecretName("a".repeat(200));
    }).toThrow(VaultIdentifierError);
  });

  it("rejects non-string input", () => {
    expect(() => {
      assertValidSecretName(123 as unknown as string);
    }).toThrow(VaultIdentifierError);
    expect(isValidSecretName(null)).toBe(false);
    expect(isValidSecretName(undefined)).toBe(false);
  });
});
