import { describe, expect, it } from "vitest";
import { parseBulkSecretInput } from "./bulk-import.js";

describe("parseBulkSecretInput", () => {
  it("parses valid rows, quoted values, equals signs, blanks, comments, and skips invalid names", () => {
    const preview = parseBulkSecretInput([
      "# comment",
      "",
      "ALPHA=one",
      'BETA="two words"',
      'GAMMA="three=four"',
      "bad key=nope",
      "DELTA=five",
      "EPSILON=six",
      "ZETA=seven",
      "ETA=eight",
    ].join("\n"));

    expect(preview.added.map((entry) => entry.name)).toEqual([
      "ALPHA",
      "BETA",
      "GAMMA",
      "DELTA",
      "EPSILON",
      "ZETA",
      "ETA",
    ]);
    expect(preview.added[1]?.value).toBe("two words");
    expect(preview.added[2]?.value).toBe("three=four");
    expect(preview.skipped).toEqual([{ line: 6, reason: "invalid secret name" }]);
  });
});
