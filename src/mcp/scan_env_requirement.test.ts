import { describe, it, expect } from "vitest";
import {
  KNOWN_CLIS,
  ENV_REQUIREMENT_TABLE,
  runScanEnvRequirement,
  scanEnvRequirementInputSchema,
} from "./scan_env_requirement.js";

describe("scan_env_requirement", () => {
  it("covers all 20 canonical CLIs", () => {
    expect(KNOWN_CLIS).toHaveLength(20);
    for (const cli of KNOWN_CLIS) {
      const entry = ENV_REQUIREMENT_TABLE[cli];
      expect(entry.length).toBeGreaterThan(0);
      for (const name of entry) {
        expect(name).toMatch(/^[A-Z_][A-Z0-9_]*$/);
      }
    }
  });

  it("returns the canonical Cloudflare API token env var for wrangler", () => {
    const result = runScanEnvRequirement({ command: "wrangler" });
    expect(result.env_vars).toContain("CLOUDFLARE_API_TOKEN");
  });

  it("returns an empty array for an unknown command without throwing", () => {
    expect(() => runScanEnvRequirement({ command: "totally-unknown-binary" }))
      .not.toThrow();
    const result = runScanEnvRequirement({ command: "totally-unknown-binary" });
    expect(result.env_vars).toEqual([]);
  });

  it("does not match prototype keys like toString, constructor", () => {
    expect(runScanEnvRequirement({ command: "toString" }).env_vars).toEqual([]);
    expect(runScanEnvRequirement({ command: "constructor" }).env_vars).toEqual([]);
    expect(runScanEnvRequirement({ command: "hasOwnProperty" }).env_vars).toEqual([]);
  });

  it("returns a fresh array copy (not a reference into the table)", () => {
    const a = runScanEnvRequirement({ command: "wrangler" }).env_vars;
    const b = runScanEnvRequirement({ command: "wrangler" }).env_vars;
    expect(a).not.toBe(b);
    a.push("MUTATED");
    expect(runScanEnvRequirement({ command: "wrangler" }).env_vars).not.toContain(
      "MUTATED",
    );
  });

  it("enumerates every required CLI by name", () => {
    const required = [
      "wrangler",
      "gh",
      "aws",
      "vercel",
      "supabase",
      "stripe",
      "doctl",
      "flyctl",
      "heroku",
      "npm",
      "pnpm",
      "docker",
      "kubectl",
      "railway",
      "render",
      "fly",
      "cloudflared",
      "turso",
      "neon",
      "planetscale",
    ];
    for (const cli of required) {
      const result = runScanEnvRequirement({ command: cli });
      expect(result.env_vars.length).toBeGreaterThan(0);
    }
  });

  it("rejects malformed input via the Zod schema", () => {
    expect(scanEnvRequirementInputSchema.safeParse({}).success).toBe(false);
    expect(scanEnvRequirementInputSchema.safeParse({ command: "" }).success).toBe(
      false,
    );
    expect(scanEnvRequirementInputSchema.safeParse({ command: 42 }).success).toBe(
      false,
    );
    expect(
      scanEnvRequirementInputSchema.safeParse({ command: "gh", extra: 1 }).success,
    ).toBe(false);
  });

  it("accepts a well-formed input via the Zod schema", () => {
    const parsed = scanEnvRequirementInputSchema.safeParse({ command: "gh" });
    expect(parsed.success).toBe(true);
  });
});
