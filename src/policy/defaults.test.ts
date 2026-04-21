import { describe, expect, it } from "vitest";
import { entryValue, policySchema } from "./schema.js";
import {
  DEFAULT_POLICIES,
  listPolicyTemplates,
  lookupDefaultPolicy,
} from "./defaults.js";

describe("DEFAULT_POLICIES", () => {
  it("every entry passes the policySchema (no wildcards, valid FQDNs)", () => {
    for (const [name, p] of Object.entries(DEFAULT_POLICIES)) {
      const parsed = policySchema.safeParse(p);
      expect(parsed.success, `template ${name}`).toBe(true);
    }
  });

  it("no template contains '*' in hosts or binaries", () => {
    for (const [name, p] of Object.entries(DEFAULT_POLICIES)) {
      for (const host of p.allowed_http_hosts) {
        expect(entryValue(host).includes("*"), `${name} host`).toBe(false);
      }
      for (const cmd of p.allowed_commands) {
        expect(entryValue(cmd.binary).includes("*"), `${name} binary`).toBe(false);
      }
    }
  });

  it("lookupDefaultPolicy returns a known provider by exact name", () => {
    const p = lookupDefaultPolicy("OPENAI_API_KEY");
    expect(p).not.toBeNull();
    expect(p?.allowed_http_hosts).toContain("api.openai.com");
  });

  it("lookupDefaultPolicy returns null for unknown names", () => {
    expect(lookupDefaultPolicy("MY_WEIRD_CUSTOM_KEY")).toBeNull();
  });

  it("listPolicyTemplates returns entries sorted by name", () => {
    const list = listPolicyTemplates();
    const names = list.map((e) => e.name);
    const sorted = [...names].sort((a, b) => a.localeCompare(b));
    expect(names).toEqual(sorted);
    expect(list.length).toBeGreaterThanOrEqual(10);
  });

  it("Cloudflare template includes wrangler binary", () => {
    const p = lookupDefaultPolicy("CLOUDFLARE_API_TOKEN");
    const binaries = p?.allowed_commands.map((c) => c.binary) ?? [];
    expect(binaries).toContain("wrangler");
  });

  it("GH_TOKEN and GITHUB_TOKEN point at the same policy shape", () => {
    const gh = lookupDefaultPolicy("GH_TOKEN");
    const github = lookupDefaultPolicy("GITHUB_TOKEN");
    expect(gh).not.toBeNull();
    expect(github).not.toBeNull();
    expect(gh?.allowed_http_hosts).toEqual(github?.allowed_http_hosts);
  });
});
