import { describe, it, expect } from "vitest";
import { ZodError } from "zod";
import {
  makePolicySchema,
  policySchema,
  validatePolicy,
  FORBIDDEN_ENV_VAR_NAMES,
} from "./index.js";

const strictPolicySchema = makePolicySchema({ strictMode: true });

function wellFormedPolicy() {
  return {
    allowed_http_hosts: ["api.example.com"],
    allowed_commands: [
      {
        binary: "wrangler",
        allowed_args_patterns: ["^deploy$"],
      },
    ],
    allowed_env_vars: ["CLOUDFLARE_API_TOKEN"],
    rate_limit: { requests: 10, window_seconds: 60 },
  };
}

describe("policy schema", () => {
  it("accepts a well-formed minimal policy", () => {
    const result = policySchema.safeParse(wellFormedPolicy());
    expect(result.success).toBe(true);
  });

  it("accepts a policy with forbidden_args_patterns present", () => {
    const policy: unknown = {
      ...wellFormedPolicy(),
      allowed_commands: [
        {
          binary: "wrangler",
          allowed_args_patterns: ["^deploy$"],
          forbidden_args_patterns: ["^--dangerous$"],
        },
      ],
    };
    expect(policySchema.safeParse(policy).success).toBe(true);
  });

  it("validatePolicy returns the parsed policy on success", () => {
    const out = validatePolicy(wellFormedPolicy());
    expect(out).not.toBeInstanceOf(ZodError);
    if (out instanceof ZodError) {
      throw new Error("unexpected zod error");
    }
    expect(out.allowed_http_hosts).toEqual(["api.example.com"]);
  });

  it("validatePolicy returns a ZodError on failure", () => {
    const out = validatePolicy({ wrong: true });
    expect(out).toBeInstanceOf(ZodError);
  });

  it("rejects wildcard '*' host", () => {
    const policy = wellFormedPolicy();
    policy.allowed_http_hosts = ["*"];
    const result = strictPolicySchema.safeParse(policy);
    expect(result.success).toBe(false);
  });

  it("rejects empty-string host", () => {
    const policy = wellFormedPolicy();
    policy.allowed_http_hosts = [""];
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects host containing '*'", () => {
    const policy = wellFormedPolicy();
    policy.allowed_http_hosts = ["foo.*.example.com"];
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects host containing whitespace", () => {
    const policy = wellFormedPolicy();
    policy.allowed_http_hosts = ["api .example.com"];
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects URL-shaped FQDN with scheme", () => {
    const policy = wellFormedPolicy();
    policy.allowed_http_hosts = ["https://api.example.com"];
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects URL-shaped FQDN with path", () => {
    const policy = wellFormedPolicy();
    policy.allowed_http_hosts = ["api.example.com/v1"];
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects URL-shaped FQDN with port", () => {
    const policy = wellFormedPolicy();
    policy.allowed_http_hosts = ["api.example.com:443"];
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects wildcard '*' binary", () => {
    const policy = wellFormedPolicy();
    policy.allowed_commands = [{ binary: "*", allowed_args_patterns: ["^deploy$"] }];
    expect(strictPolicySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects binary containing '*'", () => {
    const policy = wellFormedPolicy();
    policy.allowed_commands = [
      { binary: "wrang*ler", allowed_args_patterns: ["^deploy$"] },
    ];
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects binary containing whitespace", () => {
    const policy = wellFormedPolicy();
    policy.allowed_commands = [
      { binary: "wra ngler", allowed_args_patterns: ["^deploy$"] },
    ];
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects empty-string binary", () => {
    const policy = wellFormedPolicy();
    policy.allowed_commands = [{ binary: "", allowed_args_patterns: ["^deploy$"] }];
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects unanchored arg pattern (no leading ^)", () => {
    const policy = wellFormedPolicy();
    policy.allowed_commands = [
      { binary: "wrangler", allowed_args_patterns: ["deploy$"] },
    ];
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects unanchored arg pattern (no trailing $)", () => {
    const policy = wellFormedPolicy();
    policy.allowed_commands = [
      { binary: "wrangler", allowed_args_patterns: ["^deploy"] },
    ];
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects invalid regex arg pattern", () => {
    const policy = wellFormedPolicy();
    policy.allowed_commands = [
      { binary: "wrangler", allowed_args_patterns: ["^[unclosed$"] },
    ];
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects invalid env var name (lowercase)", () => {
    const policy = wellFormedPolicy();
    policy.allowed_env_vars = ["cloudflare_api_token"];
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects env var name starting with a digit", () => {
    const policy = wellFormedPolicy();
    policy.allowed_env_vars = ["1TOKEN"];
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects env var name with a dash", () => {
    const policy = wellFormedPolicy();
    policy.allowed_env_vars = ["MY-TOKEN"];
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects each forbidden env var name", () => {
    for (const name of FORBIDDEN_ENV_VAR_NAMES) {
      const policy = wellFormedPolicy();
      policy.allowed_env_vars = [name];
      const result = policySchema.safeParse(policy);
      expect(result.success, `forbidden env var ${name} should be rejected`).toBe(false);
    }
  });

  it("FORBIDDEN_ENV_VAR_NAMES contains exactly the six cross-cutting names", () => {
    expect([...FORBIDDEN_ENV_VAR_NAMES].sort()).toEqual(
      [
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "NODE_OPTIONS",
        "PYTHONPATH",
      ].sort(),
    );
  });

  it("rejects negative rate-limit requests", () => {
    const policy = wellFormedPolicy();
    policy.rate_limit = { requests: -1, window_seconds: 60 };
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects zero rate-limit window_seconds", () => {
    const policy = wellFormedPolicy();
    policy.rate_limit = { requests: 10, window_seconds: 0 };
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects non-integer rate-limit values", () => {
    const policy: unknown = {
      ...wellFormedPolicy(),
      rate_limit: { requests: 1.5, window_seconds: 60 },
    };
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects unknown top-level fields (strict)", () => {
    const policy: unknown = { ...wellFormedPolicy(), extra: true };
    expect(policySchema.safeParse(policy).success).toBe(false);
  });

  it("rejects missing top-level fields", () => {
    const partial: unknown = {
      allowed_http_hosts: ["api.example.com"],
      allowed_commands: [],
      allowed_env_vars: [],
    };
    expect(policySchema.safeParse(partial).success).toBe(false);
  });
});
