import { describe, it, expect } from "vitest";
import { checkHttp, checkCommand, checkEnvInjection } from "./enforce.js";
import type { Policy } from "./schema.js";

function policy(overrides: Partial<Policy> = {}): Policy {
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
    ...overrides,
  };
}

describe("checkHttp", () => {
  it("allows a request to an allowlisted host", () => {
    const decision = checkHttp(policy(), "https://api.example.com/v1/tokens");
    expect(decision.allowed).toBe(true);
  });

  it("denied HTTP host blocks request", () => {
    const decision = checkHttp(policy(), "https://api.other.com/v1/tokens");
    expect(decision).toEqual({
      allowed: false,
      reason: expect.stringContaining("api.other.com") as unknown as string,
    });
  });

  it("matches hostname case-insensitively", () => {
    const p = policy({ allowed_http_hosts: ["API.EXAMPLE.com"] });
    const decision = checkHttp(p, "https://api.example.COM/path");
    expect(decision.allowed).toBe(true);
  });

  it("rejects non-http(s) schemes", () => {
    const decision = checkHttp(policy(), "file:///etc/passwd");
    expect(decision.allowed).toBe(false);
  });

  it("rejects ftp scheme even with matching hostname", () => {
    const decision = checkHttp(policy(), "ftp://api.example.com/");
    expect(decision.allowed).toBe(false);
  });

  it("denies when URL is unparseable", () => {
    const decision = checkHttp(policy(), "not a url");
    expect(decision.allowed).toBe(false);
  });

  it("denies when policy has no allowed hosts", () => {
    const decision = checkHttp(policy({ allowed_http_hosts: [] }), "https://api.example.com/");
    expect(decision.allowed).toBe(false);
  });

  it("denies when policy is undefined (deny-by-default)", () => {
    const decision = checkHttp(undefined, "https://api.example.com/");
    expect(decision.allowed).toBe(false);
  });

  it("denies subdomain of an allowed host (no wildcard behavior)", () => {
    const decision = checkHttp(policy(), "https://evil.api.example.com/");
    expect(decision.allowed).toBe(false);
  });
});

describe("checkCommand", () => {
  it("allows an allowlisted binary with matching args", () => {
    const decision = checkCommand(policy(), "wrangler", ["deploy"]);
    expect(decision.allowed).toBe(true);
  });

  it("allows a binary with zero args when policy requires none", () => {
    const decision = checkCommand(policy(), "wrangler", []);
    expect(decision.allowed).toBe(true);
  });

  it("denied command blocks exec", () => {
    const decision = checkCommand(policy(), "rm", ["-rf", "/"]);
    expect(decision.allowed).toBe(false);
  });

  it("denied arg pattern blocks exec", () => {
    const decision = checkCommand(policy(), "wrangler", ["secret", "put", "SOMETHING"]);
    expect(decision.allowed).toBe(false);
  });

  it("denies when a forbidden arg pattern matches even if allowed patterns also match", () => {
    const p = policy({
      allowed_commands: [
        {
          binary: "wrangler",
          allowed_args_patterns: ["^[a-z]+$"],
          forbidden_args_patterns: ["^deploy$"],
        },
      ],
    });
    const decision = checkCommand(p, "wrangler", ["deploy"]);
    expect(decision.allowed).toBe(false);
  });

  it("binary comparison is case-sensitive (denies 'WRANGLER' when only 'wrangler' is allowed)", () => {
    const decision = checkCommand(policy(), "WRANGLER", ["deploy"]);
    expect(decision.allowed).toBe(false);
  });

  it("rejects a path-separator binary when the policy entry is bare", () => {
    const decision = checkCommand(policy(), "/usr/bin/wrangler", ["deploy"]);
    expect(decision.allowed).toBe(false);
  });

  it("allows a path-separator binary when the policy entry matches exactly", () => {
    const p = policy({
      allowed_commands: [
        {
          binary: "/usr/bin/wrangler",
          allowed_args_patterns: ["^deploy$"],
        },
      ],
    });
    const decision = checkCommand(p, "/usr/bin/wrangler", ["deploy"]);
    expect(decision.allowed).toBe(true);
  });

  it("denies an arg that matches no allowed pattern but passes forbidden patterns", () => {
    const p = policy({
      allowed_commands: [
        {
          binary: "wrangler",
          allowed_args_patterns: ["^deploy$"],
          forbidden_args_patterns: ["^--danger$"],
        },
      ],
    });
    const decision = checkCommand(p, "wrangler", ["unknown"]);
    expect(decision.allowed).toBe(false);
  });

  it("denies when policy has no allowed commands", () => {
    const decision = checkCommand(policy({ allowed_commands: [] }), "wrangler", []);
    expect(decision.allowed).toBe(false);
  });

  it("denies when policy is undefined (deny-by-default)", () => {
    const decision = checkCommand(undefined, "wrangler", ["deploy"]);
    expect(decision.allowed).toBe(false);
  });

  it("allows multiple args when each matches an allowed pattern", () => {
    const p = policy({
      allowed_commands: [
        {
          binary: "wrangler",
          allowed_args_patterns: ["^deploy$", "^--name$", "^[a-z][a-z0-9-]*$"],
        },
      ],
    });
    const decision = checkCommand(p, "wrangler", ["deploy", "--name", "my-worker"]);
    expect(decision.allowed).toBe(true);
  });
});

describe("checkEnvInjection", () => {
  it("allows an env var in the allowlist", () => {
    const decision = checkEnvInjection(policy(), "CLOUDFLARE_API_TOKEN");
    expect(decision.allowed).toBe(true);
  });

  it("denies an env var not in the allowlist", () => {
    const decision = checkEnvInjection(policy(), "AWS_SECRET_ACCESS_KEY");
    expect(decision.allowed).toBe(false);
  });

  it("denies when allowlist is empty", () => {
    const decision = checkEnvInjection(policy({ allowed_env_vars: [] }), "ANY");
    expect(decision.allowed).toBe(false);
  });

  it("denies when policy is undefined (deny-by-default)", () => {
    const decision = checkEnvInjection(undefined, "CLOUDFLARE_API_TOKEN");
    expect(decision.allowed).toBe(false);
  });
});

describe("deny-by-default across all dimensions", () => {
  it("undefined policy denies HTTP, command, and env injection", () => {
    expect(checkHttp(undefined, "https://api.example.com/").allowed).toBe(false);
    expect(checkCommand(undefined, "wrangler", ["deploy"]).allowed).toBe(false);
    expect(checkEnvInjection(undefined, "CLOUDFLARE_API_TOKEN").allowed).toBe(false);
  });
});
