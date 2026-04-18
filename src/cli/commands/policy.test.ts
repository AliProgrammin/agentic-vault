import { promises as fs } from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Policy } from "../../policy/index.js";
import { unlockVault } from "../../vault/index.js";
import { CliError } from "../errors.js";
import { createPopulatedGlobalVault, makeTestDeps, makeTmpDir } from "../test-helpers.js";
import { cmdPolicySet, cmdPolicyShow } from "./policy.js";

const INITIAL_POLICY: Policy = {
  allowed_http_hosts: [
    "api.one.example.com",
    "api.two.example.com",
    "api.three.example.com",
  ],
  allowed_commands: [],
  allowed_env_vars: ["TOKEN"],
  rate_limit: { requests: 1, window_seconds: 1 },
};

async function setupVault(
  tmp: string,
  password: string,
  secrets: { name: string; value: string; policy?: unknown }[],
): Promise<string> {
  const vaultPath = path.join(tmp, ".secretproxy.enc");
  const h = await createPopulatedGlobalVault(vaultPath, password, secrets);
  h.close();
  return vaultPath;
}

describe("cmdPolicyShow", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await makeTmpDir();
  });
  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("prints the full policy as JSON with sorted keys", async () => {
    const password = "show-vault-pw";
    await setupVault(tmp, password, [
      { name: "TOKEN", value: "v", policy: INITIAL_POLICY },
    ]);

    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      password,
      keychainPopulated: true,
    });

    await cmdPolicyShow(harness.deps, "TOKEN", { project: false });
    const out = harness.stdout.text();
    const parsed = JSON.parse(out.trim()) as unknown;
    expect(parsed).toEqual(INITIAL_POLICY);
  });
});

describe("cmdPolicySet", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await makeTmpDir();
  });
  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("performs a full replacement — prior hosts, commands, env vars are gone", async () => {
    const password = "set-vault-pw";
    const vaultPath = await setupVault(tmp, password, [
      { name: "TOKEN", value: "v", policy: INITIAL_POLICY },
    ]);
    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      password,
      keychainPopulated: true,
    });

    await cmdPolicySet(harness.deps, "TOKEN", {
      project: false,
      host: ["only.example.com"],
      command: ["wrangler:^deploy$"],
      env: ["X"],
      rate: "10/60",
    });

    const reopened = await unlockVault(vaultPath, password);
    const rec = reopened.getRecord("TOKEN");
    expect(rec?.policy).toEqual({
      allowed_http_hosts: ["only.example.com"],
      allowed_commands: [
        { binary: "wrangler", allowed_args_patterns: ["^deploy$"] },
      ],
      allowed_env_vars: ["X"],
      rate_limit: { requests: 10, window_seconds: 60 },
    });
    reopened.close();
  });

  it("rejects wildcard hosts and does not mutate the vault", async () => {
    const password = "wild-vault-pw";
    const vaultPath = await setupVault(tmp, password, [
      { name: "TOKEN", value: "v", policy: INITIAL_POLICY },
    ]);
    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      password,
      keychainPopulated: true,
    });

    await expect(
      cmdPolicySet(harness.deps, "TOKEN", {
        project: false,
        host: ["*"],
        command: [],
        env: [],
        rate: "10/60",
      }),
    ).rejects.toBeInstanceOf(CliError);

    const reopened = await unlockVault(vaultPath, password);
    const rec = reopened.getRecord("TOKEN");
    expect(rec?.policy).toEqual(INITIAL_POLICY);
    reopened.close();
  });

  it("refuses --rate-less convenience usage with a clear message", async () => {
    const password = "no-rate-vault-pw";
    await setupVault(tmp, password, [
      { name: "TOKEN", value: "v", policy: INITIAL_POLICY },
    ]);
    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      password,
      keychainPopulated: true,
    });

    await expect(
      cmdPolicySet(harness.deps, "TOKEN", {
        project: false,
        host: ["only.example.com"],
        command: [],
        env: [],
      }),
    ).rejects.toThrow(/--rate/);
  });

  it("rejects --from-file mixed with convenience flags, no mutation", async () => {
    const password = "mux-vault-pw";
    const vaultPath = await setupVault(tmp, password, [
      { name: "TOKEN", value: "v", policy: INITIAL_POLICY },
    ]);
    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      password,
      keychainPopulated: true,
    });

    const polPath = path.join(tmp, "pol.json");
    await fs.writeFile(polPath, "{}");

    await expect(
      cmdPolicySet(harness.deps, "TOKEN", {
        project: false,
        fromFile: polPath,
        host: ["only.example.com"],
        command: [],
        env: [],
        rate: "10/60",
      }),
    ).rejects.toBeInstanceOf(CliError);

    const reopened = await unlockVault(vaultPath, password);
    const rec = reopened.getRecord("TOKEN");
    expect(rec?.policy).toEqual(INITIAL_POLICY);
    reopened.close();
  });

  it("is atomic: invalid JSON leaves the vault untouched", async () => {
    const password = "atomic-vault-pw";
    const vaultPath = await setupVault(tmp, password, [
      { name: "TOKEN", value: "v", policy: INITIAL_POLICY },
    ]);
    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      password,
      keychainPopulated: true,
    });

    const polPath = path.join(tmp, "bad.json");
    await fs.writeFile(polPath, "{ this is not json");

    await expect(
      cmdPolicySet(harness.deps, "TOKEN", {
        project: false,
        fromFile: polPath,
        host: [],
        command: [],
        env: [],
      }),
    ).rejects.toBeInstanceOf(CliError);

    const reopened = await unlockVault(vaultPath, password);
    expect(reopened.getRecord("TOKEN")?.policy).toEqual(INITIAL_POLICY);
    reopened.close();
  });

  it("round-trips through policy show → edit file → policy set --from-file", async () => {
    const password = "round-vault-pw";
    const vaultPath = await setupVault(tmp, password, [
      { name: "TOKEN", value: "v", policy: INITIAL_POLICY },
    ]);

    const showHarness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      password,
      keychainPopulated: true,
    });
    await cmdPolicyShow(showHarness.deps, "TOKEN", { project: false });
    const shown = JSON.parse(showHarness.stdout.text()) as Policy;

    const edited = {
      ...shown,
      allowed_http_hosts: [...shown.allowed_http_hosts, "api.new.example.com"],
    };
    const polPath = path.join(tmp, "edited.json");
    await fs.writeFile(polPath, JSON.stringify(edited));

    const setHarness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      password,
      keychainPopulated: true,
    });
    await cmdPolicySet(setHarness.deps, "TOKEN", {
      project: false,
      fromFile: polPath,
      host: [],
      command: [],
      env: [],
    });

    const reopened = await unlockVault(vaultPath, password);
    expect(reopened.getRecord("TOKEN")?.policy).toEqual(edited);
    reopened.close();
  });
});
