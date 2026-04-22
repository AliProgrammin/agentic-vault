import { promises as fs } from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { render } from "ink-testing-library";
import { act } from "react-test-renderer";
import type { AuditEvent } from "../audit/index.js";
import { buildRenderModel, formatAuditDetail } from "../audit/index.js";
import type { Policy } from "../policy/index.js";
import { createPopulatedGlobalVault, makeTestDeps, makeTmpDir } from "../cli/test-helpers.js";
import {
  TuiApp,
  buildAuditDetailModelForTui,
  createDefaultTuiServices,
  policyBadgeTokens,
  type TuiServices,
} from "./app.js";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const WILDCARD_POLICY: Policy = {
  allowed_http_hosts: [{ value: "*.example.com", wildcard: true, wildcard_kind: "subdomain" }],
  allowed_commands: [{ binary: "wrangler", allowed_args_patterns: ["^deploy$"] }],
  allowed_env_vars: ["CLOUDFLARE_API_TOKEN"],
  rate_limit: { requests: 5, window_seconds: 60 },
};

class FakeWatcher {
  private listener: (() => void) | null = null;

  public watch(onChange: () => void): { close(): void } {
    this.listener = onChange;
    return { close: () => { this.listener = null; } };
  }

  public emit(): void {
    this.listener?.();
  }
}

function makeServices(overrides: Partial<TuiServices> = {}): TuiServices {
  const watcher = overrides.watchAuditLog ?? ((_, onChange) => ({ close: () => void onChange }));
  return {
    clipboard: {
      readText: async () => "PASTED_VALUE\n",
      writeText: async () => undefined,
    },
    readAuditLog: async () => [],
    watchAuditLog: watcher,
    detectMcpServer: async () => false,
    detectUiUrl: async () => null,
    openExternal: async () => undefined,
    stat: async () => ({ mtimeMs: 1 }),
    now: () => 0,
    setTimeout: (fn) => setTimeout(fn, 0),
    clearTimeout: (timer) => clearTimeout(timer),
    ...overrides,
  };
}

describe("TuiApp", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await makeTmpDir();
  });
  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("renders the dashboard snapshot with vault status, MCP indicator, risky count, audit rows, and footer help", async () => {
    const password = "tui-dashboard-password";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const handle = await createPopulatedGlobalVault(vaultPath, password, [
      { name: "API_TOKEN", value: "SEKRET123", policy: WILDCARD_POLICY },
    ]);
    handle.close();
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, password, keychainPopulated: true });
    const auditEntry: AuditEvent = {
      ts: "2026-04-21T10:00:00.000Z",
      secret_name: "API_TOKEN",
      tool: "http_request",
      target: "api.example.com",
      outcome: "allowed",
      request_id: "req-1",
      caller_cwd: tmp,
    };

    const app = render(<TuiApp deps={harness.deps} services={makeServices({ readAuditLog: async () => [auditEntry] })} />);
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
    });

    expect(app.lastFrame()).toMatchInlineSnapshot(`
      "Agentic Vault          / home  s secrets  u audit  p policies  ? help  q quit          ○ MCP offline
      ╭────────────────╮ ╭─────────────────╮ ╭────────────╮ ╭────────────────╮
      │                │ │                 │ │            │ │                │
      │ global secrets │ │ project secrets │ │ MCP server │ │ risky policies │
      │ 1              │ │ 0               │ │ ○ offline  │ │ 1              │
      │                │ │                 │ │            │ │                │
      ╰────────────────╯ ╰─────────────────╯ ╰────────────╯ ╰────────────────╯

      ╭──────────────────────────────────────────────────────────────────────────────────────────────────╮
      │ Dashboard | MCP offline                                                                          │
      │ Vault mtimes | global=1970-01-01T00:00:00.001Z | project=missing                                 │
      │ Risky policies=1                                                                                 │
      │ Recent audit activity                                                                            │
      │ ✓ 2026-04-21T10:00:00.000Z API_TOKEN api.example.com                                             │
      ╰──────────────────────────────────────────────────────────────────────────────────────────────────╯"
    `);
    app.unmount();
  });

  it("adds a secret from the Secrets screen via clipboard paste without rendering plaintext", async () => {
    const password = "tui-add-password";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const handle = await createPopulatedGlobalVault(vaultPath, password, []);
    handle.close();
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, password, keychainPopulated: true });
    const services = makeServices();
    const app = render(<TuiApp deps={harness.deps} services={services} />);

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
    });

    await act(async () => {
      app.stdin.write("s");
      await new Promise((resolve) => setTimeout(resolve, 10));
      app.stdin.write("a");
      await new Promise((resolve) => setTimeout(resolve, 10));
      app.stdin.write("NEW_SECRET");
      await new Promise((resolve) => setTimeout(resolve, 10));
      app.stdin.write("\r");
      await new Promise((resolve) => setTimeout(resolve, 10));
      app.stdin.write("p");
      await new Promise((resolve) => setTimeout(resolve, 10));
      app.stdin.write("\r");
      await new Promise((resolve) => setTimeout(resolve, 120));
    });

    const reopened = await harness.deps.unlockVault(vaultPath, password);
    expect(reopened.get("NEW_SECRET")).toBe("PASTED_VALUE");
    reopened.close();
    expect(app.lastFrame()).toContain("added NEW_SECRET");
    expect(app.lastFrame()).not.toContain("PASTED_VALUE");
    app.unmount();
  });

  it("observes audit live-tail updates through the injected watcher", async () => {
    const password = "tui-audit-password";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const handle = await createPopulatedGlobalVault(vaultPath, password, []);
    handle.close();
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, password, keychainPopulated: true });
    const watcher = new FakeWatcher();
    let entries: AuditEvent[] = [];
    const app = render(<TuiApp deps={harness.deps} services={makeServices({
      readAuditLog: async () => entries,
      watchAuditLog: (_path, onChange) => watcher.watch(onChange),
    })} />);

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
    });

    app.stdin.write("u");
    await act(async () => {
      entries = [{
        ts: "2026-04-21T11:00:00.000Z",
        secret_name: "TAIL_SECRET",
        tool: "run_command",
        target: "wrangler",
        outcome: "denied",
        request_id: "req-tail",
        caller_cwd: tmp,
      }];
      watcher.emit();
      await new Promise((resolve) => setTimeout(resolve, 20));
    });

    expect(app.lastFrame()).toContain("TAIL_SECRET");
    app.unmount();
  });

  it("filters audit entries by secret/surface/status predicates", async () => {
    const password = "tui-filter-password";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const handle = await createPopulatedGlobalVault(vaultPath, password, []);
    handle.close();
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, password, keychainPopulated: true });
    const entries: AuditEvent[] = [
      {
        ts: "2026-04-21T11:00:00.000Z",
        secret_name: "MATCH_ME",
        tool: "run_command",
        target: "wrangler",
        outcome: "denied",
        request_id: "req-match",
        caller_cwd: tmp,
        surface: "mcp_run_command",
      },
      {
        ts: "2026-04-21T11:01:00.000Z",
        secret_name: "IGNORE_ME",
        tool: "http_request",
        target: "api.example.com",
        outcome: "allowed",
        request_id: "req-ignore",
        caller_cwd: tmp,
        surface: "mcp_http_request",
      },
    ];
    const app = render(<TuiApp deps={harness.deps} services={makeServices({ readAuditLog: async () => entries })} />);

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
      app.stdin.write("u");
      await new Promise((resolve) => setTimeout(resolve, 10));
      app.stdin.write("/");
      await new Promise((resolve) => setTimeout(resolve, 10));
      app.stdin.write("secret:MATCH_ME surface:mcp_run_command status:denied");
      await new Promise((resolve) => setTimeout(resolve, 20));
    });

    expect(app.lastFrame()).toContain("MATCH_ME");
    expect(app.lastFrame()).not.toContain("IGNORE_ME");
    app.unmount();
  });

  it("Esc returns from a screen to the dashboard", async () => {
    const password = "tui-esc-password";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const handle = await createPopulatedGlobalVault(vaultPath, password, []);
    handle.close();
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, password, keychainPopulated: true });
    const app = render(<TuiApp deps={harness.deps} services={makeServices()} />);

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
      app.stdin.write("s");
      await new Promise((resolve) => setTimeout(resolve, 10));
      app.stdin.write("\u001b");
      await new Promise((resolve) => setTimeout(resolve, 20));
    });

    expect(app.lastFrame()).toContain("Dashboard | MCP offline");
    app.unmount();
  });

  it("keeps CLI and TUI audit-detail parity through the shared render model", () => {
    const event: AuditEvent = {
      ts: "2026-04-21T11:30:00.000Z",
      secret_name: "API_TOKEN",
      tool: "http_request",
      target: "api.example.com",
      outcome: "allowed",
      request_id: "req-parity",
      caller_cwd: "/tmp/demo",
      surface: "mcp_http_request",
    };

    expect(buildAuditDetailModelForTui(event)).toEqual(buildRenderModel(event));
  });

  it("renders audit detail through the shared CLI formatter output", async () => {
    const password = "tui-detail-password";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const handle = await createPopulatedGlobalVault(vaultPath, password, []);
    handle.close();
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, password, keychainPopulated: true });
    const event: AuditEvent = {
      ts: "2026-04-21T11:30:00.000Z",
      secret_name: "API_TOKEN",
      tool: "http_request",
      target: "api.example.com",
      outcome: "allowed",
      request_id: "req-detail",
      caller_cwd: tmp,
      surface: "mcp_http_request",
    };
    const expected = formatAuditDetail(buildRenderModel(event), { tty: false });
    const app = render(<TuiApp deps={harness.deps} services={makeServices({ readAuditLog: async () => [event] })} />);

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
      app.stdin.write("u");
      await new Promise((resolve) => setTimeout(resolve, 10));
      app.stdin.write("\r");
      await new Promise((resolve) => setTimeout(resolve, 20));
    });

    expect(app.lastFrame()).toContain("━━ Summary ━━");
    expect(app.lastFrame()).toContain(expected.split("\n")[1] ?? "id:");
    app.unmount();
  });

  it("creates a no-op watcher when the audit directory does not exist", () => {
    const services = createDefaultTuiServices();
    const watcher = services.watchAuditLog(path.join(tmp, ".missing", "audit.log"), () => {
      throw new Error("should not fire");
    });
    expect(() => watcher.close()).not.toThrow();
  });

  it("renders wildcard badge tokens from the shared renderer", () => {
    expect(policyBadgeTokens(WILDCARD_POLICY)).toEqual(["[RISKY]"]);
  });

  it("shows the strict-mode banner and keeps the vault unchanged when wildcard policy save is refused", async () => {
    const password = "tui-strict-password";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const handle = await createPopulatedGlobalVault(vaultPath, password, [
      { name: "STRICT_ONE", value: "SEKRET123" },
    ]);
    handle.setStrictMode(true);
    await handle.save();
    handle.close();

    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, password, keychainPopulated: true });
    const app = render(<TuiApp deps={harness.deps} services={makeServices()} />);
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
    });

    app.stdin.write("p");
    app.stdin.write("e");
    app.stdin.write("*");
    app.stdin.write("\r");
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
    });

    const reopened = await harness.deps.unlockVault(vaultPath, password);
    expect(reopened.getRecord("STRICT_ONE")?.policy).toBeUndefined();
    reopened.close();
    expect(app.lastFrame()).toContain("strict mode is enabled for this vault");
    app.unmount();
  });

  it("shows wildcard confirmation, supports no/yes, and never renders plaintext values while switching screens", async () => {
    const password = "tui-policy-password";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const handle = await createPopulatedGlobalVault(vaultPath, password, [
      { name: "CHOICE", value: "SEKRET123" },
    ]);
    handle.setStrictMode(false);
    await handle.save();
    handle.close();
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, password, keychainPopulated: true });
    const app = render(<TuiApp deps={harness.deps} services={makeServices()} />);

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
    });

    await act(async () => {
      app.stdin.write("p");
      await new Promise((resolve) => setTimeout(resolve, 10));
      app.stdin.write("e");
      await new Promise((resolve) => setTimeout(resolve, 10));
      app.stdin.write("*");
      await new Promise((resolve) => setTimeout(resolve, 10));
      app.stdin.write("\r");
      await new Promise((resolve) => setTimeout(resolve, 40));
    });
    expect(app.lastFrame()).toContain("Continue? y/N");
    app.stdin.write("n");
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
    });

    let reopened = await harness.deps.unlockVault(vaultPath, password);
    expect(reopened.getRecord("CHOICE")?.policy).toBeUndefined();
    reopened.close();

    await act(async () => {
      app.stdin.write("\r");
      await new Promise((resolve) => setTimeout(resolve, 40));
    });
    app.stdin.write("y");
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
    });

    reopened = await harness.deps.unlockVault(vaultPath, password);
    expect(reopened.getRecord("CHOICE")?.policy).toBeDefined();
    reopened.close();

    app.stdin.write("?");
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
    });
    expect(app.lastFrame()).toContain("Help");
    expect(app.lastFrame()).not.toContain("SEKRET123");
    app.unmount();
  });
});
