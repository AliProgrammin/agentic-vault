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

// --- Key helpers: arrow/Tab/Enter/Esc escape codes for the new UI ---
const K = {
  up: "[A",
  down: "[B",
  right: "[C",
  left: "[D",
  tab: "\t",
  enter: "\r",
  esc: "",
};

async function pause(ms = 20): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

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

// Move focus from the default body region to the Secrets tab.
// Default is "body" on dashboard; Esc goes to tabs, → moves to Secrets, Enter opens it.
async function openSecretsTab(app: ReturnType<typeof render>): Promise<void> {
  await act(async () => {
    app.stdin.write(K.esc);      // body → tabs
    await pause(40);
    app.stdin.write(K.right);    // Dashboard → Secrets
    await pause(25);
    app.stdin.write(K.enter);    // open Secrets
    await pause(25);
  });
}

async function openAuditTab(app: ReturnType<typeof render>): Promise<void> {
  await act(async () => {
    app.stdin.write(K.esc);
    await pause(40);
    app.stdin.write(K.right);
    await pause(25);
    app.stdin.write(K.right);
    await pause(25);
    app.stdin.write(K.enter);
    await pause(25);
  });
}

async function openPoliciesTab(app: ReturnType<typeof render>): Promise<void> {
  await act(async () => {
    app.stdin.write(K.esc);
    await pause(40);
    app.stdin.write(K.right);
    await pause(25);
    app.stdin.write(K.right);
    await pause(25);
    app.stdin.write(K.right);
    await pause(25);
    app.stdin.write(K.enter);
    await pause(25);
  });
}

describe("TuiApp", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await makeTmpDir();
  });
  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("renders the dashboard with stat cards, MCP indicator, and recent activity", async () => {
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

    const app = render(
      <TuiApp
        deps={harness.deps}
        services={makeServices({ readAuditLog: async () => [auditEntry] })}
      />,
    );
    await act(async () => {
      await pause();
    });

    const frame = app.lastFrame() ?? "";
    expect(frame).toContain("Agentic Vault");
    expect(frame).toContain("Dashboard");
    expect(frame).toContain("global secrets");
    expect(frame).toContain("project secrets");
    expect(frame).toContain("MCP server");
    expect(frame).toContain("risky policies");
    expect(frame).toContain("Recent activity");
    expect(frame).toContain("API_TOKEN");
    expect(frame).toContain("offline");
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
      await pause();
    });

    await openSecretsTab(app);

    // Focus toolbar, first button is "+ Add secret"
    await act(async () => {
      app.stdin.write(K.tab);      // body → toolbar
      await pause(10);
      app.stdin.write(K.enter);    // activate "+ Add secret"
      await pause(20);
    });

    // Dialog: Name field focused. Type name, Tab to value, paste.
    await act(async () => {
      app.stdin.write("NEW_SECRET");
      await pause(30);
    });
    await act(async () => {
      app.stdin.write(K.tab); // name paste
      await pause(25);
    });
    await act(async () => {
      app.stdin.write(K.tab); // value field
      await pause(25);
    });
    await act(async () => {
      app.stdin.write(K.tab); // value paste button
      await pause(25);
    });
    await act(async () => {
      app.stdin.write(K.enter); // paste into value
      await pause(60);
    });
    await act(async () => {
      app.stdin.write(K.tab); // to actions (Cancel)
      await pause(25);
    });
    await act(async () => {
      app.stdin.write(K.right); // to Save
      await pause(25);
    });
    await act(async () => {
      app.stdin.write(K.enter); // save
      await pause(120);
    });

    const reopened = await harness.deps.unlockVault(vaultPath, password);
    expect(reopened.get("NEW_SECRET")).toBe("PASTED_VALUE");
    reopened.close();
    const frame = app.lastFrame() ?? "";
    // The saved row shows in the Secrets list; plaintext must never leak.
    expect(frame).toContain("NEW_SECRET");
    expect(frame).not.toContain("PASTED_VALUE");
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
    const app = render(
      <TuiApp
        deps={harness.deps}
        services={makeServices({
          readAuditLog: async () => entries,
          watchAuditLog: (_p, onChange) => watcher.watch(onChange),
        })}
      />,
    );

    await act(async () => {
      await pause();
    });

    await openAuditTab(app);

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
      await pause();
    });

    expect(app.lastFrame() ?? "").toContain("TAIL_SECRET");
    app.unmount();
  });

  it("filters audit entries by secret/surface/status predicates via the filter dialog", async () => {
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
    const app = render(
      <TuiApp
        deps={harness.deps}
        services={makeServices({ readAuditLog: async () => entries })}
      />,
    );

    await act(async () => {
      await pause();
    });

    await openAuditTab(app);

    // Tab to toolbar, Enter on "Filter" button (first).
    await act(async () => {
      app.stdin.write(K.tab);  // body → toolbar
      await pause(10);
      app.stdin.write(K.enter); // activate Filter
      await pause(20);
    });

    await act(async () => {
      app.stdin.write("secret:MATCH_ME surface:mcp_run_command status:denied");
      await pause(20);
      // Tab to actions, right to Apply, Enter.
      app.stdin.write(K.tab);   // actions (Cancel focused)
      await pause(5);
      app.stdin.write(K.right); // Apply
      await pause(5);
      app.stdin.write(K.enter); // Apply
      await pause(20);
    });

    const frame = app.lastFrame() ?? "";
    expect(frame).toContain("MATCH_ME");
    expect(frame).not.toContain("IGNORE_ME");
    app.unmount();
  });

  it("Esc moves focus from the body region up to the tab bar without changing screen content", async () => {
    const password = "tui-esc-password";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const handle = await createPopulatedGlobalVault(vaultPath, password, [
      { name: "ESC_TEST", value: "S3" },
    ]);
    handle.close();
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, password, keychainPopulated: true });
    const app = render(<TuiApp deps={harness.deps} services={makeServices()} />);

    await act(async () => {
      await pause();
    });

    // Open Secrets
    await openSecretsTab(app);
    expect(app.lastFrame() ?? "").toContain("Secrets");

    // Esc from body → tabs; Secrets screen still visible, but tab-bar focus indicator shifts.
    await act(async () => {
      app.stdin.write(K.esc);
      await pause();
    });
    const frame = app.lastFrame() ?? "";
    expect(frame).toContain("ESC_TEST"); // still on Secrets screen
    expect(frame).toContain("Secrets"); // tab still active
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
    const app = render(
      <TuiApp
        deps={harness.deps}
        services={makeServices({ readAuditLog: async () => [event] })}
      />,
    );

    await act(async () => {
      await pause();
    });
    await openAuditTab(app);

    // Enter on body drills into detail
    await act(async () => {
      app.stdin.write(K.enter);
      await pause();
    });

    const frame = app.lastFrame() ?? "";
    expect(frame).toContain("━━ Summary ━━");
    expect(frame).toContain(expected.split("\n")[1] ?? "id:");
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

  it("shows the strict-mode banner on the policies screen", async () => {
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
      await pause();
    });

    await openPoliciesTab(app);
    await act(async () => {
      await pause();
    });

    const frame = app.lastFrame() ?? "";
    expect(frame).toContain("Strict mode");
    expect(frame).toContain("STRICT_ONE");
    app.unmount();
  });

  it("rejects a wildcard save in strict mode through the policy dialog without modifying the vault", async () => {
    const password = "tui-strict-save";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const handle = await createPopulatedGlobalVault(vaultPath, password, [
      { name: "STRICT_TWO", value: "SEKRET123" },
    ]);
    handle.setStrictMode(true);
    await handle.save();
    handle.close();

    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, password, keychainPopulated: true });
    const app = render(<TuiApp deps={harness.deps} services={makeServices()} />);
    await act(async () => {
      await pause();
    });

    await openPoliciesTab(app);
    // Tab to toolbar, Enter on "Edit policy"
    await act(async () => {
      app.stdin.write(K.tab);
      await pause(10);
      app.stdin.write(K.enter); // open edit policy
      await pause(20);
    });

    // Hosts field focused. Type wildcard, Tab all the way to actions, right to Save, Enter.
    await act(async () => {
      app.stdin.write("*");
      await pause(10);
      // Hit Enter: that triggers save directly from a field.
      app.stdin.write(K.enter);
      await pause(40);
    });

    const reopened = await harness.deps.unlockVault(vaultPath, password);
    expect(reopened.getRecord("STRICT_TWO")?.policy).toBeUndefined();
    reopened.close();
    app.unmount();
  });

  it("shows wildcard confirmation dialog and cancels without saving when user picks Keep editing", async () => {
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
      await pause();
    });

    await openPoliciesTab(app);
    await act(async () => {
      app.stdin.write(K.tab); // to toolbar
      await pause(10);
      app.stdin.write(K.enter); // open policy edit
      await pause(20);
      app.stdin.write("*");
      await pause(10);
      app.stdin.write(K.enter); // submit
      await pause(30);
    });

    expect(app.lastFrame() ?? "").toContain("Wildcard policy detected");
    expect(app.lastFrame() ?? "").not.toContain("SEKRET123");

    // Keep editing is index 1, default focus. Enter returns to the edit form.
    await act(async () => {
      app.stdin.write(K.enter);
      await pause();
    });

    let reopened = await harness.deps.unlockVault(vaultPath, password);
    expect(reopened.getRecord("CHOICE")?.policy).toBeUndefined();
    reopened.close();

    // Submit again then Save anyway (index 2).
    await act(async () => {
      app.stdin.write(K.enter); // re-submit wildcard
      await pause(30);
      app.stdin.write(K.right); // 1 → 2 (Save anyway)
      await pause(5);
      app.stdin.write(K.enter);
      await pause(40);
    });

    reopened = await harness.deps.unlockVault(vaultPath, password);
    expect(reopened.getRecord("CHOICE")?.policy).toBeDefined();
    reopened.close();
    expect(app.lastFrame() ?? "").not.toContain("SEKRET123");
    app.unmount();
  });

  it("renders the help bar instead of a legacy help overlay", async () => {
    const password = "tui-help-password";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const handle = await createPopulatedGlobalVault(vaultPath, password, []);
    handle.close();
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, password, keychainPopulated: true });
    const app = render(<TuiApp deps={harness.deps} services={makeServices()} />);

    await act(async () => {
      await pause();
    });
    const frame = app.lastFrame() ?? "";
    // The persistent help bar is always visible.
    expect(frame).toMatch(/Tab|Esc|Enter/);
    app.unmount();
  });

  it("replaces the screen body with the dialog when one is open so it stays on-screen", async () => {
    const password = "tui-dialog-render-password";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const handle = await createPopulatedGlobalVault(vaultPath, password, [
      { name: "VISIBLE_ROW", value: "v" },
    ]);
    handle.close();
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, password, keychainPopulated: true });
    const app = render(<TuiApp deps={harness.deps} services={makeServices()} />);

    await act(async () => {
      await pause();
    });

    await openSecretsTab(app);

    // Confirm the secrets list is visible before opening any dialog.
    expect(app.lastFrame() ?? "").toContain("VISIBLE_ROW");

    // Tab to toolbar, Enter on "+ Add secret" — opens the Add dialog.
    await act(async () => {
      app.stdin.write(K.tab);
      await pause(10);
      app.stdin.write(K.enter);
      await pause(20);
    });

    const frame = app.lastFrame() ?? "";
    // Dialog title is rendered. The Paste button is a dialog-only marker
    // (only shown inside Add/Rotate dialogs alongside the Name/Value fields).
    expect(frame).toContain("Add secret");
    expect(frame).toContain("Paste");
    // Screen body is suppressed while a dialog is open so the dialog
    // can't be pushed off the bottom of the alt-screen by the body.
    expect(frame).not.toContain("VISIBLE_ROW");

    // Esc closes the dialog and restores the body.
    await act(async () => {
      app.stdin.write(K.esc);
      await pause(20);
    });
    expect(app.lastFrame() ?? "").toContain("VISIBLE_ROW");
    expect(app.lastFrame() ?? "").not.toContain("Paste");
    app.unmount();
  });

  it("replaces the screen body with the command palette when Ctrl+K is pressed", async () => {
    const password = "tui-palette-render-password";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const handle = await createPopulatedGlobalVault(vaultPath, password, [
      { name: "PALETTE_ROW", value: "v" },
    ]);
    handle.close();
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, password, keychainPopulated: true });
    const app = render(<TuiApp deps={harness.deps} services={makeServices()} />);

    await act(async () => {
      await pause();
    });
    await openSecretsTab(app);
    expect(app.lastFrame() ?? "").toContain("PALETTE_ROW");

    // Ctrl+K opens the palette.
    await act(async () => {
      app.stdin.write(""); // Ctrl+K
      await pause(20);
    });
    const frame = app.lastFrame() ?? "";
    expect(frame).toContain("Command palette");
    expect(frame).not.toContain("PALETTE_ROW");

    // Esc closes.
    await act(async () => {
      app.stdin.write(K.esc);
      await pause(20);
    });
    expect(app.lastFrame() ?? "").toContain("PALETTE_ROW");
    app.unmount();
  });

  it("Cancel is the default-focused button on the Delete dialog so a stray Enter is safe", async () => {
    const password = "tui-delete-default-password";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const handle = await createPopulatedGlobalVault(vaultPath, password, [
      { name: "KEEP_ME", value: "v" },
    ]);
    handle.close();
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, password, keychainPopulated: true });
    const app = render(<TuiApp deps={harness.deps} services={makeServices()} />);

    await act(async () => {
      await pause();
    });

    await openSecretsTab(app);
    // Tab to toolbar, → to Delete (index 2), Enter.
    await act(async () => {
      app.stdin.write(K.tab);
      await pause(10);
      app.stdin.write(K.right); // Rotate
      await pause(5);
      app.stdin.write(K.right); // Delete
      await pause(5);
      app.stdin.write(K.enter); // open Delete dialog
      await pause(20);
    });
    expect(app.lastFrame() ?? "").toContain("Delete this secret?");

    // A stray Enter at this point must NOT delete (Cancel must be focused).
    await act(async () => {
      app.stdin.write(K.enter);
      await pause(40);
    });
    const reopened = await harness.deps.unlockVault(vaultPath, password);
    expect(reopened.get("KEEP_ME")).toBe("v");
    reopened.close();
    app.unmount();
  });
});
