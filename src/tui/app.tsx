// SecretProxy TUI (GUI-feel rewrite).
//
// Single shared `useInput` handler routes every keystroke based on
// the current focus `region`. Only five keys are globally meaningful:
// arrows, Tab, Enter, Esc (plus Ctrl+C to quit and Ctrl+K to open
// the command palette). No single-letter shortcuts.
//
// Clipboard-backed secret values are never rendered back to the terminal:
// value inputs are masked, bulk-import buffers stay hidden, and the state
// slot is cleared immediately after save (with a second best-effort clear
// on a 2-second timer because JS strings cannot be zeroized reliably in
// memory).

import { execFile } from "node:child_process";
import { promises as fs, watch as fsWatch } from "node:fs";
import * as path from "node:path";
import { promisify } from "node:util";
import clipboard from "clipboardy";
import { Box, render, Text, useApp, useInput } from "ink";
import TextInput from "ink-text-input";
import { useEffect, useMemo, useRef, useState, type ReactElement } from "react";
import {
  readAuditEntries,
  type AuditEvent,
} from "../audit/index.js";
import { formatAuditDetail } from "../audit/index.js";
import { VaultLockedError } from "../keychain/index.js";
import {
  entryValue,
  isWildcardEntry,
  validatePolicy,
  wildcardBadge,
  type Policy,
  type PolicyEntry,
} from "../policy/index.js";
import { listMerged } from "../scope/index.js";
import { WrongPasswordError, type VaultHandle } from "../vault/index.js";
import type { CliDeps } from "../cli/types.js";
import {
  buildAuditDetailModelForTui,
  hasWildcardPolicy,
  policyBadgeTokens,
} from "./app-exports.js";
import { parseBulkSecretInput, type BulkImportPreview } from "./bulk-import.js";
import { installTerminalLifecycle } from "./runtime.js";
import {
  createMouseRegistry,
  MouseProvider,
  type MouseContextValue,
} from "./MouseContext.js";
import { disableMouse, enableMouse, parseSgrMouse } from "./mouse.js";
import { Button } from "./components/Button.js";
import { CommandPalette, filterCommands, type PaletteCommand } from "./components/CommandPalette.js";
import { Dialog } from "./components/Dialog.js";
import { FormField } from "./components/FormField.js";
import { HelpBar, type HelpHint } from "./components/HelpBar.js";
import { TabBar, TAB_LABELS } from "./components/TabBar.js";
import { type ToolbarButton } from "./components/Toolbar.js";
import { Toast } from "./components/Toast.js";
import { DashboardScreen } from "./screens/DashboardScreen.js";
import { SecretsScreen } from "./screens/SecretsScreen.js";
import { AuditScreen } from "./screens/AuditScreen.js";
import { PoliciesScreen } from "./screens/PoliciesScreen.js";
import { theme } from "./theme.js";

export { buildAuditDetailModelForTui, policyBadgeTokens };

const execFileAsync = promisify(execFile);
const UI_PORT = 7381;

type Screen = "dashboard" | "secrets" | "audit" | "policies";
type Region = "tabs" | "body" | "toolbar" | "dialog" | "palette";
type ScopeChoice = "global" | "project";

interface ClipboardAdapter {
  readText(): Promise<string>;
  writeText(text: string): Promise<void>;
}

interface WatchHandle {
  close(): void;
}

export interface TuiServices {
  readonly clipboard: ClipboardAdapter;
  readAuditLog(logPath: string): Promise<readonly AuditEvent[]>;
  watchAuditLog(logPath: string, onChange: () => void): WatchHandle;
  detectMcpServer(): Promise<boolean>;
  detectUiUrl(): Promise<string | null>;
  openExternal(url: string): Promise<void>;
  stat(filePath: string): Promise<{ readonly mtimeMs: number } | null>;
  now(): number;
  setTimeout(fn: () => void, ms: number): ReturnType<typeof setTimeout>;
  clearTimeout(timer: ReturnType<typeof setTimeout>): void;
}

interface VaultRef {
  readonly path: string;
  readonly scope: ScopeChoice;
  handle: VaultHandle;
}

interface TuiSession {
  password: string;
  global: VaultRef | null;
  project: VaultRef | null;
}

interface SecretRow {
  readonly name: string;
  readonly scope: ScopeChoice;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly policy?: Policy;
}

interface Snapshot {
  readonly secrets: readonly SecretRow[];
  readonly audit: readonly AuditEvent[];
  readonly dashboard: {
    readonly globalCount: number;
    readonly projectCount: number;
    readonly riskyPolicyCount: number;
    readonly globalMtime: string;
    readonly projectMtime: string;
    readonly mcpOnline: boolean;
  };
}

interface ToastState {
  readonly kind: "success" | "error" | "info";
  readonly text: string;
}

// Dialog state machines. Every dialog tracks which "focus slot" is
// active; slots include form fields, per-field paste buttons, and
// the action row at the bottom.

// A dialog focus slot is either a field index `{ kind: 'field', index }`
// or the action row `{ kind: 'actions' }`.

type DialogFocus =
  | { readonly kind: "field"; readonly index: number; readonly onPaste: boolean }
  | { readonly kind: "actions"; readonly index: number };

interface AddDialogState {
  readonly kind: "add" | "rotate";
  readonly scope: ScopeChoice;
  readonly name: string;
  readonly value: string;
  readonly focus: DialogFocus;
  readonly error: string | null;
}

interface BulkDialogState {
  readonly kind: "bulk";
  readonly buffer: string;
  readonly preview: BulkImportPreview | null;
  readonly scope: ScopeChoice;
  readonly focus: DialogFocus;
  readonly error: string | null;
}

interface DeleteDialogState {
  readonly kind: "delete";
  readonly name: string;
  readonly scope: ScopeChoice;
  readonly focus: DialogFocus; // always actions
}

interface PolicyDialogState {
  readonly kind: "policy";
  readonly targetName: string;
  readonly targetScope: ScopeChoice;
  readonly hostsText: string;
  readonly commandsText: string;
  readonly envText: string;
  readonly requestsText: string;
  readonly windowText: string;
  readonly focus: DialogFocus;
  readonly awaitingConfirm: boolean;
  readonly error: string | null;
}

interface FilterDialogState {
  readonly kind: "filter";
  readonly target: "secrets" | "audit";
  readonly value: string;
  readonly focus: DialogFocus;
}

type DialogState =
  | AddDialogState
  | BulkDialogState
  | DeleteDialogState
  | PolicyDialogState
  | FilterDialogState;

interface AppProps {
  readonly deps: CliDeps;
  readonly services: TuiServices;
}

function defaultClipboard(): ClipboardAdapter {
  return {
    async readText(): Promise<string> {
      return clipboard.read();
    },
    async writeText(text: string): Promise<void> {
      await clipboard.write(text);
    },
  };
}

function defaultWatchAuditLog(logPath: string, onChange: () => void): WatchHandle {
  const dir = path.dirname(logPath);
  const base = path.basename(logPath);
  let watcher: ReturnType<typeof fsWatch> | null = null;
  try {
    watcher = fsWatch(dir, (_event: string, filename: string | Buffer | null) => {
      if (filename === undefined || String(filename) === base) {
        onChange();
      }
    });
  } catch {
    watcher = null;
  }
  return {
    close(): void {
      watcher?.close();
    },
  };
}

async function defaultDetectMcpServer(): Promise<boolean> {
  try {
    const { stdout } = await execFileAsync("ps", ["-axo", "command="]);
    return stdout.split(/\r?\n/u).some((line) => line.includes("secretproxy run"));
  } catch {
    return false;
  }
}

async function defaultDetectUiUrl(): Promise<string | null> {
  const url = `http://127.0.0.1:${String(UI_PORT)}`;
  try {
    const res = await fetch(`${url}/healthz`);
    return res.ok ? url : null;
  } catch {
    return null;
  }
}

async function defaultOpenExternal(url: string): Promise<void> {
  const platform = process.platform;
  const command = platform === "darwin" ? "open" : "xdg-open";
  await execFileAsync(command, [url]);
}

async function defaultStat(filePath: string): Promise<{ readonly mtimeMs: number } | null> {
  try {
    const st = await fs.stat(filePath);
    return { mtimeMs: st.mtimeMs };
  } catch {
    return null;
  }
}

export function createDefaultTuiServices(): TuiServices {
  return {
    clipboard: defaultClipboard(),
    readAuditLog: readAuditEntries,
    watchAuditLog: defaultWatchAuditLog,
    detectMcpServer: defaultDetectMcpServer,
    detectUiUrl: defaultDetectUiUrl,
    openExternal: defaultOpenExternal,
    stat: defaultStat,
    now: () => Date.now(),
    setTimeout: (fn, ms) => setTimeout(fn, ms),
    clearTimeout: (timer) => clearTimeout(timer),
  };
}

function closeSession(session: TuiSession | null): void {
  session?.global?.handle.close();
  session?.project?.handle.close();
}

async function loadSession(deps: CliDeps, password: string): Promise<TuiSession> {
  let global: VaultRef | null = null;
  let project: VaultRef | null = null;
  if (await deps.fileExists(deps.globalVaultPath)) {
    global = {
      path: deps.globalVaultPath,
      scope: "global",
      handle: await deps.unlockVault(deps.globalVaultPath, password),
    };
  }
  const location = await deps.discoverProjectVault(deps.cwd, deps.homedir);
  if (location !== null) {
    try {
      project = {
        path: location.vaultPath,
        scope: "project",
        handle: await deps.unlockVault(location.vaultPath, password),
      };
    } catch (err) {
      if (!(err instanceof WrongPasswordError)) {
        throw err;
      }
    }
  }
  return { password, global, project };
}

function collectSecretRows(session: TuiSession): readonly SecretRow[] {
  const out: SecretRow[] = [];
  for (const entry of listMerged({
    global: session.global?.handle ?? null,
    project: session.project?.handle ?? null,
  })) {
    out.push({
      name: entry.name,
      scope: entry.scope,
      createdAt: entry.created_at,
      updatedAt: entry.updated_at,
      ...(entry.policy !== undefined ? { policy: entry.policy as Policy } : {}),
    });
  }
  return out;
}

function formatMtime(mtimeMs: number | null): string {
  return mtimeMs === null ? "missing" : new Date(mtimeMs).toISOString();
}

async function buildSnapshot(
  deps: CliDeps,
  services: TuiServices,
  session: TuiSession,
): Promise<Snapshot> {
  const [audit, mcpOnline, globalStat, projectStat] = await Promise.all([
    services.readAuditLog(deps.auditLogPath),
    services.detectMcpServer(),
    session.global !== null ? services.stat(session.global.path) : Promise.resolve(null),
    session.project !== null ? services.stat(session.project.path) : Promise.resolve(null),
  ]);
  const secrets = collectSecretRows(session);
  return {
    secrets,
    audit,
    dashboard: {
      globalCount: session.global?.handle.list().length ?? 0,
      projectCount: session.project?.handle.list().length ?? 0,
      riskyPolicyCount: secrets.filter((secret) => hasWildcardPolicy(secret.policy)).length,
      globalMtime: formatMtime(globalStat?.mtimeMs ?? null),
      projectMtime: formatMtime(projectStat?.mtimeMs ?? null),
      mcpOnline,
    },
  };
}

async function ensureScopeHandle(
  deps: CliDeps,
  session: TuiSession,
  scope: ScopeChoice,
): Promise<VaultRef> {
  if (scope === "global") {
    if (session.global !== null) {
      return session.global;
    }
    session.global = {
      path: deps.globalVaultPath,
      scope,
      handle: await deps.createVault(deps.globalVaultPath, session.password),
    };
    return session.global;
  }
  if (session.project !== null) {
    return session.project;
  }
  const created = await deps.ensureProjectVault(deps.cwd, session.password);
  session.project = {
    path: created.vaultPath,
    scope,
    handle: created.handle,
  };
  return session.project;
}

function filterAuditEntriesForTui(entries: readonly AuditEvent[], filter: string): readonly AuditEvent[] {
  const query = filter.trim().toLowerCase();
  if (query.length === 0) {
    return entries;
  }
  const clauses = query.split(/\s+/u).filter((part) => part.length > 0);
  return entries.filter((entry) => {
    const haystack = [entry.secret_name, entry.surface ?? "", entry.outcome, entry.target].join(" ").toLowerCase();
    for (const clause of clauses) {
      const match = clause.match(/^(secret|surface|status):(.*)$/u);
      if (match !== null) {
        const key = match[1];
        const value = match[2];
        if (key === undefined || value === undefined) {
          continue;
        }
        if (value.length === 0) {
          continue;
        }
        if (key === "secret" && !entry.secret_name.toLowerCase().includes(value)) {
          return false;
        }
        if (key === "surface" && !(entry.surface ?? "").toLowerCase().includes(value)) {
          return false;
        }
        if (key === "status" && !entry.outcome.toLowerCase().includes(value)) {
          return false;
        }
        continue;
      }
      if (!haystack.includes(clause)) {
        return false;
      }
    }
    return true;
  });
}

function getPolicyForSecret(session: TuiSession, secret: SecretRow): Policy | null {
  const handle = secret.scope === "global" ? session.global?.handle : session.project?.handle;
  return (handle?.getRecord(secret.name)?.policy as Policy | undefined) ?? null;
}

function splitFieldEntries(text: string): string[] {
  return text
    .split(/[\n,]/u)
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

function formatEntryWithBadge(entry: PolicyEntry): string {
  const label = entryValue(entry);
  if (!isWildcardEntry(entry)) {
    return label;
  }
  return `${label} ${wildcardBadge(entry.wildcard_kind, { tty: false })}`;
}

function formatPolicyForScreen(policy: Policy | null): {
  readonly hosts: readonly string[];
  readonly commands: readonly string[];
  readonly envs: readonly string[];
  readonly rate: string;
} {
  if (policy === null) {
    return {
      hosts: [],
      commands: [],
      envs: [],
      rate: "1/60",
    };
  }
  return {
    hosts: policy.allowed_http_hosts.map((entry) => formatEntryWithBadge(entry)),
    commands: policy.allowed_commands.map((command) => {
      const binary = formatEntryWithBadge(command.binary);
      const allowed = command.allowed_args_patterns.join(", ");
      const forbidden = (command.forbidden_args_patterns ?? []).join(", ");
      return forbidden.length > 0
        ? `${binary} | allow: ${allowed} | deny: ${forbidden}`
        : `${binary} | allow: ${allowed}`;
    }),
    envs: policy.allowed_env_vars.map((entry) => formatEntryWithBadge(entry)),
    rate: `${String(policy.rate_limit.requests)}/${String(policy.rate_limit.window_seconds)}`,
  };
}

function policyToDialogState(
  policy: Policy | null,
  targetName: string,
  targetScope: ScopeChoice,
): PolicyDialogState {
  return {
    kind: "policy",
    targetName,
    targetScope,
    hostsText: policy?.allowed_http_hosts.map((entry) => entryValue(entry)).join(", ") ?? "",
    commandsText:
      policy?.allowed_commands
        .map((command) => {
          const forbidden = (command.forbidden_args_patterns ?? []).join(",");
          return `${entryValue(command.binary)}|${command.allowed_args_patterns.join(",")}|${forbidden}`;
        })
        .join(";") ?? "",
    envText: policy?.allowed_env_vars.map((entry) => entryValue(entry)).join(", ") ?? "",
    requestsText: String(policy?.rate_limit.requests ?? 1),
    windowText: String(policy?.rate_limit.window_seconds ?? 60),
    focus: { kind: "field", index: 0, onPaste: false },
    awaitingConfirm: false,
    error: null,
  };
}

function buildPolicyFromDialog(dialog: PolicyDialogState): Policy | Error {
  const requests = Number(dialog.requestsText);
  const windowSeconds = Number(dialog.windowText);
  if (!Number.isInteger(requests) || requests <= 0) {
    return new Error("rate requests must be a positive integer");
  }
  if (!Number.isInteger(windowSeconds) || windowSeconds <= 0) {
    return new Error("rate window must be a positive integer");
  }
  try {
    const allowed_commands = splitFieldEntries(dialog.commandsText.replace(/;/gu, "\n")).map((line) => {
      const [binaryRaw, allowedRaw = "", forbiddenRaw = ""] = line.split("|").map((part) => part.trim());
      if (binaryRaw === undefined || binaryRaw.length === 0) {
        throw new Error(`invalid command rule '${line}'`);
      }
      const allowed_args_patterns = splitFieldEntries(allowedRaw);
      if (allowed_args_patterns.length === 0) {
        throw new Error(`command '${binaryRaw}' must include at least one allowed pattern`);
      }
      const forbidden_args_patterns = splitFieldEntries(forbiddenRaw);
      return {
        binary: binaryRaw,
        allowed_args_patterns,
        ...(forbidden_args_patterns.length > 0 ? { forbidden_args_patterns } : {}),
      };
    });
    return {
      allowed_http_hosts: splitFieldEntries(dialog.hostsText),
      allowed_commands,
      allowed_env_vars: splitFieldEntries(dialog.envText),
      rate_limit: { requests, window_seconds: windowSeconds },
    };
  } catch (err) {
    return err instanceof Error ? err : new Error(String(err));
  }
}

function getSecretValue(session: TuiSession, secret: SecretRow): string | undefined {
  const handle = secret.scope === "global" ? session.global?.handle : session.project?.handle;
  return handle?.get(secret.name);
}

// --- Focus cycling helpers for dialogs -------------------------------

interface FieldSpec {
  readonly id: string;
  readonly hasPaste: boolean;
}

function nextDialogFocus(
  focus: DialogFocus,
  fields: readonly FieldSpec[],
  actionCount: number,
): DialogFocus {
  if (focus.kind === "field") {
    const field = fields[focus.index];
    if (field !== undefined && field.hasPaste && !focus.onPaste) {
      return { kind: "field", index: focus.index, onPaste: true };
    }
    const nextIndex = focus.index + 1;
    if (nextIndex < fields.length) {
      return { kind: "field", index: nextIndex, onPaste: false };
    }
    if (actionCount > 0) {
      return { kind: "actions", index: 0 };
    }
    return { kind: "field", index: 0, onPaste: false };
  }
  // actions → wrap to first field (or first action if no fields)
  if (fields.length > 0) {
    return { kind: "field", index: 0, onPaste: false };
  }
  return { kind: "actions", index: 0 };
}

// ---------------------------------------------------------------------

export function TuiApp(props: AppProps): ReactElement {
  const mouseRef = useRef<MouseContextValue | null>(null);
  if (mouseRef.current === null) {
    mouseRef.current = createMouseRegistry();
  }
  return (
    <MouseProvider value={mouseRef.current}>
      <TuiAppInner {...props} mouse={mouseRef.current} />
    </MouseProvider>
  );
}

interface TuiAppInnerProps extends AppProps {
  readonly mouse: MouseContextValue;
}

function TuiAppInner(props: TuiAppInnerProps): ReactElement {
  const { exit } = useApp();
  const [screen, setScreen] = useState<Screen>("dashboard");
  const [region, setRegion] = useState<Region>("tabs");
  const [tabFocus, setTabFocus] = useState(0);
  const [toolbarFocus, setToolbarFocus] = useState(0);
  const [session, setSession] = useState<TuiSession | null>(null);
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [unlock, setUnlock] = useState<
    | {
        value: string;
        error: string | null;
        hasVault: boolean;
        actionFocus: number; // 0 = cancel/quit, 1 = submit
        focusArea: "input" | "actions";
      }
    | null
  >(null);
  const [dialog, setDialog] = useState<DialogState | null>(null);
  const [toast, setToast] = useState<ToastState | null>(null);
  const [secretFilter, setSecretFilter] = useState("");
  const [auditFilter, setAuditFilter] = useState("");
  const [selectedSecret, setSelectedSecret] = useState(0);
  const [selectedAudit, setSelectedAudit] = useState(0);
  const [auditDetail, setAuditDetail] = useState(false);
  const [paletteQuery, setPaletteQuery] = useState("");
  const [paletteIndex, setPaletteIndex] = useState(0);
  const zeroizeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const filteredSecrets = useMemo(() => {
    const rows = snapshot?.secrets ?? [];
    const q = secretFilter.toLowerCase();
    return q.length === 0 ? rows : rows.filter((s) => s.name.toLowerCase().includes(q));
  }, [snapshot, secretFilter]);
  const selectedSecretRow: SecretRow | null =
    filteredSecrets[selectedSecret] ?? filteredSecrets[0] ?? null;
  const filteredAudit = useMemo(
    () => filterAuditEntriesForTui(snapshot?.audit ?? [], auditFilter),
    [snapshot, auditFilter],
  );
  const selectedAuditEntry = filteredAudit[selectedAudit] ?? filteredAudit[0] ?? null;

  const showToast = (next: ToastState): void => {
    setToast(next);
    if (toastTimer.current !== null) {
      props.services.clearTimeout(toastTimer.current);
    }
    toastTimer.current = props.services.setTimeout(() => {
      setToast(null);
    }, 2500);
  };

  const refresh = async (current: TuiSession): Promise<void> => {
    const next = await buildSnapshot(props.deps, props.services, current);
    setSnapshot(next);
  };

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const password = props.deps.resolvePassword();
        const nextSession = await loadSession(props.deps, password);
        if (cancelled) {
          closeSession(nextSession);
          return;
        }
        setSession(nextSession);
        await refresh(nextSession);
      } catch (err) {
        if (!cancelled && err instanceof VaultLockedError) {
          const hasVault = await props.deps.fileExists(props.deps.globalVaultPath);
          setUnlock({ value: "", error: null, hasVault, actionFocus: 1, focusArea: "input" });
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => () => {
    if (zeroizeTimer.current !== null) {
      props.services.clearTimeout(zeroizeTimer.current);
    }
    if (toastTimer.current !== null) {
      props.services.clearTimeout(toastTimer.current);
    }
    closeSession(session);
  }, [session]);

  useEffect(() => {
    if (session === null) {
      return;
    }
    const watcher = props.services.watchAuditLog(props.deps.auditLogPath, () => {
      void refresh(session);
    });
    return () => watcher.close();
  }, [session]);

  // Reset transient per-screen state when switching screens.
  // Do NOT touch `region` here — the user explicitly chose their focus
  // region (tabs on mount, or whatever the Tab/Enter handlers set). This
  // effect fires on mount too, so resetting region would clobber the
  // initial "tabs" focus and break arrow navigation on launch.
  useEffect(() => {
    setAuditDetail(false);
    setToolbarFocus(0);
  }, [screen]);

  const screenIndex = TAB_LABELS.findIndex(
    (label) => label.toLowerCase() === screen,
  );

  const clearSecretValue = (): void => {
    setDialog((current) => {
      if (current === null || (current.kind !== "add" && current.kind !== "rotate")) {
        return current;
      }
      return { ...current, value: "" };
    });
    if (zeroizeTimer.current !== null) {
      props.services.clearTimeout(zeroizeTimer.current);
    }
    zeroizeTimer.current = props.services.setTimeout(() => {
      setDialog((current) => {
        if (current === null || (current.kind !== "add" && current.kind !== "rotate")) {
          return current;
        }
        return { ...current, value: "" };
      });
    }, 2000);
  };

  const clearBulkBuffer = (): void => {
    setDialog((current) => {
      if (current === null || current.kind !== "bulk") {
        return current;
      }
      return { ...current, buffer: "" };
    });
    if (zeroizeTimer.current !== null) {
      props.services.clearTimeout(zeroizeTimer.current);
    }
    zeroizeTimer.current = props.services.setTimeout(() => {
      setDialog((current) => {
        if (current === null || current.kind !== "bulk") {
          return current;
        }
        return { ...current, buffer: "" };
      });
    }, 2000);
  };

  const saveSingleSecret = async (current: AddDialogState): Promise<void> => {
    if (session === null) {
      return;
    }
    if (current.name.trim().length === 0) {
      setDialog({ ...current, error: "Name is required" });
      return;
    }
    const target = await ensureScopeHandle(props.deps, session, current.scope);
    const nextValue = current.value.replace(/[\r\n]+$/u, "");
    const existingPolicy = target.handle.getRecord(current.name)?.policy;
    target.handle.set(current.name, nextValue, existingPolicy);
    await target.handle.save();
    await refresh(session);
    clearSecretValue();
    setDialog(null);
    setRegion("toolbar");
    showToast({
      kind: "success",
      text: `${current.kind === "add" ? "added" : "rotated"} ${current.name}`,
    });
  };

  const saveBulkPreview = async (current: BulkDialogState): Promise<void> => {
    if (session === null || current.preview === null) {
      return;
    }
    const target = await ensureScopeHandle(props.deps, session, current.scope);
    for (const entry of current.preview.added) {
      target.handle.set(
        entry.name,
        entry.value.replace(/[\r\n]+$/u, ""),
        target.handle.getRecord(entry.name)?.policy,
      );
    }
    await target.handle.save();
    await refresh(session);
    clearBulkBuffer();
    setDialog(null);
    setRegion("toolbar");
    showToast({
      kind: "success",
      text: `${String(current.preview.added.length)} added, ${String(current.preview.skipped.length)} skipped`,
    });
  };

  const savePolicyDraft = async (
    current: PolicyDialogState,
    confirmed: boolean,
  ): Promise<void> => {
    if (session === null) {
      return;
    }
    const target = current.targetScope === "global" ? session.global : session.project;
    if (target === null) {
      setDialog({ ...current, error: "vault not available" });
      return;
    }
    const draftPolicy = buildPolicyFromDialog(current);
    if (draftPolicy instanceof Error) {
      setDialog({ ...current, error: draftPolicy.message });
      return;
    }
    const validated = validatePolicy(draftPolicy, {
      strictMode: target.handle.getStrictMode(),
    });
    if (validated instanceof Error) {
      setDialog({ ...current, error: validated.message });
      return;
    }
    if (!confirmed && hasWildcardPolicy(validated)) {
      setDialog({ ...current, awaitingConfirm: true, error: null });
      return;
    }
    const secretRow = (snapshot?.secrets ?? []).find(
      (s) => s.name === current.targetName && s.scope === current.targetScope,
    );
    if (secretRow === undefined) {
      setDialog({ ...current, error: `secret not found: ${current.targetName}` });
      return;
    }
    const value = getSecretValue(session, secretRow);
    if (value === undefined) {
      setDialog({ ...current, error: `secret not found: ${current.targetName}` });
      return;
    }
    target.handle.set(current.targetName, value, validated);
    await target.handle.save();
    await refresh(session);
    setDialog(null);
    setRegion("toolbar");
    showToast({ kind: "success", text: `policy updated for ${current.targetName}` });
  };

  const deleteSecret = async (current: DeleteDialogState): Promise<void> => {
    if (session === null) {
      return;
    }
    const target = current.scope === "global" ? session.global : session.project;
    target?.handle.remove(current.name);
    await target?.handle.save();
    await refresh(session);
    setDialog(null);
    setRegion("toolbar");
    showToast({ kind: "success", text: `deleted ${current.name}` });
  };

  const tryUnlock = async (): Promise<void> => {
    if (unlock === null) {
      return;
    }
    try {
      const nextSession = await loadSession(props.deps, unlock.value);
      props.deps.passwordStore.storeMasterPassword(unlock.value);
      setSession(nextSession);
      setUnlock(null);
      await refresh(nextSession);
    } catch (err) {
      const text = err instanceof WrongPasswordError ? err.message : String(err);
      setUnlock({ ...unlock, value: "", error: text });
    }
  };

  const doPaste = async (onText: (text: string) => void): Promise<void> => {
    try {
      const text = await props.services.clipboard.readText();
      onText(text);
      showToast({
        kind: "success",
        text: `pasted ${String(text.length)} chars`,
      });
    } catch {
      showToast({ kind: "error", text: "clipboard read failed" });
    }
  };

  const doCopy = async (text: string, label: string): Promise<void> => {
    try {
      await props.services.clipboard.writeText(text);
      showToast({ kind: "success", text: `copied ${label}` });
    } catch {
      showToast({ kind: "error", text: "clipboard write failed" });
    }
  };

  // -------- Toolbars for each screen --------
  const secretsToolbar: readonly ToolbarButton[] = [
    { label: "+ Add secret" },
    { label: "↻ Rotate", disabled: selectedSecretRow === null },
    { label: "− Delete", variant: "danger", disabled: selectedSecretRow === null },
    { label: "⚙ Policy", disabled: selectedSecretRow === null },
    { label: "⎘ Copy name", disabled: selectedSecretRow === null },
    { label: "⤒ Bulk import" },
    { label: "⧉ Filter" },
  ];
  const auditToolbar: readonly ToolbarButton[] = auditDetail
    ? [
        { label: "⎘ Copy detail", disabled: selectedAuditEntry === null },
        { label: "← Back" },
      ]
    : [
        { label: "⧉ Filter" },
        { label: "⎘ Copy detail", disabled: selectedAuditEntry === null },
      ];
  const policiesToolbar: readonly ToolbarButton[] = [
    { label: "⚙ Edit policy", disabled: selectedSecretRow === null },
    { label: "⎘ Copy policy JSON", disabled: selectedSecretRow === null },
  ];

  const currentToolbar: readonly ToolbarButton[] =
    screen === "secrets"
      ? secretsToolbar
      : screen === "audit"
        ? auditToolbar
        : screen === "policies"
          ? policiesToolbar
          : [];

  const activateSecretsToolbar = (index: number = toolbarFocus): void => {
    const btn = secretsToolbar[index];
    if (btn === undefined || btn.disabled === true) {
      return;
    }
    switch (btn.label) {
      case "+ Add secret":
        setDialog({
          kind: "add",
          scope: selectedSecretRow?.scope ?? "global",
          name: "",
          value: "",
          focus: { kind: "field", index: 0, onPaste: false },
          error: null,
        });
        setRegion("dialog");
        return;
      case "↻ Rotate":
        if (selectedSecretRow !== null) {
          setDialog({
            kind: "rotate",
            scope: selectedSecretRow.scope,
            name: selectedSecretRow.name,
            value: "",
            focus: { kind: "field", index: 1, onPaste: false },
            error: null,
          });
          setRegion("dialog");
        }
        return;
      case "− Delete":
        if (selectedSecretRow !== null) {
          setDialog({
            kind: "delete",
            name: selectedSecretRow.name,
            scope: selectedSecretRow.scope,
            focus: { kind: "actions", index: 1 },
          });
          setRegion("dialog");
        }
        return;
      case "⚙ Policy":
        if (selectedSecretRow !== null) {
          setDialog(
            policyToDialogState(
              getPolicyForSecret(session as TuiSession, selectedSecretRow),
              selectedSecretRow.name,
              selectedSecretRow.scope,
            ),
          );
          setRegion("dialog");
        }
        return;
      case "⎘ Copy name":
        if (selectedSecretRow !== null) {
          void doCopy(selectedSecretRow.name, selectedSecretRow.name);
        }
        return;
      case "⤒ Bulk import":
        setDialog({
          kind: "bulk",
          buffer: "",
          preview: null,
          scope: selectedSecretRow?.scope ?? "global",
          focus: { kind: "actions", index: 1 },
          error: null,
        });
        setRegion("dialog");
        return;
      case "⧉ Filter":
        setDialog({
          kind: "filter",
          target: "secrets",
          value: secretFilter,
          focus: { kind: "field", index: 0, onPaste: false },
        });
        setRegion("dialog");
        return;
      default:
        return;
    }
  };

  const activateAuditToolbar = (index: number = toolbarFocus): void => {
    const btn = auditToolbar[index];
    if (btn === undefined || btn.disabled === true) {
      return;
    }
    switch (btn.label) {
      case "⧉ Filter":
        setDialog({
          kind: "filter",
          target: "audit",
          value: auditFilter,
          focus: { kind: "field", index: 0, onPaste: false },
        });
        setRegion("dialog");
        return;
      case "⎘ Copy detail":
        if (selectedAuditEntry !== null) {
          const model = buildAuditDetailModelForTui(selectedAuditEntry);
          void doCopy(formatAuditDetail(model, { tty: false }), "audit detail");
        }
        return;
      case "← Back":
        setAuditDetail(false);
        setRegion("body");
        return;
      default:
        return;
    }
  };

  const activatePoliciesToolbar = (index: number = toolbarFocus): void => {
    const btn = policiesToolbar[index];
    if (btn === undefined || btn.disabled === true || selectedSecretRow === null) {
      return;
    }
    switch (btn.label) {
      case "⚙ Edit policy":
        setDialog(
          policyToDialogState(
            getPolicyForSecret(session as TuiSession, selectedSecretRow),
            selectedSecretRow.name,
            selectedSecretRow.scope,
          ),
        );
        setRegion("dialog");
        return;
      case "⎘ Copy policy JSON": {
        const policy = getPolicyForSecret(session as TuiSession, selectedSecretRow);
        void doCopy(
          JSON.stringify(policy ?? {}, null, 2),
          `policy for ${selectedSecretRow.name}`,
        );
        return;
      }
      default:
        return;
    }
  };

  const handleToolbarClick = (index: number): void => {
    setToolbarFocus(index);
    setRegion("toolbar");
    if (screen === "secrets") {
      activateSecretsToolbar(index);
    } else if (screen === "audit") {
      activateAuditToolbar(index);
    } else if (screen === "policies") {
      activatePoliciesToolbar(index);
    }
  };

  const handleDialogAction = (d: DialogState, index: number): void => {
    if (d.kind === "add" || d.kind === "rotate") {
      if (index === 0) {
        clearSecretValue();
        setDialog(null);
        setRegion("toolbar");
        return;
      }
      void saveSingleSecret(d);
      return;
    }
    if (d.kind === "delete") {
      if (index === 0) {
        setDialog(null);
        setRegion("toolbar");
        return;
      }
      void deleteSecret(d);
      return;
    }
    if (d.kind === "bulk") {
      if (index === 0) {
        clearBulkBuffer();
        setDialog(null);
        setRegion("toolbar");
        return;
      }
      if (d.preview === null && d.buffer.length === 0) {
        void doPaste((text) => {
          setDialog((prev) => {
            if (prev === null || prev.kind !== "bulk") {
              return prev;
            }
            return { ...prev, buffer: text, preview: null };
          });
        });
        return;
      }
      if (d.preview === null && d.buffer.length > 0) {
        setDialog({ ...d, preview: parseBulkSecretInput(d.buffer) });
        return;
      }
      void saveBulkPreview(d);
      return;
    }
    if (d.kind === "filter") {
      if (index === 0) {
        setDialog(null);
        setRegion("toolbar");
        return;
      }
      if (d.target === "secrets") {
        setSecretFilter(d.value);
      } else {
        setAuditFilter(d.value);
      }
      setDialog(null);
      setRegion("toolbar");
      return;
    }
    if (d.kind === "policy") {
      if (d.awaitingConfirm) {
        if (index === 0) {
          setDialog(null);
          setRegion("toolbar");
        } else if (index === 1) {
          setDialog({ ...d, awaitingConfirm: false });
        } else {
          void savePolicyDraft(d, true);
        }
        return;
      }
      if (index === 0) {
        setDialog(null);
        setRegion("toolbar");
        return;
      }
      void savePolicyDraft(d, false);
    }
  };

  const handleTabClick = (index: number): void => {
    const targetLabel = TAB_LABELS[index];
    if (targetLabel === undefined) {
      return;
    }
    setScreen(targetLabel.toLowerCase() as Screen);
    setTabFocus(index);
    setRegion("body");
  };

  const handleSecretRowClick = (index: number): void => {
    setSelectedSecret(index);
    setRegion("body");
  };

  const handleAuditRowClick = (index: number): void => {
    setSelectedAudit(index);
    setRegion("body");
    if (!auditDetail && filteredAudit[index] !== undefined) {
      setAuditDetail(true);
    }
  };

  const handleSecretScroll = (delta: number): void => {
    setSelectedSecret((i) => {
      const max = Math.max(0, filteredSecrets.length - 1);
      return Math.max(0, Math.min(max, i + delta));
    });
  };

  const handleAuditScroll = (delta: number): void => {
    setSelectedAudit((i) => {
      const max = Math.max(0, filteredAudit.length - 1);
      return Math.max(0, Math.min(max, i + delta));
    });
  };

  const activateToolbar = (): void => {
    if (screen === "secrets") {
      activateSecretsToolbar();
    } else if (screen === "audit") {
      activateAuditToolbar();
    } else if (screen === "policies") {
      activatePoliciesToolbar();
    }
  };

  // -------- Command palette --------
  const paletteCommands: readonly PaletteCommand[] = [
    { id: "goto:dashboard", label: "Go to Dashboard" },
    { id: "goto:secrets", label: "Go to Secrets" },
    { id: "goto:audit", label: "Go to Audit" },
    { id: "goto:policies", label: "Go to Policies" },
    { id: "add:secret", label: "Add secret" },
    { id: "bulk:import", label: "Bulk import secrets" },
    { id: "rotate:secret", label: "Rotate selected secret" },
    { id: "delete:secret", label: "Delete selected secret" },
    { id: "edit:policy", label: "Edit policy for selected secret" },
    { id: "copy:name", label: "Copy selected secret name" },
    { id: "filter:secrets", label: "Filter secrets" },
    { id: "filter:audit", label: "Filter audit" },
    { id: "quit", label: "Quit" },
  ];
  const filteredPaletteCommands = filterCommands(paletteCommands, paletteQuery);

  const runPaletteCommand = (id: string): void => {
    setRegion("body");
    setPaletteQuery("");
    setPaletteIndex(0);
    switch (id) {
      case "goto:dashboard":
        setScreen("dashboard");
        return;
      case "goto:secrets":
        setScreen("secrets");
        return;
      case "goto:audit":
        setScreen("audit");
        return;
      case "goto:policies":
        setScreen("policies");
        return;
      case "add:secret":
        setScreen("secrets");
        setDialog({
          kind: "add",
          scope: selectedSecretRow?.scope ?? "global",
          name: "",
          value: "",
          focus: { kind: "field", index: 0, onPaste: false },
          error: null,
        });
        setRegion("dialog");
        return;
      case "bulk:import":
        setScreen("secrets");
        setDialog({
          kind: "bulk",
          buffer: "",
          preview: null,
          scope: selectedSecretRow?.scope ?? "global",
          focus: { kind: "actions", index: 1 },
          error: null,
        });
        setRegion("dialog");
        return;
      case "rotate:secret":
        if (selectedSecretRow !== null) {
          setScreen("secrets");
          setDialog({
            kind: "rotate",
            scope: selectedSecretRow.scope,
            name: selectedSecretRow.name,
            value: "",
            focus: { kind: "field", index: 1, onPaste: false },
            error: null,
          });
          setRegion("dialog");
        }
        return;
      case "delete:secret":
        if (selectedSecretRow !== null) {
          setScreen("secrets");
          setDialog({
            kind: "delete",
            name: selectedSecretRow.name,
            scope: selectedSecretRow.scope,
            focus: { kind: "actions", index: 1 },
          });
          setRegion("dialog");
        }
        return;
      case "edit:policy":
        if (selectedSecretRow !== null) {
          setScreen("policies");
          setDialog(
            policyToDialogState(
              getPolicyForSecret(session as TuiSession, selectedSecretRow),
              selectedSecretRow.name,
              selectedSecretRow.scope,
            ),
          );
          setRegion("dialog");
        }
        return;
      case "copy:name":
        if (selectedSecretRow !== null) {
          void doCopy(selectedSecretRow.name, selectedSecretRow.name);
        }
        return;
      case "filter:secrets":
        setScreen("secrets");
        setDialog({
          kind: "filter",
          target: "secrets",
          value: secretFilter,
          focus: { kind: "field", index: 0, onPaste: false },
        });
        setRegion("dialog");
        return;
      case "filter:audit":
        setScreen("audit");
        setDialog({
          kind: "filter",
          target: "audit",
          value: auditFilter,
          focus: { kind: "field", index: 0, onPaste: false },
        });
        setRegion("dialog");
        return;
      case "quit":
        exit();
        return;
      default:
        return;
    }
  };

  // -------- Dialog field helpers --------
  const addDialogFields = (current: AddDialogState): readonly FieldSpec[] => {
    const f: FieldSpec[] = [];
    if (current.kind === "add") {
      f.push({ id: "name", hasPaste: true });
    }
    f.push({ id: "value", hasPaste: true });
    return f;
  };
  const policyDialogFields: readonly FieldSpec[] = [
    { id: "hosts", hasPaste: false },
    { id: "commands", hasPaste: false },
    { id: "env", hasPaste: false },
    { id: "requests", hasPaste: false },
    { id: "window", hasPaste: false },
  ];

  // ============ INPUT ROUTER (keyboard + mouse) ============
  useInput((input, key) => {
    // Mouse events arrive as raw CSI bodies (Ink strips the leading ESC).
    // Detect them first so they don't fall through to keyboard handlers.
    const mouseEvent = parseSgrMouse(input);
    if (mouseEvent !== null) {
      if (mouseEvent.kind === "press") {
        props.mouse.dispatchClick(mouseEvent.col, mouseEvent.row);
      } else if (mouseEvent.kind === "scrollUp") {
        props.mouse.dispatchScroll(mouseEvent.col, mouseEvent.row, -1);
      } else if (mouseEvent.kind === "scrollDown") {
        props.mouse.dispatchScroll(mouseEvent.col, mouseEvent.row, 1);
      }
      return;
    }

    if (key.ctrl === true && input === "c") {
      exit();
      return;
    }

    // Unlock screen
    if (unlock !== null) {
      if (unlock.focusArea === "input") {
        if (key.tab || key.downArrow) {
          setUnlock({ ...unlock, focusArea: "actions" });
          return;
        }
        if (key.return) {
          void tryUnlock();
          return;
        }
        if (key.escape) {
          exit();
        }
        return;
      }
      // actions
      if (key.tab || key.upArrow) {
        setUnlock({ ...unlock, focusArea: "input" });
        return;
      }
      if (key.leftArrow) {
        setUnlock({ ...unlock, actionFocus: Math.max(0, unlock.actionFocus - 1) });
        return;
      }
      if (key.rightArrow) {
        setUnlock({ ...unlock, actionFocus: Math.min(1, unlock.actionFocus + 1) });
        return;
      }
      if (key.return) {
        if (unlock.actionFocus === 0) {
          exit();
          return;
        }
        void tryUnlock();
        return;
      }
      if (key.escape) {
        exit();
      }
      return;
    }

    // Ctrl+K opens palette (global)
    if (key.ctrl === true && input === "k" && region !== "palette" && region !== "dialog") {
      setPaletteQuery("");
      setPaletteIndex(0);
      setRegion("palette");
      return;
    }

    // PALETTE
    if (region === "palette") {
      if (key.escape) {
        setRegion("body");
        setPaletteQuery("");
        setPaletteIndex(0);
        return;
      }
      if (key.return) {
        const cmd = filteredPaletteCommands[paletteIndex];
        if (cmd !== undefined) {
          runPaletteCommand(cmd.id);
        }
        return;
      }
      if (key.upArrow) {
        setPaletteIndex((i) => Math.max(0, i - 1));
        return;
      }
      if (key.downArrow) {
        setPaletteIndex((i) => Math.min(filteredPaletteCommands.length - 1, i + 1));
        return;
      }
      // TextInput owns the rest (filters via its focus flag)
      return;
    }

    // DIALOG
    if (region === "dialog" && dialog !== null) {
      // Esc always cancels
      if (key.escape) {
        if (dialog.kind === "add" || dialog.kind === "rotate") {
          clearSecretValue();
        } else if (dialog.kind === "bulk") {
          clearBulkBuffer();
        } else if (dialog.kind === "policy" && dialog.awaitingConfirm) {
          setDialog({ ...dialog, awaitingConfirm: false });
          return;
        }
        setDialog(null);
        setRegion("toolbar");
        return;
      }

      // Policy wildcard confirmation gate
      if (dialog.kind === "policy" && dialog.awaitingConfirm) {
        // actions row: Cancel, Keep editing, Save anyway
        if (key.leftArrow) {
          const idx = dialog.focus.kind === "actions" ? dialog.focus.index : 0;
          setDialog({ ...dialog, focus: { kind: "actions", index: Math.max(0, idx - 1) } });
          return;
        }
        if (key.rightArrow) {
          const idx = dialog.focus.kind === "actions" ? dialog.focus.index : 0;
          setDialog({ ...dialog, focus: { kind: "actions", index: Math.min(2, idx + 1) } });
          return;
        }
        if (key.return) {
          const idx = dialog.focus.kind === "actions" ? dialog.focus.index : 0;
          if (idx === 0) {
            // cancel whole thing
            setDialog(null);
            setRegion("toolbar");
          } else if (idx === 1) {
            // keep editing → drop confirm flag
            setDialog({ ...dialog, awaitingConfirm: false });
          } else {
            // save anyway
            void savePolicyDraft(dialog, true);
          }
        }
        return;
      }

      // Add / Rotate dialog
      if (dialog.kind === "add" || dialog.kind === "rotate") {
        const fields = addDialogFields(dialog as AddDialogState);
        const actionCount = 2; // Cancel, Save
        if (key.tab) {
          setDialog({
            ...dialog,
            focus: nextDialogFocus(dialog.focus, fields, actionCount),
          });
          return;
        }
        if (dialog.focus.kind === "field") {
          const field = fields[dialog.focus.index];
          if (field === undefined) {
            return;
          }
          if (dialog.focus.onPaste) {
            if (key.return) {
              const fieldId = field.id;
              void doPaste((text) => {
                setDialog((prev) => {
                  if (prev === null || (prev.kind !== "add" && prev.kind !== "rotate")) {
                    return prev;
                  }
                  if (fieldId === "name") {
                    return { ...prev, name: text.replace(/[\r\n]+$/u, "") };
                  }
                  return { ...prev, value: text.replace(/[\r\n]+$/u, "") };
                });
              });
            }
            if (key.leftArrow) {
              setDialog({
                ...dialog,
                focus: { kind: "field", index: dialog.focus.index, onPaste: false },
              });
            }
            return;
          }
          // field input, Enter submits full dialog (go to Save action) or advances
          if (key.return) {
            // advance to next field; if no next, trigger save
            const next = nextDialogFocus(dialog.focus, fields, actionCount);
            if (next.kind === "actions") {
              setDialog({ ...dialog, focus: { kind: "actions", index: 1 } }); // focus Save
            } else {
              setDialog({ ...dialog, focus: next });
            }
            return;
          }
          return;
        }
        // actions row
        if (key.leftArrow) {
          setDialog({
            ...dialog,
            focus: { kind: "actions", index: Math.max(0, dialog.focus.index - 1) },
          });
          return;
        }
        if (key.rightArrow) {
          setDialog({
            ...dialog,
            focus: { kind: "actions", index: Math.min(actionCount - 1, dialog.focus.index + 1) },
          });
          return;
        }
        if (key.return) {
          if (dialog.focus.index === 0) {
            clearSecretValue();
            setDialog(null);
            setRegion("toolbar");
            return;
          }
          void saveSingleSecret(dialog);
        }
        return;
      }

      // Bulk dialog
      if (dialog.kind === "bulk") {
        const preview = dialog.preview;
        const actionCount = 2;
        if (key.tab) {
          setDialog({
            ...dialog,
            focus: { kind: "actions", index: (dialog.focus.kind === "actions" ? (dialog.focus.index + 1) % actionCount : 0) },
          });
          return;
        }
        if (key.leftArrow && dialog.focus.kind === "actions") {
          setDialog({
            ...dialog,
            focus: { kind: "actions", index: Math.max(0, dialog.focus.index - 1) },
          });
          return;
        }
        if (key.rightArrow && dialog.focus.kind === "actions") {
          setDialog({
            ...dialog,
            focus: { kind: "actions", index: Math.min(actionCount - 1, dialog.focus.index + 1) },
          });
          return;
        }
        // Scope toggle with up/down when focused on actions
        if ((key.upArrow || key.downArrow) && dialog.focus.kind === "actions") {
          setDialog({
            ...dialog,
            scope: dialog.scope === "global" ? "project" : "global",
          });
          return;
        }
        if (key.return) {
          if (dialog.focus.kind !== "actions") {
            return;
          }
          if (dialog.focus.index === 0) {
            // cancel
            clearBulkBuffer();
            setDialog(null);
            setRegion("toolbar");
            return;
          }
          // action index 1: paste/preview/import
          if (preview === null && dialog.buffer.length === 0) {
            // Paste
            void doPaste((text) => {
              setDialog((prev) => {
                if (prev === null || prev.kind !== "bulk") {
                  return prev;
                }
                return { ...prev, buffer: text, preview: null };
              });
            });
            return;
          }
          if (preview === null && dialog.buffer.length > 0) {
            setDialog({ ...dialog, preview: parseBulkSecretInput(dialog.buffer) });
            return;
          }
          // preview !== null → import
          void saveBulkPreview(dialog);
        }
        return;
      }

      // Delete dialog
      if (dialog.kind === "delete") {
        const actionCount = 2;
        if (key.leftArrow) {
          setDialog({
            ...dialog,
            focus: { kind: "actions", index: Math.max(0, dialog.focus.index - 1) },
          });
          return;
        }
        if (key.rightArrow) {
          setDialog({
            ...dialog,
            focus: { kind: "actions", index: Math.min(actionCount - 1, dialog.focus.index + 1) },
          });
          return;
        }
        if (key.return) {
          if (dialog.focus.index === 0) {
            setDialog(null);
            setRegion("toolbar");
            return;
          }
          void deleteSecret(dialog);
        }
        return;
      }

      // Policy dialog (non-confirm)
      if (dialog.kind === "policy") {
        const fields = policyDialogFields;
        const actionCount = 2;
        if (key.tab) {
          setDialog({
            ...dialog,
            focus: nextDialogFocus(dialog.focus, fields, actionCount),
          });
          return;
        }
        if (dialog.focus.kind === "actions") {
          if (key.leftArrow) {
            setDialog({
              ...dialog,
              focus: { kind: "actions", index: Math.max(0, dialog.focus.index - 1) },
            });
            return;
          }
          if (key.rightArrow) {
            setDialog({
              ...dialog,
              focus: { kind: "actions", index: Math.min(actionCount - 1, dialog.focus.index + 1) },
            });
            return;
          }
          if (key.return) {
            if (dialog.focus.index === 0) {
              setDialog(null);
              setRegion("toolbar");
              return;
            }
            void savePolicyDraft(dialog, false);
          }
          return;
        }
        // field focus — Enter submits
        if (key.return) {
          void savePolicyDraft(dialog, false);
        }
        return;
      }

      // Filter dialog
      if (dialog.kind === "filter") {
        const actionCount = 2;
        if (key.tab) {
          setDialog({
            ...dialog,
            focus: nextDialogFocus(dialog.focus, [{ id: "q", hasPaste: false }], actionCount),
          });
          return;
        }
        if (dialog.focus.kind === "actions") {
          if (key.leftArrow) {
            setDialog({
              ...dialog,
              focus: { kind: "actions", index: Math.max(0, dialog.focus.index - 1) },
            });
            return;
          }
          if (key.rightArrow) {
            setDialog({
              ...dialog,
              focus: { kind: "actions", index: Math.min(actionCount - 1, dialog.focus.index + 1) },
            });
            return;
          }
          if (key.return) {
            if (dialog.focus.index === 0) {
              setDialog(null);
              setRegion("toolbar");
              return;
            }
            if (dialog.target === "secrets") {
              setSecretFilter(dialog.value);
            } else {
              setAuditFilter(dialog.value);
            }
            setDialog(null);
            setRegion("toolbar");
          }
          return;
        }
        if (key.return) {
          if (dialog.target === "secrets") {
            setSecretFilter(dialog.value);
          } else {
            setAuditFilter(dialog.value);
          }
          setDialog(null);
          setRegion("toolbar");
        }
        return;
      }
      return;
    }

    // MAIN UI routing: tabs / body / toolbar

    // Esc: escalate one region level up; if at tabs, no-op.
    if (key.escape) {
      if (auditDetail) {
        setAuditDetail(false);
        setRegion("body");
        return;
      }
      if (region === "toolbar") {
        setRegion("body");
        return;
      }
      if (region === "body") {
        setRegion("tabs");
        setTabFocus(Math.max(0, screenIndex));
        return;
      }
      return;
    }

    // Tab: cycle regions
    if (key.tab) {
      if (region === "tabs") {
        setRegion("body");
        return;
      }
      if (region === "body") {
        if (currentToolbar.length > 0) {
          setRegion("toolbar");
          setToolbarFocus(0);
        } else {
          setRegion("tabs");
          setTabFocus(Math.max(0, screenIndex));
        }
        return;
      }
      // toolbar → tabs
      setRegion("tabs");
      setTabFocus(Math.max(0, screenIndex));
      return;
    }

    // TABS region
    if (region === "tabs") {
      if (key.leftArrow) {
        setTabFocus((i) => Math.max(0, i - 1));
        return;
      }
      if (key.rightArrow) {
        setTabFocus((i) => Math.min(TAB_LABELS.length - 1, i + 1));
        return;
      }
      if (key.return) {
        const targetLabel = TAB_LABELS[tabFocus] ?? "Dashboard";
        const next = targetLabel.toLowerCase() as Screen;
        setScreen(next);
        setRegion("body");
      }
      return;
    }

    // TOOLBAR region
    if (region === "toolbar") {
      if (key.leftArrow) {
        setToolbarFocus((i) => Math.max(0, i - 1));
        return;
      }
      if (key.rightArrow) {
        setToolbarFocus((i) => Math.min(currentToolbar.length - 1, i + 1));
        return;
      }
      if (key.return) {
        activateToolbar();
      }
      return;
    }

    // BODY region (per-screen)
    if (screen === "secrets") {
      if (key.upArrow) {
        setSelectedSecret((i) => Math.max(0, i - 1));
        return;
      }
      if (key.downArrow) {
        setSelectedSecret((i) => Math.min(Math.max(0, filteredSecrets.length - 1), i + 1));
        return;
      }
      return;
    }
    if (screen === "audit") {
      if (auditDetail) {
        if (key.upArrow) {
          setSelectedAudit((i) => Math.max(0, i - 1));
          return;
        }
        if (key.downArrow) {
          setSelectedAudit((i) => Math.min(filteredAudit.length - 1, i + 1));
          return;
        }
        return;
      }
      if (key.upArrow) {
        setSelectedAudit((i) => Math.max(0, i - 1));
        return;
      }
      if (key.downArrow) {
        setSelectedAudit((i) => Math.min(Math.max(0, filteredAudit.length - 1), i + 1));
        return;
      }
      if (key.return && selectedAuditEntry !== null) {
        setAuditDetail(true);
      }
      return;
    }
    if (screen === "policies") {
      if (key.upArrow) {
        setSelectedSecret((i) => Math.max(0, i - 1));
        return;
      }
      if (key.downArrow) {
        setSelectedSecret((i) => Math.min(Math.max(0, filteredSecrets.length - 1), i + 1));
      }
    }
    // dashboard body: no-op
  });

  // ============ RENDER ============
  if (loading) {
    return <Text color={theme.dim}>Loading...</Text>;
  }

  if (unlock !== null) {
    const isNew = !unlock.hasVault;
    return (
      <Box justifyContent="center" alignItems="center" flexDirection="column">
        <Box
          borderStyle="round"
          borderColor={theme.border}
          flexDirection="column"
          padding={2}
          width={60}
        >
          <Text color={theme.accent} bold>
            {isNew ? "Set up Agentic Vault" : "Unlock Agentic Vault"}
          </Text>
          <Text color={theme.dim}>
            {isNew
              ? "No vault found. Enter a new master password to create one (min 12 characters)."
              : "Enter your master password to continue."}
          </Text>
          <Box marginTop={1} flexDirection="column">
            <Text color={unlock.focusArea === "input" ? theme.accent : theme.dim}>
              Master password
            </Text>
            <TextInput
              focus={unlock.focusArea === "input"}
              value={unlock.value}
              mask="*"
              onChange={(value) => setUnlock({ ...unlock, value })}
            />
          </Box>
          {unlock.error !== null ? (
            <Box marginTop={1}>
              <Text color={theme.danger}>{unlock.error}</Text>
            </Box>
          ) : null}
          <Box marginTop={1}>
            <Button
              label={isNew ? "Cancel" : "Quit"}
              focused={unlock.focusArea === "actions" && unlock.actionFocus === 0}
            />
            <Text> </Text>
            <Button
              label={isNew ? "Create vault" : "Unlock"}
              focused={unlock.focusArea === "actions" && unlock.actionFocus === 1}
            />
          </Box>
        </Box>
        <HelpBar hints={[
          { key: "Tab", label: "switch field" },
          { key: "←→", label: "buttons" },
          { key: "Enter", label: "activate" },
          { key: "Esc", label: "quit" },
        ]} />
      </Box>
    );
  }

  const selectedPolicy =
    selectedSecretRow !== null && session !== null
      ? getPolicyForSecret(session, selectedSecretRow)
      : null;
  const policyView = formatPolicyForScreen(selectedPolicy);
  const selectedPolicyHandle =
    selectedSecretRow?.scope === "global"
      ? session?.global?.handle
      : session?.project?.handle;
  const strictMode = selectedPolicyHandle?.getStrictMode() === true;

  const hints: readonly HelpHint[] = (() => {
    if (region === "palette") {
      return [
        { key: "↑↓", label: "move" },
        { key: "Enter", label: "run" },
        { key: "Esc", label: "close" },
      ];
    }
    if (region === "dialog") {
      return [
        { key: "Tab", label: "next field" },
        { key: "←→", label: "buttons" },
        { key: "Enter", label: "activate" },
        { key: "Esc", label: "cancel" },
      ];
    }
    if (region === "tabs") {
      return [
        { key: "←→", label: "tab" },
        { key: "Enter", label: "open" },
        { key: "Tab", label: "focus body" },
        { key: "Ctrl+K", label: "palette" },
        { key: "Ctrl+C", label: "quit" },
      ];
    }
    if (region === "toolbar") {
      return [
        { key: "←→", label: "button" },
        { key: "Enter", label: "activate" },
        { key: "Tab", label: "focus tabs" },
        { key: "Esc", label: "back" },
      ];
    }
    return [
      { key: "↑↓", label: "move" },
      { key: "Enter", label: "select" },
      { key: "Tab", label: "switch area" },
      { key: "Esc", label: "back" },
      { key: "Ctrl+K", label: "palette" },
    ];
  })();

  return (
    <Box flexDirection="column">
      <TabBar
        activeIndex={Math.max(0, screenIndex)}
        focusedIndex={tabFocus}
        isFocused={region === "tabs"}
        onTabClick={handleTabClick}
      />

      {screen === "dashboard" && snapshot !== null ? (
        <DashboardScreen dashboard={snapshot.dashboard} audit={snapshot.audit} />
      ) : null}

      {screen === "secrets" ? (
        <SecretsScreen
          secrets={filteredSecrets}
          selectedIndex={selectedSecret}
          filter={secretFilter}
          selectedSecret={selectedSecretRow}
          bodyFocused={region === "body"}
          toolbarFocused={region === "toolbar"}
          toolbarIndex={toolbarFocus}
          toolbarButtons={secretsToolbar}
          onRowClick={handleSecretRowClick}
          onScroll={handleSecretScroll}
          onToolbarClick={handleToolbarClick}
        />
      ) : null}

      {screen === "audit" ? (
        <AuditScreen
          entries={filteredAudit}
          selectedIndex={selectedAudit}
          filter={auditFilter}
          auditDetail={auditDetail}
          model={selectedAuditEntry !== null ? buildAuditDetailModelForTui(selectedAuditEntry) : null}
          bodyFocused={region === "body"}
          toolbarFocused={region === "toolbar"}
          toolbarIndex={toolbarFocus}
          toolbarButtons={auditToolbar}
          onRowClick={handleAuditRowClick}
          onScroll={handleAuditScroll}
          onToolbarClick={handleToolbarClick}
        />
      ) : null}

      {screen === "policies" ? (
        <PoliciesScreen
          secrets={filteredSecrets}
          selectedIndex={selectedSecret}
          selectedSecret={selectedSecretRow}
          policyView={policyView}
          strictMode={strictMode}
          bodyFocused={region === "body"}
          toolbarFocused={region === "toolbar"}
          toolbarIndex={toolbarFocus}
          toolbarButtons={policiesToolbar}
          onRowClick={handleSecretRowClick}
          onScroll={handleSecretScroll}
          onToolbarClick={handleToolbarClick}
        />
      ) : null}

      {dialog !== null ? <DialogOverlay dialog={dialog} /> : null}
      {region === "palette" ? (
        <CommandPalette
          query={paletteQuery}
          onQueryChange={(q) => {
            setPaletteQuery(q);
            setPaletteIndex(0);
          }}
          commands={paletteCommands}
          selectedIndex={paletteIndex}
          onItemClick={(index) => {
            const cmd = filteredPaletteCommands[index];
            if (cmd !== undefined) {
              setPaletteIndex(index);
              runPaletteCommand(cmd.id);
            }
          }}
        />
      ) : null}

      {toast !== null ? (
        <Toast kind={toast.kind} text={toast.text} />
      ) : null}

      <HelpBar hints={hints} />
    </Box>
  );

  // ============ DIALOG RENDERER ============
  function DialogOverlay(innerProps: { readonly dialog: DialogState }): ReactElement {
    const d = innerProps.dialog;
    if (d.kind === "add" || d.kind === "rotate") {
      const fields = addDialogFields(d);
      const actions: readonly ToolbarButton[] = [
        { label: "Cancel" },
        { label: "Save", variant: "success" },
      ];
      return (
        <Dialog
          title={d.kind === "add" ? "Add secret" : "Rotate value"}
          description={`scope: ${d.scope}`}
          actions={actions}
          focusedAction={d.focus.kind === "actions" ? d.focus.index : 0}
          actionsFocused={d.focus.kind === "actions"}
          errorText={d.error}
          onAction={(index) => handleDialogAction(d, index)}
        >
          {d.kind === "add" ? (
            <FormField
              label="Name"
              value={d.name}
              isFieldFocused={d.focus.kind === "field" && fields[d.focus.index]?.id === "name" && !d.focus.onPaste}
              isPasteButtonFocused={d.focus.kind === "field" && fields[d.focus.index]?.id === "name" && d.focus.onPaste}
              showPasteButton
              onChange={(name) => setDialog({ ...d, name })}
            />
          ) : null}
          <FormField
            label="Value"
            value={d.value}
            mask="*"
            isFieldFocused={d.focus.kind === "field" && fields[d.focus.index]?.id === "value" && !d.focus.onPaste}
            isPasteButtonFocused={d.focus.kind === "field" && fields[d.focus.index]?.id === "value" && d.focus.onPaste}
            showPasteButton
            onChange={(value) => setDialog({ ...d, value })}
            hint={`hidden · ${String(d.value.length)} chars`}
          />
        </Dialog>
      );
    }
    if (d.kind === "delete") {
      const actions: readonly ToolbarButton[] = [
        { label: "Cancel" },
        { label: "Delete", variant: "danger" },
      ];
      return (
        <Dialog
          title="Delete this secret?"
          description={`${d.name} from ${d.scope} scope will be permanently deleted.`}
          actions={actions}
          focusedAction={d.focus.kind === "actions" ? d.focus.index : 1}
          actionsFocused
          onAction={(index) => handleDialogAction(d, index)}
        />
      );
    }
    if (d.kind === "bulk") {
      const title = "Bulk import secrets";
      if (d.preview === null) {
        const lines = d.buffer.split(/\r?\n/u).filter((line) => line.length > 0).length;
        const hasBuffer = d.buffer.length > 0;
        const actions: readonly ToolbarButton[] = [
          { label: "Cancel" },
          { label: hasBuffer ? "Preview" : "Paste from clipboard" },
        ];
        return (
          <Dialog
            title={title}
            description={`scope: ${d.scope} (↑/↓ to toggle)`}
            actions={actions}
            focusedAction={d.focus.kind === "actions" ? d.focus.index : 1}
            actionsFocused
            errorText={d.error}
            onAction={(index) => handleDialogAction(d, index)}
          >
            <Text color={theme.dim}>
              {String(lines)} lines captured ({String(d.buffer.length)} chars, hidden)
            </Text>
          </Dialog>
        );
      }
      const actions: readonly ToolbarButton[] = [
        { label: "Cancel" },
        { label: "Import", variant: "success" },
      ];
      return (
        <Dialog
          title={title}
          description={`${String(d.preview.added.length)} to add, ${String(d.preview.skipped.length)} skipped · scope: ${d.scope}`}
          actions={actions}
          focusedAction={d.focus.kind === "actions" ? d.focus.index : 1}
          actionsFocused
          errorText={d.error}
          onAction={(index) => handleDialogAction(d, index)}
        >
          {d.preview.added.map((entry) => (
            <Text key={`add:${String(entry.line)}:${entry.name}`} color={theme.text}>
              add {entry.name}
            </Text>
          ))}
          {d.preview.skipped.map((skip) => (
            <Text key={`skip:${String(skip.line)}`} color={theme.dim}>
              line {String(skip.line)}: {skip.reason}
            </Text>
          ))}
        </Dialog>
      );
    }
    if (d.kind === "policy") {
      if (d.awaitingConfirm) {
        const actions: readonly ToolbarButton[] = [
          { label: "Cancel" },
          { label: "Keep editing" },
          { label: "Save anyway", variant: "danger" },
        ];
        return (
          <Dialog
            title="Wildcard policy detected"
            description={`Enabling a wildcarded policy broadens what the agent can do with secret ${d.targetName}. Continue?`}
            actions={actions}
            focusedAction={d.focus.kind === "actions" ? d.focus.index : 1}
            actionsFocused
            onAction={(index) => handleDialogAction(d, index)}
          />
        );
      }
      const preview = buildPolicyFromDialog(d);
      const badges = policyBadgeTokens(preview instanceof Error ? undefined : preview);
      const actions: readonly ToolbarButton[] = [
        { label: "Cancel" },
        { label: "Save", variant: "success" },
      ];
      const isField = (id: string): boolean =>
        d.focus.kind === "field" && policyDialogFields[d.focus.index]?.id === id;
      return (
        <Dialog
          title={`Edit policy for ${d.targetName}`}
          description="hosts/env: comma-separated · commands: binary|allowed1,allowed2|forbidden1 ; next"
          actions={actions}
          focusedAction={d.focus.kind === "actions" ? d.focus.index : 0}
          actionsFocused={d.focus.kind === "actions"}
          errorText={d.error}
          onAction={(index) => handleDialogAction(d, index)}
        >
          <Text color={theme.dim}>
            Preview badges: <Text color={theme.warning}>{badges.join(" ") || "none"}</Text>
          </Text>
          <FormField
            label="Allowed HTTP hosts"
            value={d.hostsText}
            isFieldFocused={isField("hosts")}
            isPasteButtonFocused={false}
            showPasteButton={false}
            onChange={(hostsText) => setDialog({ ...d, hostsText })}
          />
          <FormField
            label="Allowed commands"
            value={d.commandsText}
            isFieldFocused={isField("commands")}
            isPasteButtonFocused={false}
            showPasteButton={false}
            onChange={(commandsText) => setDialog({ ...d, commandsText })}
          />
          <FormField
            label="Allowed env vars"
            value={d.envText}
            isFieldFocused={isField("env")}
            isPasteButtonFocused={false}
            showPasteButton={false}
            onChange={(envText) => setDialog({ ...d, envText })}
          />
          <FormField
            label="Rate limit requests"
            value={d.requestsText}
            isFieldFocused={isField("requests")}
            isPasteButtonFocused={false}
            showPasteButton={false}
            onChange={(requestsText) => setDialog({ ...d, requestsText })}
          />
          <FormField
            label="Rate limit window seconds"
            value={d.windowText}
            isFieldFocused={isField("window")}
            isPasteButtonFocused={false}
            showPasteButton={false}
            onChange={(windowText) => setDialog({ ...d, windowText })}
          />
        </Dialog>
      );
    }
    // filter
    if (d.kind !== "filter") {
      return <Text color={theme.dim}>unknown dialog</Text>;
    }
    const actions: readonly ToolbarButton[] = [
      { label: "Cancel" },
      { label: "Apply", variant: "success" },
    ];
    return (
      <Dialog
        title={`Filter ${d.target}`}
        description={
          d.target === "audit"
            ? "Use secret:NAME, surface:NAME, status:allowed|denied, or plain text."
            : "Match secrets by name."
        }
        actions={actions}
        focusedAction={d.focus.kind === "actions" ? d.focus.index : 0}
        actionsFocused={d.focus.kind === "actions"}
        onAction={(index) => handleDialogAction(d, index)}
      >
        <FormField
          label="Query"
          value={d.value}
          isFieldFocused={d.focus.kind === "field"}
          isPasteButtonFocused={false}
          showPasteButton={false}
          onChange={(value) => setDialog({ ...d, value })}
        />
      </Dialog>
    );
  }
}

export interface RunTuiOptions {
  readonly services?: TuiServices;
  readonly stdin?: NodeJS.ReadStream;
  readonly stdout?: NodeJS.WriteStream;
  readonly stderr?: NodeJS.WriteStream;
  readonly processRef?: { on: typeof process.on; off: typeof process.off };
}

export async function runTuiApp(deps: CliDeps, options: RunTuiOptions = {}): Promise<void> {
  const stdin = options.stdin ?? process.stdin;
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const instance = render(<TuiApp deps={deps} services={options.services ?? createDefaultTuiServices()} />, {
    stdin,
    stdout,
    stderr,
    exitOnCtrlC: false,
  });
  if (stdout.isTTY === true) {
    enableMouse(stdout);
  }
  const lifecycle = installTerminalLifecycle({
    stdin,
    processRef: options.processRef ?? process,
    onSignal: () => instance.unmount(),
    beforeSignal: () => {
      if (stdout.isTTY === true) {
        disableMouse(stdout);
      }
    },
  });
  try {
    await instance.waitUntilExit();
  } finally {
    if (stdout.isTTY === true) {
      disableMouse(stdout);
    }
    lifecycle.restore();
  }
}
