// SecretProxy TUI.
//
// Uses Ink for the terminal UI and `clipboardy` for clipboard reads/writes.
// Clipboard-backed secret values are never rendered back to the terminal:
// value inputs are masked, bulk-import buffers stay hidden, and the state slot
// is cleared immediately after save (with a second best-effort clear on a
// 2-second timer because JS strings cannot be zeroized reliably in memory).
//
// The dashboard's MCP indicator uses a lightweight `ps` process scan rather
// than a pidfile because the existing `secretproxy run` command does not yet
// emit one. The audit-detail panel and policy wildcard badges both reuse the
// shared F13/F14 render helpers so the TUI cannot drift from the CLI/UI.

import { execFile } from "node:child_process";
import { promises as fs, watch as fsWatch } from "node:fs";
import * as path from "node:path";
import { promisify } from "node:util";
import clipboard from "clipboardy";
import { Box, render, Text, useApp, useInput } from "ink";
import TextInput from "ink-text-input";
import { useEffect, useMemo, useRef, useState, type ReactElement } from "react";
import {
  buildRenderModel,
  readAuditEntries,
  type AuditEvent,
  type BuildRenderOptions,
  type RenderModel,
} from "../audit/index.js";
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
import { parseBulkSecretInput, type BulkImportPreview } from "./bulk-import.js";
import { installTerminalLifecycle } from "./runtime.js";
import { StatusBar } from "./components/StatusBar.js";
import { DashboardScreen } from "./screens/DashboardScreen.js";
import { SecretsScreen } from "./screens/SecretsScreen.js";
import { AuditScreen } from "./screens/AuditScreen.js";
import { PoliciesScreen } from "./screens/PoliciesScreen.js";
import { theme } from "./theme.js";

const execFileAsync = promisify(execFile);
const UI_PORT = 7381;

type Screen = "dashboard" | "secrets" | "audit" | "policies";
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

interface MessageState {
  readonly kind: "error" | "info";
  readonly text: string;
}

interface AddDialogState {
  readonly kind: "add" | "rotate";
  readonly scope: ScopeChoice;
  readonly name: string;
  readonly value: string;
  readonly focus: "name" | "value";
}

interface BulkDialogState {
  readonly kind: "bulk";
  readonly buffer: string;
  readonly preview: BulkImportPreview | null;
  readonly scope: ScopeChoice;
}

interface DeleteDialogState {
  readonly kind: "delete";
  readonly name: string;
  readonly scope: ScopeChoice;
}

interface PolicyDialogState {
  readonly kind: "policy";
  readonly hostsText: string;
  readonly commandsText: string;
  readonly envText: string;
  readonly requestsText: string;
  readonly windowText: string;
  readonly focus: "hosts" | "commands" | "env" | "requests" | "window";
  readonly awaitingConfirm: boolean;
}

type DialogState =
  | AddDialogState
  | BulkDialogState
  | DeleteDialogState
  | PolicyDialogState;

interface FilterState {
  readonly screen: "secrets" | "audit";
  readonly value: string;
}

interface PaletteState {
  readonly selected: number;
}

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
  for (const entry of listMerged({ global: session.global?.handle ?? null, project: session.project?.handle ?? null })) {
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

function collectWildcardKinds(entries: readonly PolicyEntry[]): readonly string[] {
  const tokens = new Set<string>();
  for (const entry of entries) {
    if (isWildcardEntry(entry)) {
      tokens.add(wildcardBadge(entry.wildcard_kind, { tty: false }));
    }
  }
  return [...tokens];
}

export function policyBadgeTokens(policy: Policy | undefined): readonly string[] {
  if (policy === undefined) {
    return [];
  }
  const tokens = new Set<string>();
  for (const token of collectWildcardKinds(policy.allowed_http_hosts)) tokens.add(token);
  for (const command of policy.allowed_commands) {
    for (const token of collectWildcardKinds([command.binary])) tokens.add(token);
  }
  for (const token of collectWildcardKinds(policy.allowed_env_vars)) tokens.add(token);
  return [...tokens];
}

function hasWildcardPolicy(policy: Policy | undefined): boolean {
  return policyBadgeTokens(policy).length > 0;
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

function findSelectedSecret(
  snapshot: Snapshot | null,
  filter: string,
  selected: number,
): SecretRow | null {
  if (snapshot === null) {
    return null;
  }
  const rows = snapshot.secrets.filter((secret) => secret.name.toLowerCase().includes(filter.toLowerCase()));
  return rows[selected] ?? rows[0] ?? null;
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

function policyToDialogState(policy: Policy | null): PolicyDialogState {
  return {
    kind: "policy",
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
    focus: "hosts",
    awaitingConfirm: false,
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
}

function getSecretValue(session: TuiSession, secret: SecretRow): string | undefined {
  const handle = secret.scope === "global" ? session.global?.handle : session.project?.handle;
  return handle?.get(secret.name);
}

export function buildAuditDetailModelForTui(
  event: AuditEvent,
  opts: BuildRenderOptions = {},
): RenderModel {
  return buildRenderModel(event, opts);
}

function HelpOverlay(): ReactElement {
  const lines = [
    "/ dashboard",
    "s secrets",
    "u audit",
    "p policies",
    "? help",
    ": command palette",
    "j/k move",
    "a add",
    "A bulk add",
    "r rotate",
    "d delete",
    "e edit policy",
    "c copy secret name",
    "o open local UI",
    "Esc back",
    "q quit",
  ];
  return (
    <Box borderStyle="round" flexDirection="column" padding={1}>
      <Text bold color={theme.accent}>Help</Text>
      {lines.map((line) => (
        <Text key={line} color={theme.dim}>{line}</Text>
      ))}
    </Box>
  );
}

function PaletteOverlay(props: { readonly selected: number }): ReactElement {
  const items = ["Dashboard", "Secrets", "Audit", "Policies"];
  return (
    <Box borderStyle="round" flexDirection="column" padding={1}>
      <Text bold color={theme.accent}>Command palette</Text>
      {items.map((item, index) => (
        index === props.selected ? (
          <Text key={item} color={theme.accent}>{"▶ "}{item}</Text>
        ) : (
          <Text key={item}>{"  "}{item}</Text>
        )
      ))}
    </Box>
  );
}

export function TuiApp(props: AppProps): ReactElement {
  const { exit } = useApp();
  const [screen, setScreen] = useState<Screen>("dashboard");
  const [session, setSession] = useState<TuiSession | null>(null);
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [unlock, setUnlock] = useState<{ value: string; error: string | null; hasVault: boolean } | null>(null);
  const [message, setMessage] = useState<MessageState | null>(null);
  const [dialog, setDialog] = useState<DialogState | null>(null);
  const [filter, setFilter] = useState<FilterState | null>(null);
  const [showHelp, setShowHelp] = useState(false);
  const [palette, setPalette] = useState<PaletteState | null>(null);
  const [selectedSecret, setSelectedSecret] = useState(0);
  const [selectedAudit, setSelectedAudit] = useState(0);
  const [auditDetail, setAuditDetail] = useState(false);
  const zeroizeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const secretFilter = filter?.screen === "secrets" ? filter.value : "";
  const auditFilter = filter?.screen === "audit" ? filter.value : "";
  const selectedSecretRow = findSelectedSecret(snapshot, secretFilter, selectedSecret);
  const filteredAudit = useMemo(
    () => filterAuditEntriesForTui(snapshot?.audit ?? [], auditFilter),
    [snapshot, auditFilter],
  );
  const selectedAuditEntry = filteredAudit[selectedAudit] ?? filteredAudit[0] ?? null;

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
          setUnlock({ value: "", error: null, hasVault });
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

  const saveSingleSecret = async (): Promise<void> => {
    if (session === null || dialog === null || (dialog.kind !== "add" && dialog.kind !== "rotate")) {
      return;
    }
    const target = await ensureScopeHandle(props.deps, session, dialog.scope);
    const nextValue = dialog.value.replace(/[\r\n]+$/u, "");
    const existingPolicy = target.handle.getRecord(dialog.name)?.policy;
    target.handle.set(dialog.name, nextValue, existingPolicy);
    await target.handle.save();
    await refresh(session);
    clearSecretValue();
    setDialog(null);
    setMessage({ kind: "info", text: `${dialog.kind === "add" ? "added" : "rotated"} ${dialog.name}` });
  };

  const saveBulkPreview = async (): Promise<void> => {
    if (session === null || dialog === null || dialog.kind !== "bulk" || dialog.preview === null) {
      return;
    }
    const target = await ensureScopeHandle(props.deps, session, dialog.scope);
    for (const entry of dialog.preview.added) {
      target.handle.set(entry.name, entry.value.replace(/[\r\n]+$/u, ""), target.handle.getRecord(entry.name)?.policy);
    }
    await target.handle.save();
    await refresh(session);
    clearBulkBuffer();
    setDialog(null);
    setMessage({
      kind: "info",
      text: `${String(dialog.preview.added.length)} secrets added, ${String(dialog.preview.skipped.length)} skipped`,
    });
  };

  const savePolicyDraft = async (confirmed: boolean): Promise<void> => {
    if (session === null || dialog === null || dialog.kind !== "policy" || selectedSecretRow === null) {
      return;
    }
    const target = selectedSecretRow.scope === "global" ? session.global : session.project;
    if (target === null) {
      return;
    }
    const draftPolicy = buildPolicyFromDialog(dialog);
    if (draftPolicy instanceof Error) {
      setMessage({ kind: "error", text: draftPolicy.message });
      return;
    }
    const validated = validatePolicy(draftPolicy, { strictMode: target.handle.getStrictMode() });
    if (validated instanceof Error) {
      setMessage({ kind: "error", text: validated.message });
      return;
    }
    if (!confirmed && hasWildcardPolicy(validated)) {
      setDialog({ ...dialog, awaitingConfirm: true });
      return;
    }
    const value = getSecretValue(session, selectedSecretRow);
    if (value === undefined) {
      setMessage({ kind: "error", text: `secret not found: ${selectedSecretRow.name}` });
      return;
    }
    target.handle.set(selectedSecretRow.name, value, validated);
    await target.handle.save();
    await refresh(session);
    setDialog(null);
    setMessage({ kind: "info", text: `policy updated for ${selectedSecretRow.name}` });
  };

  const deleteSecret = async (): Promise<void> => {
    if (session === null || dialog === null || dialog.kind !== "delete") {
      return;
    }
    const target = dialog.scope === "global" ? session.global : session.project;
    target?.handle.remove(dialog.name);
    await target?.handle.save();
    await refresh(session);
    setDialog(null);
    setMessage({ kind: "info", text: `deleted ${dialog.name}` });
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

  useInput((input, key) => {
    if (key.ctrl === true && input === "c") {
      exit();
      return;
    }
    if (showHelp) {
      if (key.escape || input === "?" || input === "q") {
        setShowHelp(false);
      }
      return;
    }
    if (palette !== null) {
      if (input === "j" || key.downArrow) {
        setPalette({ selected: Math.min(3, palette.selected + 1) });
        return;
      }
      if (input === "k" || key.upArrow) {
        setPalette({ selected: Math.max(0, palette.selected - 1) });
        return;
      }
      if (key.return) {
        setScreen((["dashboard", "secrets", "audit", "policies"] as const)[palette.selected] ?? "dashboard");
        setPalette(null);
        return;
      }
      if (key.escape || input === ":") {
        setPalette(null);
      }
      return;
    }
    if (unlock !== null) {
      if (key.return) {
        void tryUnlock();
      }
      return;
    }
    if (filter !== null) {
      if (key.escape) {
        setFilter(null);
      }
      return;
    }
    if (dialog?.kind === "delete") {
      if (input === "y") {
        void deleteSecret();
      }
      if (input === "n" || key.escape) {
        setDialog(null);
      }
      return;
    }
    if (dialog?.kind === "policy" && dialog.awaitingConfirm) {
      if (input === "y") {
        void savePolicyDraft(true);
      }
      if (input === "n" || key.escape) {
        setDialog({ ...dialog, awaitingConfirm: false });
      }
      return;
    }
    if (dialog?.kind === "bulk") {
      if (dialog.preview !== null) {
        if (key.tab) {
          setDialog({ ...dialog, scope: dialog.scope === "global" ? "project" : "global" });
          return;
        }
        if (key.return) {
          void saveBulkPreview();
          return;
        }
      } else {
        if (key.return) {
          setDialog({ ...dialog, preview: parseBulkSecretInput(dialog.buffer) });
          return;
        }
        if (input === "p") {
          void props.services.clipboard.readText().then((text) => {
            setDialog({ ...dialog, buffer: text, preview: null });
          });
          return;
        }
        if (key.backspace || key.delete) {
          setDialog({ ...dialog, buffer: dialog.buffer.slice(0, -1) });
          return;
        }
        if (key.escape) {
          clearBulkBuffer();
          setDialog(null);
          return;
        }
        if (input.length > 0) {
          setDialog({ ...dialog, buffer: `${dialog.buffer}${input}` });
          return;
        }
      }
      if (key.escape) {
        clearBulkBuffer();
        setDialog(null);
      }
      return;
    }
    if (dialog?.kind === "add" || dialog?.kind === "rotate") {
      if (key.tab) {
        setDialog({ ...dialog, focus: dialog.focus === "name" ? "value" : "name" });
        return;
      }
      if (key.return && dialog.focus === "name") {
        setDialog({ ...dialog, focus: "value" });
        return;
      }
      if (key.return && dialog.focus === "value") {
        void saveSingleSecret();
        return;
      }
      if (input === "p" && dialog.focus === "value") {
        void props.services.clipboard.readText().then((text) => {
          setDialog({ ...dialog, value: text.replace(/[\r\n]+$/u, "") });
        });
        return;
      }
      if (key.escape) {
        clearSecretValue();
        setDialog(null);
      }
      return;
    }
    if (dialog?.kind === "policy") {
      if (key.tab) {
        const order: PolicyDialogState["focus"][] = ["hosts", "commands", "env", "requests", "window"];
        const nextIndex = (order.indexOf(dialog.focus) + 1) % order.length;
        setDialog({ ...dialog, focus: order[nextIndex] ?? "hosts" });
        return;
      }
      if (key.return) {
        void savePolicyDraft(false);
        return;
      }
      if (key.escape) {
        setDialog(null);
      }
      return;
    }
    if (auditDetail) {
      if (input === "j" || key.downArrow) {
        setSelectedAudit((current) => Math.min(filteredAudit.length - 1, current + 1));
        return;
      }
      if (input === "k" || key.upArrow) {
        setSelectedAudit((current) => Math.max(0, current - 1));
        return;
      }
      if (input === "o" && selectedAuditEntry !== null) {
        void props.services.detectUiUrl().then((url) => {
          if (url === null) {
            setMessage({ kind: "info", text: "local UI not detected; start `secretproxy ui`" });
            return;
          }
          void props.services.openExternal(`${url}/#/audit/${selectedAuditEntry.request_id}`);
        });
        return;
      }
      if (key.escape) {
        setAuditDetail(false);
      }
      return;
    }

    if (input === "q") {
      exit();
      return;
    }
    if (input === "?") {
      setShowHelp(true);
      return;
    }
    if (input === ":") {
      setPalette({ selected: 0 });
      return;
    }
    if (input === "s") {
      setScreen("secrets");
      return;
    }
    if (input === "u") {
      setScreen("audit");
      return;
    }
    if (input === "p") {
      setScreen("policies");
      return;
    }
    if (key.escape && screen !== "dashboard") {
      setScreen("dashboard");
      setAuditDetail(false);
      return;
    }
    if (input === "/") {
      if (screen === "secrets") {
        setFilter({ screen: "secrets", value: secretFilter });
      } else if (screen === "audit") {
        setFilter({ screen: "audit", value: auditFilter });
      } else {
        setScreen("dashboard");
      }
      return;
    }
    if (screen === "secrets") {
      if (input === "j" || key.downArrow) {
        setSelectedSecret((current) => current + 1);
        return;
      }
      if (input === "k" || key.upArrow) {
        setSelectedSecret((current) => Math.max(0, current - 1));
        return;
      }
      if (input === "a") {
        setDialog({ kind: "add", scope: selectedSecretRow?.scope ?? "global", name: "", value: "", focus: "name" });
        return;
      }
      if (input === "A") {
        setDialog({ kind: "bulk", buffer: "", preview: null, scope: selectedSecretRow?.scope ?? "global" });
        return;
      }
      if (input === "r" && selectedSecretRow !== null) {
        setDialog({ kind: "rotate", scope: selectedSecretRow.scope, name: selectedSecretRow.name, value: "", focus: "value" });
        return;
      }
      if (input === "d" && selectedSecretRow !== null) {
        setDialog({ kind: "delete", name: selectedSecretRow.name, scope: selectedSecretRow.scope });
        return;
      }
      if (input === "e" && selectedSecretRow !== null) {
        setScreen("policies");
        setDialog(policyToDialogState(getPolicyForSecret(session as TuiSession, selectedSecretRow)));
        return;
      }
      if (input === "c" && selectedSecretRow !== null) {
        void props.services.clipboard.writeText(selectedSecretRow.name).then(() => {
          setMessage({ kind: "info", text: `copied ${selectedSecretRow.name}` });
        });
      }
      return;
    }
    if (screen === "audit") {
      if (input === "j" || key.downArrow) {
        setSelectedAudit((current) => Math.min(filteredAudit.length - 1, current + 1));
        return;
      }
      if (input === "k" || key.upArrow) {
        setSelectedAudit((current) => Math.max(0, current - 1));
        return;
      }
      if (key.return && selectedAuditEntry !== null) {
        setAuditDetail(true);
      }
      return;
    }
    if (screen === "policies") {
      if (input === "j" || key.downArrow) {
        setSelectedSecret((current) => current + 1);
        return;
      }
      if (input === "k" || key.upArrow) {
        setSelectedSecret((current) => Math.max(0, current - 1));
        return;
      }
      if (input === "e" && selectedSecretRow !== null) {
        setDialog(policyToDialogState(getPolicyForSecret(session as TuiSession, selectedSecretRow)));
      }
    }
  });

  if (loading) {
    return <Text color={theme.dim}>Loading...</Text>;
  }
  if (unlock !== null) {
    const isNew = !unlock.hasVault;
    return (
      <Box justifyContent="center" alignItems="center" flexDirection="column">
        <Box borderStyle="round" flexDirection="column" padding={2} width={60}>
          <Text color={theme.accent} bold>{isNew ? "Set Up Agentic Vault" : "Unlock Agentic Vault"}</Text>
          <Text color={theme.dim}>
            {isNew
              ? "No vault found. Enter a new master password to create one (min 12 characters)."
              : "Enter your master password to continue."}
          </Text>
          <TextInput
            value={unlock.value}
            mask="*"
            onChange={(value) => setUnlock({ ...unlock, value })}
            onSubmit={() => {
              void tryUnlock();
            }}
          />
          {unlock.error !== null ? <Text color="red">{unlock.error}</Text> : null}
        </Box>
      </Box>
    );
  }

  const model = selectedAuditEntry !== null ? buildAuditDetailModelForTui(selectedAuditEntry) : null;
  const selectedPolicy = selectedSecretRow !== null ? getPolicyForSecret(session as TuiSession, selectedSecretRow) : null;
  const policyView = formatPolicyForScreen(selectedPolicy);
  const selectedPolicyHandle = selectedSecretRow?.scope === "global" ? session?.global?.handle : session?.project?.handle;
  const secretRows = snapshot?.secrets.filter((secret) => secret.name.toLowerCase().includes(secretFilter.toLowerCase())) ?? [];

  return (
    <Box flexDirection="column">
      <StatusBar screen={screen} {...(snapshot !== null ? { mcpOnline: snapshot.dashboard.mcpOnline } : {})} />
      {message !== null ? <Text color={message.kind === "error" ? "red" : "green"}>{message.text}</Text> : null}

      {screen === "dashboard" && snapshot !== null ? (
        <DashboardScreen dashboard={snapshot.dashboard} audit={snapshot.audit} />
      ) : null}

      {screen === "secrets" ? (
        <SecretsScreen
          secrets={secretRows}
          selected={selectedSecret}
          filter={secretFilter}
          selectedSecret={selectedSecretRow}
        />
      ) : null}

      {screen === "audit" ? (
        <AuditScreen
          entries={filteredAudit}
          selected={selectedAudit}
          filter={auditFilter}
          auditDetail={auditDetail}
          model={model}
        />
      ) : null}

      {screen === "policies" ? (
        <PoliciesScreen
          secrets={secretRows}
          selected={selectedSecret}
          selectedSecret={selectedSecretRow}
          policyView={policyView}
          strictMode={selectedPolicyHandle?.getStrictMode() === true}
        />
      ) : null}

      {filter !== null ? (
        <Box borderStyle="round" flexDirection="column" padding={1}>
          <Text color={theme.accent} bold>Filter {filter.screen}</Text>
          {filter.screen === "audit" ? (
            <Text color={theme.dim}>Use `secret:NAME`, `surface:NAME`, `status:allowed|denied`, or plain text.</Text>
          ) : null}
          <TextInput value={filter.value} onChange={(value) => setFilter({ ...filter, value })} />
        </Box>
      ) : null}

      {dialog?.kind === "add" || dialog?.kind === "rotate" ? (
        <Box borderStyle="round" flexDirection="column" padding={1}>
          <Text color={theme.accent} bold>{dialog.kind === "add" ? "Add secret" : "Rotate secret"}</Text>
          <Text color={theme.dim}>scope: {dialog.scope}</Text>
          <Text color={theme.dim}>Name</Text>
          <TextInput
            focus={dialog.focus === "name"}
            value={dialog.name}
            onChange={(name) => setDialog({ ...dialog, name })}
          />
          <Text color={theme.dim}>Value hidden ({String(dialog.value.length)} chars)</Text>
          <TextInput
            focus={dialog.focus === "value"}
            mask="*"
            value={dialog.value}
            onChange={(value) => setDialog({ ...dialog, value })}
          />
          <Text color={theme.dim}>Press p in the value field to paste from clipboard.</Text>
        </Box>
      ) : null}

      {dialog?.kind === "bulk" ? (
        <Box borderStyle="round" flexDirection="column" padding={1}>
          <Text color={theme.accent} bold>Bulk add</Text>
          {dialog.preview === null ? (
            <>
              <Text color={theme.dim}>
                Hidden buffer: {String(dialog.buffer.split(/\r?\n/u).filter((line) => line.length > 0).length)} lines, {String(dialog.buffer.length)} chars
              </Text>
              <Text color={theme.dim}>Paste with p, then press Enter for a preview.</Text>
            </>
          ) : (
            <>
              <Text color={theme.dim}>
                {String(dialog.preview.added.length)} secrets will be added, {String(dialog.preview.skipped.length)} will be skipped
              </Text>
              <Text color={theme.dim}>scope: {dialog.scope}</Text>
              {dialog.preview.added.map((entry) => (
                <Text key={`add:${String(entry.line)}:${entry.name}`}>add {entry.name}</Text>
              ))}
              {dialog.preview.skipped.map((skip) => (
                <Text key={`skip:${String(skip.line)}`} color={theme.dim}>line {String(skip.line)}: {skip.reason}</Text>
              ))}
            </>
          )}
        </Box>
      ) : null}

      {dialog?.kind === "delete" ? (
        <Box borderStyle="round" flexDirection="column" padding={1}>
          <Text bold>Delete &quot;{dialog.name}&quot; from {dialog.scope}?</Text>
          <Text color={theme.dim}>[y] yes  [n] no</Text>
        </Box>
      ) : null}

      {dialog?.kind === "policy" ? (
        <Box borderStyle="round" flexDirection="column" padding={1}>
          {dialog.awaitingConfirm ? (
            <>
              <Text bold>
                You are enabling a wildcarded policy. This broadens what the agent can do with secret {selectedSecretRow?.name ?? ""}. Continue? y/N
              </Text>
            </>
          ) : (
            <>
              {(() => {
                const previewPolicy = buildPolicyFromDialog(dialog);
                const badges = policyBadgeTokens(previewPolicy instanceof Error ? undefined : previewPolicy);
                return <Text color={theme.dim}>Preview badges: {badges.join(" ") || "none"}</Text>;
              })()}
              <Text color={theme.accent} bold>Edit policy</Text>
              <Text color={theme.dim}>Fields are structured: hosts/env accept comma-separated values; commands use `binary|allowed1,allowed2|forbidden1,forbidden2` separated by `;`.</Text>
              <Text color={dialog.focus === "hosts" ? theme.accent : theme.dim}>Allowed HTTP hosts</Text>
              <TextInput
                focus={dialog.focus === "hosts"}
                value={dialog.hostsText}
                onChange={(hostsText) => setDialog({ ...dialog, hostsText })}
              />
              <Text color={dialog.focus === "commands" ? theme.accent : theme.dim}>Allowed commands</Text>
              <TextInput
                focus={dialog.focus === "commands"}
                value={dialog.commandsText}
                onChange={(commandsText) => setDialog({ ...dialog, commandsText })}
              />
              <Text color={dialog.focus === "env" ? theme.accent : theme.dim}>Allowed env vars</Text>
              <TextInput
                focus={dialog.focus === "env"}
                value={dialog.envText}
                onChange={(envText) => setDialog({ ...dialog, envText })}
              />
              <Text color={dialog.focus === "requests" ? theme.accent : theme.dim}>Rate limit requests</Text>
              <TextInput
                focus={dialog.focus === "requests"}
                value={dialog.requestsText}
                onChange={(requestsText) => setDialog({ ...dialog, requestsText })}
              />
              <Text color={dialog.focus === "window" ? theme.accent : theme.dim}>Rate limit window seconds</Text>
              <TextInput
                focus={dialog.focus === "window"}
                value={dialog.windowText}
                onChange={(windowText) => setDialog({ ...dialog, windowText })}
              />
            </>
          )}
        </Box>
      ) : null}

      {showHelp ? <HelpOverlay /> : null}
      {palette !== null ? <PaletteOverlay selected={palette.selected} /> : null}
    </Box>
  );
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
  const lifecycle = installTerminalLifecycle({
    stdin,
    processRef: options.processRef ?? process,
    onSignal: () => instance.unmount(),
  });
  try {
    await instance.waitUntilExit();
  } finally {
    lifecycle.restore();
  }
}
