// Single source of truth for the TUI keyboard model.
//
// Every focusable zone (tabs, body, toolbar, palette) and every dialog
// declares its bindings here. The help bar derives its hints from this
// registry, and the input-router code in app.tsx is structured so that
// every advertised key actually has a real handler.
//
// The truthfulness test in app.test.tsx checks both directions:
//   - every key listed in `getHelpHints(zone)` produces an observable
//     effect when dispatched into a freshly-rendered TUI in that zone;
//   - the registry includes every key actually handled in that zone (no
//     hidden keybindings). The router code in app.tsx is written so this
//     property holds.
//
// Keys are described by a small symbolic vocabulary (`KeySymbol`) that
// maps both to a printable label for the help bar and to a matcher over
// Ink's `(input, key)` pair. Adding a new binding here is the only place
// you need to touch — provided the corresponding handler in app.tsx
// already calls one of the listed symbols, the help bar updates
// automatically.

import type { HelpHint } from "./components/HelpBar.js";

export type KeySymbol =
  | "up"
  | "down"
  | "left"
  | "right"
  | "tab"
  | "enter"
  | "esc"
  | "ctrl+k"
  | "ctrl+t"
  | "ctrl+c";

export interface InkKey {
  readonly upArrow?: boolean;
  readonly downArrow?: boolean;
  readonly leftArrow?: boolean;
  readonly rightArrow?: boolean;
  readonly tab?: boolean;
  readonly return?: boolean;
  readonly escape?: boolean;
  readonly ctrl?: boolean;
}

export function matchesKey(symbol: KeySymbol, input: string, key: InkKey): boolean {
  switch (symbol) {
    case "up":
      return key.upArrow === true;
    case "down":
      return key.downArrow === true;
    case "left":
      return key.leftArrow === true;
    case "right":
      return key.rightArrow === true;
    case "tab":
      return key.tab === true;
    case "enter":
      return key.return === true;
    case "esc":
      return key.escape === true;
    case "ctrl+k":
      return key.ctrl === true && input === "k";
    case "ctrl+t":
      return key.ctrl === true && input === "t";
    case "ctrl+c":
      return key.ctrl === true && input === "c";
    default:
      return false;
  }
}

export const SYMBOL_LABELS: Readonly<Record<KeySymbol, string>> = {
  up: "↑",
  down: "↓",
  left: "←",
  right: "→",
  tab: "Tab",
  enter: "Enter",
  esc: "Esc",
  "ctrl+k": "Ctrl+K",
  "ctrl+t": "Ctrl+T",
  "ctrl+c": "Ctrl+C",
};

export interface Binding {
  /** The key symbols that all trigger this binding (e.g. `["up", "down"]`). */
  readonly keys: readonly KeySymbol[];
  /** Short description shown in the help bar (e.g. "move", "buttons"). */
  readonly label: string;
  /**
   * Optional grouping label for the help bar — e.g. ↑↓ are shown as one
   * combined entry "↑↓ move" rather than two separate entries. If omitted,
   * `keys` is used directly.
   */
  readonly displayKeys?: string;
}

export type ZoneId =
  | "tabs"
  | "body"
  | "toolbar"
  | "palette"
  | "dialog:add"
  | "dialog:rotate"
  | "dialog:delete"
  | "dialog:bulk"
  | "dialog:filter"
  | "dialog:policy"
  | "dialog:policy-confirm"
  | "audit-detail";

const TABS: readonly Binding[] = [
  { keys: ["left", "right"], label: "tab", displayKeys: "←→" },
  { keys: ["enter"], label: "open" },
  { keys: ["down", "tab"], label: "focus body", displayKeys: "↓/Tab" },
  { keys: ["ctrl+k"], label: "palette" },
  { keys: ["ctrl+c"], label: "quit" },
];

const BODY: readonly Binding[] = [
  { keys: ["up", "down"], label: "move", displayKeys: "↑↓" },
  { keys: ["enter"], label: "select" },
  { keys: ["down"], label: "actions", displayKeys: "↓" },
  { keys: ["up"], label: "tabs", displayKeys: "↑" },
  { keys: ["esc"], label: "back" },
  { keys: ["ctrl+t"], label: "tabs" },
  { keys: ["ctrl+k"], label: "palette" },
];

const TOOLBAR: readonly Binding[] = [
  { keys: ["left", "right"], label: "button", displayKeys: "←→" },
  { keys: ["enter"], label: "activate" },
  { keys: ["up"], label: "list", displayKeys: "↑" },
  { keys: ["tab"], label: "tabs" },
  { keys: ["ctrl+t"], label: "tabs" },
  { keys: ["esc"], label: "back" },
];

const PALETTE: readonly Binding[] = [
  { keys: ["up", "down"], label: "move", displayKeys: "↑↓" },
  { keys: ["enter"], label: "run" },
  { keys: ["esc"], label: "close" },
];

// Dialog bindings — applied uniformly across all six dialogs. The
// "↑/↓ fields, ←/→ buttons, Tab as ↓" model is the same everywhere.
const DIALOG_NAV_FIELDS_AND_BUTTONS: readonly Binding[] = [
  { keys: ["up", "down"], label: "field", displayKeys: "↑↓" },
  { keys: ["left", "right"], label: "button", displayKeys: "←→" },
  { keys: ["tab"], label: "next" },
  { keys: ["enter"], label: "confirm" },
  { keys: ["esc"], label: "cancel" },
  { keys: ["ctrl+t"], label: "tabs" },
];

// Bulk dialog has no fields (it's a paste-buffer + actions), but we
// still advertise ↑/↓ because they toggle scope when on the actions row.
const DIALOG_BULK: readonly Binding[] = [
  { keys: ["up", "down"], label: "scope", displayKeys: "↑↓" },
  { keys: ["left", "right"], label: "button", displayKeys: "←→" },
  { keys: ["tab"], label: "next" },
  { keys: ["enter"], label: "confirm" },
  { keys: ["esc"], label: "cancel" },
  { keys: ["ctrl+t"], label: "tabs" },
];

// Delete dialog has no fields either; ↑/↓ are documented no-ops that
// just stay on the actions row (so there's no silent dead key — the
// help bar simply doesn't advertise ↑/↓).
const DIALOG_DELETE: readonly Binding[] = [
  { keys: ["left", "right"], label: "button", displayKeys: "←→" },
  { keys: ["tab"], label: "next" },
  { keys: ["enter"], label: "confirm" },
  { keys: ["esc"], label: "cancel" },
  { keys: ["ctrl+t"], label: "tabs" },
];

const DIALOG_POLICY_CONFIRM: readonly Binding[] = [
  { keys: ["left", "right"], label: "button", displayKeys: "←→" },
  { keys: ["enter"], label: "confirm" },
  { keys: ["esc"], label: "back" },
  { keys: ["ctrl+t"], label: "tabs" },
];

const AUDIT_DETAIL: readonly Binding[] = [
  { keys: ["up", "down"], label: "move", displayKeys: "↑↓" },
  { keys: ["left"], label: "back", displayKeys: "←" },
  { keys: ["esc"], label: "back" },
  { keys: ["ctrl+t"], label: "tabs" },
];

const REGISTRY: Readonly<Record<ZoneId, readonly Binding[]>> = {
  tabs: TABS,
  body: BODY,
  toolbar: TOOLBAR,
  palette: PALETTE,
  "dialog:add": DIALOG_NAV_FIELDS_AND_BUTTONS,
  "dialog:rotate": DIALOG_NAV_FIELDS_AND_BUTTONS,
  "dialog:delete": DIALOG_DELETE,
  "dialog:bulk": DIALOG_BULK,
  "dialog:filter": DIALOG_NAV_FIELDS_AND_BUTTONS,
  "dialog:policy": DIALOG_NAV_FIELDS_AND_BUTTONS,
  "dialog:policy-confirm": DIALOG_POLICY_CONFIRM,
  "audit-detail": AUDIT_DETAIL,
};

export function getBindings(zone: ZoneId): readonly Binding[] {
  return REGISTRY[zone];
}

export function getHelpHints(zone: ZoneId): readonly HelpHint[] {
  const bindings = REGISTRY[zone];
  return bindings.map((binding) => ({
    key: binding.displayKeys ?? binding.keys.map((k) => SYMBOL_LABELS[k]).join("/"),
    label: binding.label,
  }));
}

/**
 * Returns true if the registry advertises the given key symbol for the
 * given zone. Used by the truthfulness test to enumerate bindings.
 */
export function bindingMatchesSymbol(binding: Binding, symbol: KeySymbol): boolean {
  return binding.keys.includes(symbol);
}

/**
 * Enumerate every (zone, symbol) pair declared in the registry. The
 * truthfulness test iterates this list and asserts each one fires.
 */
export function enumerateBindings(): readonly { zone: ZoneId; symbol: KeySymbol; label: string }[] {
  const out: { zone: ZoneId; symbol: KeySymbol; label: string }[] = [];
  for (const zone of Object.keys(REGISTRY) as ZoneId[]) {
    for (const binding of REGISTRY[zone]) {
      for (const symbol of binding.keys) {
        out.push({ zone, symbol, label: binding.label });
      }
    }
  }
  return out;
}
