export const ENABLE_SGR_MOUSE = "\x1b[?1006h";
export const ENABLE_MOUSE_TRACKING = "\x1b[?1000h";
export const DISABLE_MOUSE_TRACKING = "\x1b[?1000l";
export const DISABLE_SGR_MOUSE = "\x1b[?1006l";
// Alt screen buffer — switches to a fresh screen that starts at (1,1).
// Must be entered BEFORE Ink's first render so content paints into the
// alt buffer (and at terminal row 1) instead of the shell scrollback.
// Mouse coordinates also rely on this: yoga is (0,0)-origin and terminal
// mouse events are (1,1)-origin, so alt-screen + subtract-1 maps cleanly.
export const ENABLE_ALT_SCREEN = "\x1b[?1049h";
export const DISABLE_ALT_SCREEN = "\x1b[?1049l";

export function enableAltScreen(stdout: NodeJS.WriteStream): void {
  stdout.write(ENABLE_ALT_SCREEN);
}

export function disableAltScreen(stdout: NodeJS.WriteStream): void {
  stdout.write(DISABLE_ALT_SCREEN);
}

export function enableMouse(stdout: NodeJS.WriteStream): void {
  stdout.write(ENABLE_MOUSE_TRACKING);
  stdout.write(ENABLE_SGR_MOUSE);
}

export function disableMouse(stdout: NodeJS.WriteStream): void {
  stdout.write(DISABLE_SGR_MOUSE);
  stdout.write(DISABLE_MOUSE_TRACKING);
}

export interface MouseEvent {
  readonly kind: "press" | "release" | "scrollUp" | "scrollDown";
  readonly button: "left" | "middle" | "right" | "none";
  readonly col: number;
  readonly row: number;
}

// Parse an SGR mouse report. Accepts either the full sequence
// `ESC [ < Cb ; Cx ; Cy (M|m)` or the body `[< Cb ; Cx ; Cy (M|m)`
// (Ink strips the leading ESC before useInput fires).
// Returns null if the input is not a valid, complete mouse sequence.
export function parseSgrMouse(data: string): MouseEvent | null {
  if (data.length === 0) {
    return null;
  }
  let i = 0;
  if (data.charCodeAt(0) === 0x1b) {
    i = 1;
  }
  if (data.charCodeAt(i) !== 0x5b /* [ */) {
    return null;
  }
  i += 1;
  if (data.charCodeAt(i) !== 0x3c /* < */) {
    return null;
  }
  i += 1;
  const rest = data.slice(i);
  const match = /^(\d+);(\d+);(\d+)([Mm])$/u.exec(rest);
  if (match === null) {
    return null;
  }
  const cb = Number(match[1]);
  const col = Number(match[2]);
  const row = Number(match[3]);
  const terminator = match[4];
  if (!Number.isFinite(cb) || !Number.isFinite(col) || !Number.isFinite(row)) {
    return null;
  }
  if (cb === 64) {
    return { kind: "scrollUp", button: "none", col, row };
  }
  if (cb === 65) {
    return { kind: "scrollDown", button: "none", col, row };
  }
  const low = cb & 0x03;
  const button = low === 0 ? "left" : low === 1 ? "middle" : low === 2 ? "right" : "none";
  if (button === "none") {
    return null;
  }
  return {
    kind: terminator === "M" ? "press" : "release",
    button,
    col,
    row,
  };
}
