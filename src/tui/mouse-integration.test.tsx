import { describe, expect, it, vi } from "vitest";
import { render } from "ink-testing-library";
import { act } from "react-test-renderer";
import { Text, useInput } from "ink";
import type { ReactElement } from "react";
import {
  createMouseRegistry,
  MouseProvider,
  type MouseContextValue,
} from "./MouseContext.js";
import { parseSgrMouse } from "./mouse.js";

// Minimal harness: mirrors the TuiApp's input-router branch that routes
// SGR mouse sequences to the MouseContext dispatcher. This is the exact
// seam TuiApp uses — proving the wire works end-to-end without pulling in
// the whole vault.
function MouseHarness(props: {
  readonly mouse: MouseContextValue;
}): ReactElement {
  useInput((input) => {
    const mouseEvent = parseSgrMouse(input);
    if (mouseEvent === null) {
      return;
    }
    if (mouseEvent.kind === "press") {
      props.mouse.dispatchClick(mouseEvent.col, mouseEvent.row);
    } else if (mouseEvent.kind === "scrollUp") {
      props.mouse.dispatchScroll(mouseEvent.col, mouseEvent.row, -1);
    } else if (mouseEvent.kind === "scrollDown") {
      props.mouse.dispatchScroll(mouseEvent.col, mouseEvent.row, 1);
    }
  });
  return <Text>ready</Text>;
}

describe("TUI mouse integration", () => {
  it("routes an SGR mouse press through Ink's useInput to the dispatcher", async () => {
    const onClick = vi.fn();
    const registry = createMouseRegistry();
    registry.register({
      id: "target",
      fromCol: 0,
      toCol: 20,
      fromRow: 0,
      toRow: 2,
      onClick,
    });
    const app = render(
      <MouseProvider value={registry}>
        <MouseHarness mouse={registry} />
      </MouseProvider>,
    );
    await act(async () => {
      await new Promise((r) => setTimeout(r, 20));
    });
    await act(async () => {
      app.stdin.write("\x1b[<0;5;1M");
      await new Promise((r) => setTimeout(r, 20));
    });
    expect(onClick).toHaveBeenCalledTimes(1);
    app.unmount();
  });

  it("routes a scroll-down wheel event to the dispatcher with delta=+1", async () => {
    const onScroll = vi.fn();
    const registry = createMouseRegistry();
    registry.register({
      id: "list",
      fromCol: 0,
      toCol: 80,
      fromRow: 0,
      toRow: 20,
      onScroll,
    });
    const app = render(
      <MouseProvider value={registry}>
        <MouseHarness mouse={registry} />
      </MouseProvider>,
    );
    await act(async () => {
      await new Promise((r) => setTimeout(r, 20));
    });
    await act(async () => {
      app.stdin.write("\x1b[<65;10;10M");
      await new Promise((r) => setTimeout(r, 20));
    });
    expect(onScroll).toHaveBeenCalledWith(1);
    app.unmount();
  });
});
