import { describe, expect, it, vi } from "vitest";
import { createMouseRegistry, type HitZone } from "./MouseContext.js";

function zone(partial: Partial<HitZone> & { readonly id: string }): HitZone {
  return {
    fromCol: 0,
    toCol: 10,
    fromRow: 0,
    toRow: 1,
    ...partial,
  };
}

describe("createMouseRegistry", () => {
  it("dispatches a click to the registered zone containing the point", () => {
    const r = createMouseRegistry();
    const onClick = vi.fn();
    r.register(zone({ id: "a", fromCol: 5, toCol: 15, fromRow: 2, toRow: 3, onClick }));
    expect(r.dispatchClick(7, 2)).toBe(true);
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it("ignores clicks outside any zone", () => {
    const r = createMouseRegistry();
    const onClick = vi.fn();
    r.register(zone({ id: "a", fromCol: 0, toCol: 5, fromRow: 0, toRow: 1, onClick }));
    expect(r.dispatchClick(10, 0)).toBe(false);
    expect(onClick).not.toHaveBeenCalled();
  });

  it("treats toCol/toRow as exclusive bounds", () => {
    const r = createMouseRegistry();
    const onClick = vi.fn();
    r.register(zone({ id: "a", fromCol: 0, toCol: 5, fromRow: 0, toRow: 2, onClick }));
    // (5, 0) is just outside the exclusive toCol=5.
    expect(r.dispatchClick(5, 0)).toBe(false);
    expect(r.dispatchClick(4, 1)).toBe(true);
  });

  it("dispatches scroll to the zone under the cursor", () => {
    const r = createMouseRegistry();
    const onScroll = vi.fn();
    r.register(zone({ id: "list", fromCol: 0, toCol: 80, fromRow: 5, toRow: 20, onScroll }));
    r.dispatchScroll(10, 10, 1);
    r.dispatchScroll(10, 10, -1);
    expect(onScroll).toHaveBeenNthCalledWith(1, 1);
    expect(onScroll).toHaveBeenNthCalledWith(2, -1);
  });

  it("later registrations win when zones overlap (topmost)", () => {
    const r = createMouseRegistry();
    const under = vi.fn();
    const over = vi.fn();
    r.register(zone({ id: "under", fromCol: 0, toCol: 10, onClick: under }));
    r.register(zone({ id: "over", fromCol: 5, toCol: 10, onClick: over }));
    r.dispatchClick(7, 0);
    expect(over).toHaveBeenCalled();
    expect(under).not.toHaveBeenCalled();
  });

  it("unregister removes a zone", () => {
    const r = createMouseRegistry();
    const onClick = vi.fn();
    r.register(zone({ id: "a", onClick }));
    r.unregister("a");
    expect(r.dispatchClick(0, 0)).toBe(false);
    expect(onClick).not.toHaveBeenCalled();
  });
});
