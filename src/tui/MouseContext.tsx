import { createContext, useContext, useLayoutEffect, useMemo, useRef, type ReactElement, type ReactNode } from "react";
import { measureElement, type DOMElement } from "ink";

export interface HitZone {
  readonly id: string;
  readonly fromCol: number;
  readonly toCol: number;      // exclusive
  readonly fromRow: number;
  readonly toRow: number;      // exclusive
  readonly onClick?: () => void;
  readonly onScroll?: (delta: number) => void;
}

export interface MouseContextValue {
  register(zone: HitZone): void;
  unregister(id: string): void;
  dispatchClick(col: number, row: number): boolean;
  dispatchScroll(col: number, row: number, delta: number): boolean;
}

const MouseContext = createContext<MouseContextValue | null>(null);

export function useMouse(): MouseContextValue | null {
  return useContext(MouseContext);
}

// Creates a dispatcher backed by an internal zone registry. Exported so tests
// can drive clicks/scrolls directly without rendering a full TUI.
export function createMouseRegistry(): MouseContextValue {
  const zones = new Map<string, HitZone>();
  const findTopmost = (col: number, row: number): HitZone | null => {
    let hit: HitZone | null = null;
    // Later registrations win (simulates "topmost"). Iteration order of Map
    // preserves insertion order.
    for (const zone of zones.values()) {
      if (col >= zone.fromCol && col < zone.toCol && row >= zone.fromRow && row < zone.toRow) {
        hit = zone;
      }
    }
    return hit;
  };
  return {
    register(zone) {
      zones.set(zone.id, zone);
    },
    unregister(id) {
      zones.delete(id);
    },
    dispatchClick(col, row) {
      const zone = findTopmost(col, row);
      if (zone?.onClick !== undefined) {
        zone.onClick();
        return true;
      }
      return false;
    },
    dispatchScroll(col, row, delta) {
      const zone = findTopmost(col, row);
      if (zone?.onScroll !== undefined) {
        zone.onScroll(delta);
        return true;
      }
      return false;
    },
  };
}

interface MouseProviderProps {
  readonly value: MouseContextValue;
  readonly children: ReactNode;
}

export function MouseProvider(props: MouseProviderProps): ReactElement {
  return <MouseContext.Provider value={props.value}>{props.children}</MouseContext.Provider>;
}

// Compute the absolute (col, row) of a rendered Ink node by summing
// computed-left/top offsets up the yoga tree.
function computeAbsoluteRect(
  node: DOMElement,
): { readonly col: number; readonly row: number; readonly width: number; readonly height: number } | null {
  const { width, height } = measureElement(node);
  if (width === 0 && height === 0) {
    return null;
  }
  let col = 0;
  let row = 0;
  let current: DOMElement | undefined = node;
  while (current !== undefined) {
    const yoga = current.yogaNode;
    if (yoga !== undefined) {
      col += yoga.getComputedLeft();
      row += yoga.getComputedTop();
    }
    current = current.parentNode;
  }
  return { col: Math.round(col), row: Math.round(row), width, height };
}

interface UseHitZoneOptions {
  readonly onClick?: () => void;
  readonly onScroll?: (delta: number) => void;
  readonly enabled?: boolean;
  readonly deps?: readonly unknown[];
}

export function useHitZone(
  id: string,
  options: UseHitZoneOptions,
): React.RefObject<DOMElement | null> {
  const ref = useRef<DOMElement | null>(null);
  const mouse = useMouse();
  const enabled = options.enabled !== false;
  const deps = options.deps ?? [];
  useLayoutEffect(() => {
    if (!enabled || mouse === null || ref.current === null) {
      return;
    }
    const rect = computeAbsoluteRect(ref.current);
    if (rect === null) {
      return;
    }
    const zone: HitZone = {
      id,
      fromCol: rect.col,
      toCol: rect.col + rect.width,
      fromRow: rect.row,
      toRow: rect.row + rect.height,
      ...(options.onClick !== undefined ? { onClick: options.onClick } : {}),
      ...(options.onScroll !== undefined ? { onScroll: options.onScroll } : {}),
    };
    mouse.register(zone);
    return () => mouse.unregister(id);
  }, [mouse, id, enabled, options.onClick, options.onScroll, ...deps]);
  return ref;
}

// Helper for tests and for the app to hold a stable dispatcher across re-renders.
export function useMouseRegistry(): MouseContextValue {
  return useMemo(() => createMouseRegistry(), []);
}
