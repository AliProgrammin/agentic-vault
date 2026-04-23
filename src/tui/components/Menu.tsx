import { Box, Text } from "ink";
import { useCallback, type ReactElement } from "react";
import { theme } from "../theme.js";
import { useHitZone } from "../MouseContext.js";

export interface MenuItem<V extends string = string> {
  readonly label: string;
  readonly value: V;
  readonly detail?: string;
  readonly trailing?: readonly string[];
}

interface MenuProps<V extends string = string> {
  readonly items: readonly MenuItem<V>[];
  readonly selectedIndex: number;
  readonly isFocused: boolean;
  readonly emptyText?: string;
  readonly onItemClick?: (index: number) => void;
  readonly onScroll?: (delta: number) => void;
  readonly idPrefix?: string;
}

function itemText<V extends string>(item: MenuItem<V>, indicator: string): string {
  const detail = item.detail !== undefined ? `  ${item.detail}` : "";
  const trailing = item.trailing !== undefined && item.trailing.length > 0
    ? `  ${item.trailing.join(" ")}`
    : "";
  return `${indicator}${item.label}${detail}${trailing}`;
}

interface RowProps<V extends string> {
  readonly item: MenuItem<V>;
  readonly index: number;
  readonly isSelected: boolean;
  readonly isFocused: boolean;
  readonly onItemClick?: (index: number) => void;
  readonly idPrefix: string;
}

function Row<V extends string>(props: RowProps<V>): ReactElement {
  const { item, index, isSelected, isFocused } = props;
  const onClick = useCallback(() => props.onItemClick?.(index), [index, props]);
  const ref = useHitZone(`${props.idPrefix}:row:${String(index)}`, {
    onClick,
    enabled: props.onItemClick !== undefined,
  });
  const indicator = isSelected ? "▶ " : "  ";
  const text = itemText(item, indicator);
  if (isSelected && isFocused) {
    return (
      <Box ref={ref} paddingX={1} flexGrow={1} backgroundColor={theme.primary}>
        <Text color={theme.background} bold>{text}</Text>
      </Box>
    );
  }
  if (isSelected) {
    return (
      <Box ref={ref} paddingX={1} flexGrow={1} backgroundColor={theme.backgroundElement}>
        <Text color={theme.text} bold>{text}</Text>
      </Box>
    );
  }
  return (
    <Box ref={ref} paddingX={1}>
      <Text color={theme.text}>{text}</Text>
    </Box>
  );
}

export function Menu<V extends string = string>(props: MenuProps<V>): ReactElement {
  const idPrefix = props.idPrefix ?? "menu";
  // A container-level scroll hit zone captures wheel events anywhere over the list.
  const onScroll = useCallback(
    (delta: number) => props.onScroll?.(delta),
    [props],
  );
  const scrollRef = useHitZone(`${idPrefix}:scroll`, {
    onScroll,
    enabled: props.onScroll !== undefined,
  });
  if (props.items.length === 0) {
    return (
      <Box paddingX={1}>
        <Text color={theme.textMuted}>{props.emptyText ?? "No items."}</Text>
      </Box>
    );
  }
  return (
    <Box ref={scrollRef} flexDirection="column">
      {props.items.map((item, index) => (
        <Row
          key={`${idPrefix}:${String(index)}:${item.value}`}
          item={item}
          index={index}
          isSelected={index === props.selectedIndex}
          isFocused={props.isFocused}
          idPrefix={idPrefix}
          {...(props.onItemClick !== undefined ? { onItemClick: props.onItemClick } : {})}
        />
      ))}
    </Box>
  );
}
