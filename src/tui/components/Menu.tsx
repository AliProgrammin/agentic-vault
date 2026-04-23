import { Box, Text } from "ink";
import type { ReactElement } from "react";
import { theme } from "../theme.js";

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
}

export function Menu<V extends string = string>(props: MenuProps<V>): ReactElement {
  if (props.items.length === 0) {
    return (
      <Box paddingX={1}>
        <Text color={theme.dim}>{props.emptyText ?? "No items."}</Text>
      </Box>
    );
  }
  return (
    <Box flexDirection="column">
      {props.items.map((item, index) => {
        const isSelected = index === props.selectedIndex;
        const indicator = isSelected ? "▶ " : "  ";
        if (isSelected && props.isFocused) {
          return (
            <Box key={`menu:${String(index)}:${item.value}`} paddingX={1}>
              <Text color={theme.accent} bold>
                {indicator}
                {item.label}
                {item.detail !== undefined ? `  ${item.detail}` : ""}
                {item.trailing !== undefined && item.trailing.length > 0
                  ? `  ${item.trailing.join(" ")}`
                  : ""}
              </Text>
            </Box>
          );
        }
        if (isSelected) {
          return (
            <Box key={`menu:${String(index)}:${item.value}`} paddingX={1}>
              <Text color={theme.text} bold>
                {indicator}
                {item.label}
                {item.detail !== undefined ? `  ${item.detail}` : ""}
                {item.trailing !== undefined && item.trailing.length > 0
                  ? `  ${item.trailing.join(" ")}`
                  : ""}
              </Text>
            </Box>
          );
        }
        return (
          <Box key={`menu:${String(index)}:${item.value}`} paddingX={1}>
            <Text color={theme.text}>
              {indicator}
              {item.label}
              {item.detail !== undefined ? `  ${item.detail}` : ""}
              {item.trailing !== undefined && item.trailing.length > 0
                ? `  ${item.trailing.join(" ")}`
                : ""}
            </Text>
          </Box>
        );
      })}
    </Box>
  );
}
