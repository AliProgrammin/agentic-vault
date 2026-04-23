import { Box, Text } from "ink";
import type { ReactElement } from "react";
import { theme } from "../theme.js";

export const TAB_LABELS = ["Dashboard", "Secrets", "Audit", "Policies"] as const;

interface TabBarProps {
  readonly activeIndex: number;
  readonly focusedIndex: number;
  readonly isFocused: boolean;
}

export function TabBar(props: TabBarProps): ReactElement {
  return (
    <Box flexDirection="row" paddingX={1}>
      <Text color={theme.accent} bold>
        {"Agentic Vault  "}
      </Text>
      {TAB_LABELS.map((label, index) => {
        const isActive = index === props.activeIndex;
        const isFocused = props.isFocused && index === props.focusedIndex;
        // Three visual states:
        //   active + focused → bright blue bg + "▸ label ◂" chevrons (you're on this tab AND arrow cursor is here)
        //   active only      → accentMuted bg (this is the current screen)
        //   focused only     → surfaceElevated bg (arrow cursor is here, Enter to activate)
        //   neither          → dim text
        if (isActive && isFocused) {
          return (
            <Text key={label} backgroundColor={theme.accent} color="white" bold>
              {` ▸ ${label} ◂ `}
            </Text>
          );
        }
        if (isActive) {
          return (
            <Text key={label} backgroundColor={theme.accentMuted} color="white" bold>
              {`  ${label}  `}
            </Text>
          );
        }
        if (isFocused) {
          return (
            <Text key={label} backgroundColor={theme.surfaceElevated} color={theme.text} bold>
              {`  ${label}  `}
            </Text>
          );
        }
        return (
          <Text key={label} color={theme.dim}>
            {`  ${label}  `}
          </Text>
        );
      })}
    </Box>
  );
}
