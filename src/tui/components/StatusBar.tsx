import { Box, Text } from "ink";
import type { ReactElement } from "react";
import { theme } from "../theme.js";

type Screen = "dashboard" | "secrets" | "audit" | "policies";

const HINTS: Record<Screen, string> = {
  dashboard: "/ home  s secrets  u audit  p policies  ? help  q quit",
  secrets: "a add  A bulk  r rotate  d delete  e policy  c copy  / filter",
  audit: "j/k move  Enter detail  / filter  Esc back",
  policies: "j/k move  e edit  Esc back",
};

interface StatusBarProps {
  readonly screen: Screen;
  readonly mcpOnline?: boolean;
}

export function StatusBar(props: StatusBarProps): ReactElement {
  const hint = HINTS[props.screen];
  return (
    <Box justifyContent="space-between">
      <Text color={theme.accent} bold>Agentic Vault</Text>
      <Text color={theme.dim}>{hint}</Text>
      {props.mcpOnline !== undefined ? (
        <Text color={props.mcpOnline ? "green" : "red"}>
          {props.mcpOnline ? "● MCP online" : "○ MCP offline"}
        </Text>
      ) : null}
    </Box>
  );
}
