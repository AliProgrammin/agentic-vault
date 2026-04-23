import { Box, Text } from "ink";
import type { ReactElement, ReactNode } from "react";
import { theme } from "../theme.js";
import { Toolbar, type ToolbarButton } from "./Toolbar.js";

interface DialogProps {
  readonly title: string;
  readonly description?: string;
  readonly children?: ReactNode;
  readonly actions: readonly ToolbarButton[];
  readonly focusedAction: number;
  readonly actionsFocused: boolean;
  readonly errorText?: string | null;
}

export function Dialog(props: DialogProps): ReactElement {
  return (
    <Box
      borderStyle="round"
      borderColor={theme.border}
      flexDirection="column"
      padding={1}
      marginTop={1}
    >
      <Text color={theme.accent} bold>
        {props.title}
      </Text>
      {props.description !== undefined ? (
        <Text color={theme.dim}>{props.description}</Text>
      ) : null}
      {props.children !== undefined ? (
        <Box flexDirection="column" marginTop={1}>
          {props.children}
        </Box>
      ) : null}
      {props.errorText !== undefined && props.errorText !== null ? (
        <Box marginTop={1}>
          <Text color={theme.danger}>{props.errorText}</Text>
        </Box>
      ) : null}
      <Box marginTop={1}>
        <Toolbar
          buttons={props.actions}
          focused={props.actionsFocused}
          focusedIndex={props.focusedAction}
        />
      </Box>
    </Box>
  );
}
