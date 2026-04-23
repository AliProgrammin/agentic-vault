import { Box, Text } from "ink";
import type { ReactElement } from "react";
import { theme } from "../theme.js";

interface ToastProps {
  readonly kind: "success" | "error" | "info";
  readonly text: string;
}

export function Toast(props: ToastProps): ReactElement {
  const color =
    props.kind === "error"
      ? theme.danger
      : props.kind === "success"
        ? theme.success
        : theme.accent;
  return (
    <Box paddingX={1}>
      <Text backgroundColor={theme.surfaceElevated} color={color}>
        {`  ${props.text}  `}
      </Text>
    </Box>
  );
}
