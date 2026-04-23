import { Text } from "ink";
import type { ReactElement } from "react";
import { theme } from "../theme.js";

export interface ButtonProps {
  readonly label: string;
  readonly focused: boolean;
  readonly variant?: "default" | "danger" | "success";
  readonly disabled?: boolean;
}

export function Button(props: ButtonProps): ReactElement {
  const variant = props.variant ?? "default";
  const label = `  ${props.label}  `;
  if (props.disabled === true) {
    return (
      <Text backgroundColor={theme.surface} color={theme.dim}>
        {label}
      </Text>
    );
  }
  if (props.focused) {
    const bg =
      variant === "danger"
        ? theme.danger
        : variant === "success"
          ? theme.success
          : theme.accent;
    return (
      <Text backgroundColor={bg} color="white" bold>
        {label}
      </Text>
    );
  }
  return (
    <Text backgroundColor={theme.surfaceElevated} color={theme.text}>
      {label}
    </Text>
  );
}
