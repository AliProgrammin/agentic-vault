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
  // Caret marker for focused buttons. The marker is part of the visible
  // label so screen-buffer assertions can detect it; it pairs with the
  // bold weight already applied below for a "caret + bold" indicator.
  const label = props.focused ? `▶ ${props.label}  ` : `  ${props.label}  `;
  if (props.disabled === true) {
    return (
      <Text backgroundColor={theme.backgroundPanel} color={theme.textMuted}>
        {`  ${props.label}  `}
      </Text>
    );
  }
  if (props.focused) {
    if (variant === "danger") {
      return (
        <Text backgroundColor={theme.danger} color="white" bold>
          {label}
        </Text>
      );
    }
    if (variant === "success") {
      return (
        <Text backgroundColor={theme.success} color={theme.background} bold>
          {label}
        </Text>
      );
    }
    return (
      <Text backgroundColor={theme.primary} color={theme.background} bold>
        {label}
      </Text>
    );
  }
  return (
    <Text backgroundColor={theme.backgroundElement} color={theme.text}>
      {label}
    </Text>
  );
}
