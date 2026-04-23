import { Box, Text } from "ink";
import type { ReactElement } from "react";
import { Button } from "./Button.js";

export interface ToolbarButton {
  readonly label: string;
  readonly variant?: "default" | "danger" | "success";
  readonly disabled?: boolean;
}

interface ToolbarProps {
  readonly buttons: readonly ToolbarButton[];
  readonly focused: boolean;
  readonly focusedIndex: number;
}

export function Toolbar(props: ToolbarProps): ReactElement {
  return (
    <Box flexDirection="row">
      {props.buttons.map((button, index) => (
        <Box key={`tb:${String(index)}:${button.label}`} flexDirection="row">
          {index > 0 ? <Text> </Text> : null}
          <Button
            label={button.label}
            focused={props.focused && index === props.focusedIndex}
            {...(button.variant !== undefined ? { variant: button.variant } : {})}
            {...(button.disabled !== undefined ? { disabled: button.disabled } : {})}
          />
        </Box>
      ))}
    </Box>
  );
}
