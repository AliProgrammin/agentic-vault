import { Box, Text } from "ink";
import { useCallback, type ReactElement } from "react";
import { Button } from "./Button.js";
import { theme } from "../theme.js";
import { useHitZone } from "../MouseContext.js";

export interface ToolbarButton {
  readonly label: string;
  readonly variant?: "default" | "danger" | "success";
  readonly disabled?: boolean;
}

interface ToolbarProps {
  readonly buttons: readonly ToolbarButton[];
  readonly focused: boolean;
  readonly focusedIndex: number;
  readonly onButtonClick?: (index: number) => void;
  readonly idPrefix?: string;
}

interface ToolbarItemProps {
  readonly index: number;
  readonly button: ToolbarButton;
  readonly isFocused: boolean;
  readonly onButtonClick?: (index: number) => void;
  readonly idPrefix: string;
}

function ToolbarItem(props: ToolbarItemProps): ReactElement {
  const { index, button } = props;
  const onClick = useCallback(() => props.onButtonClick?.(index), [index, props]);
  const enabled = props.onButtonClick !== undefined && button.disabled !== true;
  const ref = useHitZone(`${props.idPrefix}:${button.label}`, { onClick, enabled });
  return (
    <Box flexDirection="row">
      {index > 0 ? <Text> </Text> : null}
      <Box ref={ref}>
        <Button
          label={button.label}
          focused={props.isFocused}
          {...(button.variant !== undefined ? { variant: button.variant } : {})}
          {...(button.disabled !== undefined ? { disabled: button.disabled } : {})}
        />
      </Box>
    </Box>
  );
}

export function Toolbar(props: ToolbarProps): ReactElement {
  const idPrefix = props.idPrefix ?? "tb";
  return (
    <Box flexDirection="row" backgroundColor={theme.backgroundPanel} paddingX={1}>
      {props.buttons.map((button, index) => (
        <ToolbarItem
          key={`${idPrefix}:${String(index)}:${button.label}`}
          index={index}
          button={button}
          isFocused={props.focused && index === props.focusedIndex}
          idPrefix={idPrefix}
          {...(props.onButtonClick !== undefined ? { onButtonClick: props.onButtonClick } : {})}
        />
      ))}
    </Box>
  );
}
