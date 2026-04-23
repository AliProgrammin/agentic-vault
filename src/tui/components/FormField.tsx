import { Box, Text } from "ink";
import TextInput from "ink-text-input";
import type { ReactElement } from "react";
import { theme } from "../theme.js";
import { Button } from "./Button.js";

interface FormFieldProps {
  readonly label: string;
  readonly value: string;
  readonly mask?: string;
  readonly isFieldFocused: boolean;
  readonly isPasteButtonFocused: boolean;
  readonly showPasteButton: boolean;
  readonly onChange: (value: string) => void;
  readonly hint?: string;
}

export function FormField(props: FormFieldProps): ReactElement {
  return (
    <Box flexDirection="column" marginBottom={1}>
      <Text color={props.isFieldFocused ? theme.accent : theme.dim}>
        {props.label}
      </Text>
      <Box flexDirection="row">
        <Box flexGrow={1}>
          <TextInput
            focus={props.isFieldFocused}
            value={props.value}
            {...(props.mask !== undefined ? { mask: props.mask } : {})}
            onChange={props.onChange}
          />
        </Box>
        {props.showPasteButton ? (
          <Box marginLeft={1}>
            <Button
              label="Paste"
              focused={props.isPasteButtonFocused}
            />
          </Box>
        ) : null}
      </Box>
      {props.hint !== undefined ? (
        <Text color={theme.dim}>{props.hint}</Text>
      ) : null}
    </Box>
  );
}
