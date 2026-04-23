import { Box, Text } from "ink";
import { Fragment, type ReactElement } from "react";
import { theme } from "../theme.js";

export interface HelpHint {
  readonly key: string;
  readonly label: string;
}

interface HelpBarProps {
  readonly hints: readonly HelpHint[];
}

export function HelpBar(props: HelpBarProps): ReactElement {
  return (
    <Box paddingX={1}>
      <Text color={theme.dim}>
        {props.hints.map((hint, index) => (
          <Fragment key={`${hint.key}:${hint.label}`}>
            {index > 0 ? "  ·  " : ""}
            <Text color={theme.text}>{hint.key}</Text>
            {" "}
            {hint.label}
          </Fragment>
        ))}
      </Text>
    </Box>
  );
}
