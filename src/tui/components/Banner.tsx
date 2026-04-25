import { Box, Text } from "ink";
import BigText from "ink-big-text";
import type { ReactElement } from "react";
import { theme } from "../theme.js";

// Two-line ASCII banner — fits inside an 80-col terminal because the cfonts
// `3d` font is roughly 7 cols per glyph. "AGENTIC VAULT" on one line would
// overflow.
export function Banner(): ReactElement {
  return (
    <Box flexDirection="column" alignItems="flex-start">
      <BigText text="AGENTIC" font="huge" colors={[theme.primary]} space={false} />
      <BigText text="VAULT" font="huge" colors={[theme.primary]} space={false} />
      <Box marginTop={1} paddingLeft={1}>
        <Text color={theme.textMuted}>by madhoob.dev</Text>
      </Box>
    </Box>
  );
}
