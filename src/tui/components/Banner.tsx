import { Box, Text } from "ink";
import type { ReactElement } from "react";
import { theme } from "../theme.js";

// Pre-rendered figlet "ANSI Shadow" output. Inlined as strings so the bundle
// doesn't have to ship figlet's runtime + font files. Regenerate with:
//   node -e "const f=require('figlet'); console.log(JSON.stringify(f.textSync('AGENTIC',{font:'ANSI Shadow'})))"
export const AGENTIC = " █████╗  ██████╗ ███████╗███╗   ██╗████████╗██╗ ██████╗\n██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██║██╔════╝\n███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ██║██║     \n██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ██║██║     \n██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ██║╚██████╗\n╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝ ╚═════╝";
export const VAULT = "██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗\n██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝\n██║   ██║███████║██║   ██║██║     ██║   \n╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   \n ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   \n  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ";

// Print the banner directly to stdout (used after the TUI exits and the
// alt-screen has been restored, so the user sees a branded signature
// in their shell scrollback). Peach #fab283, dim grey #808080 — same
// theme tokens the TUI uses. Truecolor (24-bit) escape codes; modern
// terminals all support them.
export function printExitSignature(stdout: NodeJS.WriteStream): void {
  const peach = "\x1b[38;2;250;178;131m";
  const dim = "\x1b[38;2;128;128;128m";
  const reset = "\x1b[0m";
  stdout.write("\n");
  for (const line of AGENTIC.split("\n")) {
    stdout.write(`${peach}${line}${reset}\n`);
  }
  for (const line of VAULT.split("\n")) {
    stdout.write(`${peach}${line}${reset}\n`);
  }
  stdout.write(`\n  ${dim}by madhoob.dev${reset}\n\n`);
}

export function Banner(): ReactElement {
  return (
    <Box flexDirection="column" alignItems="flex-start">
      {AGENTIC.split("\n").map((line, i) => (
        <Text key={`a:${String(i)}`} color={theme.primary}>{line}</Text>
      ))}
      {VAULT.split("\n").map((line, i) => (
        <Text key={`v:${String(i)}`} color={theme.primary}>{line}</Text>
      ))}
      <Box marginTop={1} paddingLeft={1}>
        <Text color={theme.textMuted}>by madhoob.dev</Text>
      </Box>
    </Box>
  );
}
