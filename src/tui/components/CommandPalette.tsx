import { Box, Text } from "ink";
import TextInput from "ink-text-input";
import type { ReactElement } from "react";
import { theme } from "../theme.js";
import { Menu, type MenuItem } from "./Menu.js";

export interface PaletteCommand {
  readonly id: string;
  readonly label: string;
  readonly description?: string;
}

interface CommandPaletteProps {
  readonly query: string;
  readonly onQueryChange: (value: string) => void;
  readonly commands: readonly PaletteCommand[];
  readonly selectedIndex: number;
  readonly onItemClick?: (index: number) => void;
}

function matchesQuery(command: PaletteCommand, query: string): boolean {
  if (query.length === 0) {
    return true;
  }
  const lowered = query.toLowerCase();
  return (
    command.label.toLowerCase().includes(lowered) ||
    (command.description ?? "").toLowerCase().includes(lowered)
  );
}

export function filterCommands(
  commands: readonly PaletteCommand[],
  query: string,
): readonly PaletteCommand[] {
  return commands.filter((c) => matchesQuery(c, query));
}

export function CommandPalette(props: CommandPaletteProps): ReactElement {
  const filtered = filterCommands(props.commands, props.query);
  const items: readonly MenuItem[] = filtered.map((command) => ({
    label: command.label,
    value: command.id,
    ...(command.description !== undefined ? { detail: command.description } : {}),
  }));
  return (
    <Box
      borderStyle="round"
      borderColor={theme.borderActive}
      backgroundColor={theme.backgroundPanel}
      flexDirection="column"
      padding={1}
      marginTop={1}
    >
      <Text color={theme.primary} bold>Command palette</Text>
      <Box marginTop={1}>
        <Text color={theme.textMuted}>Search: </Text>
        <TextInput value={props.query} focus onChange={props.onQueryChange} />
      </Box>
      <Box marginTop={1} flexDirection="column">
        <Menu
          items={items}
          selectedIndex={props.selectedIndex}
          isFocused
          emptyText="No matching commands."
          idPrefix="palette"
          {...(props.onItemClick !== undefined ? { onItemClick: props.onItemClick } : {})}
        />
      </Box>
    </Box>
  );
}
