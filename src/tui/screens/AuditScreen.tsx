import { Box, Text } from "ink";
import type { ReactElement } from "react";
import { formatAuditDetail, type AuditEvent, type RenderModel } from "../../audit/index.js";
import { theme } from "../theme.js";
import { Menu, type MenuItem } from "../components/Menu.js";
import { Toolbar, type ToolbarButton } from "../components/Toolbar.js";

interface AuditScreenProps {
  readonly entries: readonly AuditEvent[];
  readonly selectedIndex: number;
  readonly filter: string;
  readonly auditDetail: boolean;
  readonly model: RenderModel | null;
  readonly bodyFocused: boolean;
  readonly toolbarFocused: boolean;
  readonly toolbarIndex: number;
  readonly toolbarButtons: readonly ToolbarButton[];
  readonly onRowClick?: (index: number) => void;
  readonly onScroll?: (delta: number) => void;
  readonly onToolbarClick?: (index: number) => void;
}

export function AuditScreen(props: AuditScreenProps): ReactElement {
  const { entries, selectedIndex, filter, auditDetail, model } = props;

  if (auditDetail && model !== null) {
    const lines = formatAuditDetail(model, { tty: false }).trimEnd().split("\n");
    return (
      <Box flexDirection="column" paddingX={1} gap={1}>
        <Box
          borderStyle="round"
          borderColor={theme.border}
          backgroundColor={theme.backgroundPanel}
          flexDirection="column"
          paddingX={1}
        >
          <Text color={theme.primary} bold>Audit detail</Text>
          {lines.map((line, index) => (
            <Text key={`audit-detail:${String(index)}`} color={theme.text}>
              {line}
            </Text>
          ))}
        </Box>
        <Toolbar
          buttons={props.toolbarButtons}
          focused={props.toolbarFocused}
          focusedIndex={props.toolbarIndex}
          idPrefix="audit-tb"
          {...(props.onToolbarClick !== undefined ? { onButtonClick: props.onToolbarClick } : {})}
        />
      </Box>
    );
  }

  const items: readonly MenuItem[] = entries.map((entry, index) => ({
    label: `${entry.outcome === "allowed" ? "✓" : "✗"}  ${entry.ts.padEnd(24)}  ${entry.secret_name.padEnd(22)}  ${entry.target}`,
    value: `${entry.request_id}:${String(index)}`,
  }));

  return (
    <Box flexDirection="column" paddingX={1} gap={1}>
      <Box
        borderStyle="round"
        borderColor={props.bodyFocused ? theme.borderActive : theme.border}
        backgroundColor={theme.backgroundPanel}
        flexDirection="column"
      >
        <Box paddingX={1}>
          <Text color={theme.primary} bold>Audit log</Text>
        </Box>
        {filter.length > 0 ? (
          <Box paddingX={1}>
            <Text color={theme.textMuted}>Filter: </Text>
            <Text color={theme.primary}>{filter}</Text>
          </Box>
        ) : null}
        <Box paddingX={1}>
          <Text color={theme.textMuted} bold>
            {"  "}
            {"OUTCOME".padEnd(8)}
            {"TIMESTAMP".padEnd(26)}
            {"SECRET".padEnd(24)}
            TARGET
          </Text>
        </Box>
        <Menu
          items={items}
          selectedIndex={selectedIndex}
          isFocused={props.bodyFocused}
          emptyText="No audit entries yet."
          idPrefix="audit"
          {...(props.onRowClick !== undefined ? { onItemClick: props.onRowClick } : {})}
          {...(props.onScroll !== undefined ? { onScroll: props.onScroll } : {})}
        />
      </Box>
      <Toolbar
        buttons={props.toolbarButtons}
        focused={props.toolbarFocused}
        focusedIndex={props.toolbarIndex}
        idPrefix="audit-tb"
        {...(props.onToolbarClick !== undefined ? { onButtonClick: props.onToolbarClick } : {})}
      />
    </Box>
  );
}
