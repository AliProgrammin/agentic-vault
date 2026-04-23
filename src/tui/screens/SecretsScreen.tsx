import { Box, Text } from "ink";
import type { ReactElement } from "react";
import type { Policy } from "../../policy/index.js";
import { policyBadgeTokens } from "../app-exports.js";
import { theme } from "../theme.js";
import { Menu, type MenuItem } from "../components/Menu.js";
import { Toolbar, type ToolbarButton } from "../components/Toolbar.js";

interface SecretRow {
  readonly name: string;
  readonly scope: "global" | "project";
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly policy?: Policy;
}

interface SecretsScreenProps {
  readonly secrets: readonly SecretRow[];
  readonly selectedIndex: number;
  readonly filter: string;
  readonly selectedSecret: SecretRow | null;
  readonly bodyFocused: boolean;
  readonly toolbarFocused: boolean;
  readonly toolbarIndex: number;
  readonly toolbarButtons: readonly ToolbarButton[];
  readonly onRowClick?: (index: number) => void;
  readonly onScroll?: (delta: number) => void;
  readonly onToolbarClick?: (index: number) => void;
}

export function SecretsScreen(props: SecretsScreenProps): ReactElement {
  const { secrets, selectedIndex, filter, selectedSecret } = props;
  const items: readonly MenuItem[] = secrets.map((secret, index) => {
    const badges = policyBadgeTokens(secret.policy);
    const updated = secret.updatedAt.slice(0, 10);
    return {
      label: `${secret.name.padEnd(30)}  ${secret.scope.padEnd(10)}${updated.padEnd(12)}`,
      value: `${secret.scope}:${secret.name}:${String(index)}`,
      ...(badges.length > 0 ? { trailing: badges } : {}),
    };
  });

  return (
    <Box flexDirection="column" paddingX={1} gap={1}>
      <Box flexDirection="row" gap={1}>
        <Box
          borderStyle="round"
          borderColor={props.bodyFocused ? theme.borderActive : theme.border}
          backgroundColor={theme.backgroundPanel}
          flexDirection="column"
          flexGrow={1}
        >
          <Box paddingX={1}>
            <Text color={theme.primary} bold>Secrets</Text>
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
              {"NAME".padEnd(30)}
              {"  "}
              {"SCOPE".padEnd(10)}
              {"UPDATED".padEnd(12)}
              POLICY
            </Text>
          </Box>
          <Menu
            items={items}
            selectedIndex={selectedIndex}
            isFocused={props.bodyFocused}
            emptyText="No secrets yet. Focus the toolbar and press Enter on Add secret to create one."
            idPrefix="secrets"
            {...(props.onRowClick !== undefined ? { onItemClick: props.onRowClick } : {})}
            {...(props.onScroll !== undefined ? { onScroll: props.onScroll } : {})}
          />
        </Box>

        <Box
          borderStyle="round"
          borderColor={theme.border}
          backgroundColor={theme.backgroundPanel}
          flexDirection="column"
          paddingX={1}
          width={38}
        >
          <Text color={theme.primary} bold>Detail</Text>
          {selectedSecret !== null ? (
            <>
              <Text bold color={theme.text}>{selectedSecret.name}</Text>
              <Text color={theme.textMuted}>scope: {selectedSecret.scope}</Text>
              <Text color={theme.textMuted}>
                created: {selectedSecret.createdAt.slice(0, 10)}
              </Text>
              <Text color={theme.textMuted}>
                updated: {selectedSecret.updatedAt.slice(0, 10)}
              </Text>
              <Text color={theme.textMuted}>Value: hidden</Text>
              {policyBadgeTokens(selectedSecret.policy).length > 0 ? (
                <Text color={theme.warning}>
                  {policyBadgeTokens(selectedSecret.policy).join(" ")}
                </Text>
              ) : null}
            </>
          ) : (
            <Text color={theme.textMuted}>No secret selected.</Text>
          )}
        </Box>
      </Box>

      <Toolbar
        buttons={props.toolbarButtons}
        focused={props.toolbarFocused}
        focusedIndex={props.toolbarIndex}
        idPrefix="secrets-tb"
        {...(props.onToolbarClick !== undefined ? { onButtonClick: props.onToolbarClick } : {})}
      />
    </Box>
  );
}
