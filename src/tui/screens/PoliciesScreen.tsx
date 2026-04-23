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

interface PolicyView {
  readonly hosts: readonly string[];
  readonly commands: readonly string[];
  readonly envs: readonly string[];
  readonly rate: string;
}

interface PoliciesScreenProps {
  readonly secrets: readonly SecretRow[];
  readonly selectedIndex: number;
  readonly selectedSecret: SecretRow | null;
  readonly policyView: PolicyView;
  readonly strictMode: boolean;
  readonly bodyFocused: boolean;
  readonly toolbarFocused: boolean;
  readonly toolbarIndex: number;
  readonly toolbarButtons: readonly ToolbarButton[];
  readonly onRowClick?: (index: number) => void;
  readonly onScroll?: (delta: number) => void;
  readonly onToolbarClick?: (index: number) => void;
}

export function PoliciesScreen(props: PoliciesScreenProps): ReactElement {
  const { secrets, selectedIndex, selectedSecret, policyView, strictMode } = props;
  const items: readonly MenuItem[] = secrets.map((secret, index) => {
    const badges = policyBadgeTokens(secret.policy);
    return {
      label: `${secret.name.padEnd(30)}  ${secret.scope.padEnd(10)}`,
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
          <Box paddingX={1}>
            <Text color={theme.textMuted} bold>
              {"  "}
              {"NAME".padEnd(30)}
              {"  "}
              {"SCOPE".padEnd(10)}
              POLICY
            </Text>
          </Box>
          <Menu
            items={items}
            selectedIndex={selectedIndex}
            isFocused={props.bodyFocused}
            emptyText="No secrets."
            idPrefix="policies"
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
          width={48}
        >
          {strictMode ? (
            <Text color={theme.warning}>
              ⚠ Strict mode: wildcards rejected
            </Text>
          ) : null}
          <Text color={theme.primary} bold>
            {selectedSecret !== null
              ? `Policy for ${selectedSecret.name}`
              : "Policy"}
          </Text>
          {selectedSecret !== null ? (
            <>
              <Text color={theme.textMuted}>Allowed HTTP hosts</Text>
              {policyView.hosts.length > 0 ? (
                policyView.hosts.map((host) => (
                  <Text key={`host:${host}`} color={theme.text}>
                    {"  "}
                    {host}
                  </Text>
                ))
              ) : (
                <Text color={theme.textMuted}>  none</Text>
              )}
              <Text color={theme.textMuted}>Allowed commands</Text>
              {policyView.commands.length > 0 ? (
                policyView.commands.map((command) => (
                  <Text key={`cmd:${command}`} color={theme.text}>
                    {"  "}
                    {command}
                  </Text>
                ))
              ) : (
                <Text color={theme.textMuted}>  none</Text>
              )}
              <Text color={theme.textMuted}>Allowed env vars</Text>
              {policyView.envs.length > 0 ? (
                policyView.envs.map((env) => (
                  <Text key={`env:${env}`} color={theme.text}>
                    {"  "}
                    {env}
                  </Text>
                ))
              ) : (
                <Text color={theme.textMuted}>  none</Text>
              )}
              <Text color={theme.textMuted}>
                Rate limit: <Text color={theme.text}>{policyView.rate}</Text>
              </Text>
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
        idPrefix="policies-tb"
        {...(props.onToolbarClick !== undefined ? { onButtonClick: props.onToolbarClick } : {})}
      />
    </Box>
  );
}
