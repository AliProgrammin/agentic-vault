import { Box, Text } from "ink";
import type { ReactElement } from "react";
import type { Policy } from "../../policy/index.js";
import { policyBadgeTokens } from "../app.js";
import { theme } from "../theme.js";

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
  readonly selected: number;
  readonly selectedSecret: SecretRow | null;
  readonly policyView: PolicyView;
  readonly strictMode: boolean;
}

export function PoliciesScreen(props: PoliciesScreenProps): ReactElement {
  const { secrets, selected, selectedSecret, policyView, strictMode } = props;

  return (
    <Box flexDirection="column" gap={1}>
      {strictMode ? (
        <Text color="yellow">strict mode is enabled for this vault; wildcard saves are rejected</Text>
      ) : null}

      <Box borderStyle="round" flexDirection="column">
        <Box paddingX={1} flexDirection="row">
          <Text bold color={theme.dim}>{"NAME".padEnd(32)}</Text>
          <Text bold color={theme.dim}>{"SCOPE".padEnd(10)}</Text>
          <Text bold color={theme.dim}>POLICY</Text>
        </Box>
        {secrets.map((secret, index) => {
          const isSelected = index === selected;
          const badges = policyBadgeTokens(secret.policy).join(" ");
          return (
            <Box key={`policy:${secret.scope}:${secret.name}`} paddingX={1}>
              {isSelected ? (
                <Text color={theme.accent}>
                  {"▶ "}
                  {secret.name.slice(0, 30).padEnd(30)}{"  "}
                  {secret.scope.padEnd(10)}
                  {badges}
                </Text>
              ) : (
                <Text>
                  {"  "}
                  {secret.name.slice(0, 30).padEnd(30)}{"  "}
                  {secret.scope.padEnd(10)}
                  {badges}
                </Text>
              )}
            </Box>
          );
        })}
      </Box>

      {selectedSecret !== null ? (
        <Box borderStyle="round" flexDirection="column" padding={1}>
          <Text bold>Policy for {selectedSecret.name}</Text>
          <Text color={theme.dim}>Allowed HTTP hosts</Text>
          {policyView.hosts.length > 0
            ? policyView.hosts.map((host) => <Text key={`host:${host}`}>  {host}</Text>)
            : <Text color={theme.dim}>  none</Text>}
          <Text color={theme.dim}>Allowed commands</Text>
          {policyView.commands.length > 0
            ? policyView.commands.map((command) => <Text key={`cmd:${command}`}>  {command}</Text>)
            : <Text color={theme.dim}>  none</Text>}
          <Text color={theme.dim}>Allowed env vars</Text>
          {policyView.envs.length > 0
            ? policyView.envs.map((env) => <Text key={`env:${env}`}>  {env}</Text>)
            : <Text color={theme.dim}>  none</Text>}
          <Text color={theme.dim}>Rate limit: <Text>{policyView.rate}</Text></Text>
        </Box>
      ) : null}
    </Box>
  );
}
