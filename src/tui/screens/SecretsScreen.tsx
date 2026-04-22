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

interface SecretsScreenProps {
  readonly secrets: readonly SecretRow[];
  readonly selected: number;
  readonly filter: string;
  readonly selectedSecret: SecretRow | null;
}

export function SecretsScreen(props: SecretsScreenProps): ReactElement {
  const { secrets, selected, filter, selectedSecret } = props;

  return (
    <Box flexDirection="row" gap={1}>
      <Box borderStyle="round" flexDirection="column" flexGrow={1}>
        {filter.length > 0 ? (
          <Box paddingX={1}>
            <Text color={theme.dim}>filter: <Text color={theme.accent}>{filter}</Text></Text>
          </Box>
        ) : null}
        <Box paddingX={1} flexDirection="row">
          <Text bold color={theme.dim}>{"NAME".padEnd(32)}</Text>
          <Text bold color={theme.dim}>{"SCOPE".padEnd(10)}</Text>
          <Text bold color={theme.dim}>{"UPDATED".padEnd(14)}</Text>
          <Text bold color={theme.dim}>POLICY</Text>
        </Box>
        {secrets.length === 0 ? (
          <Box paddingX={1}>
            <Text color={theme.dim}>No secrets. Press a to add one.</Text>
          </Box>
        ) : (
          secrets.map((secret, index) => {
            const isSelected = index === selected;
            const badges = policyBadgeTokens(secret.policy).join(" ");
            const updatedShort = secret.updatedAt.slice(0, 10);
            return (
              <Box key={`${secret.scope}:${secret.name}`} paddingX={1} flexDirection="row">
                {isSelected ? (
                  <Text color={theme.accent}>
                    {"▶ "}
                    {secret.name.slice(0, 30).padEnd(30)}{"  "}
                    {secret.scope.padEnd(10)}
                    {updatedShort.padEnd(14)}
                    {badges}
                  </Text>
                ) : (
                  <Text>
                    {"  "}
                    {secret.name.slice(0, 30).padEnd(30)}{"  "}
                    {secret.scope.padEnd(10)}
                    {updatedShort.padEnd(14)}
                    {badges}
                  </Text>
                )}
              </Box>
            );
          })
        )}
      </Box>

      {selectedSecret !== null ? (
        <Box borderStyle="round" flexDirection="column" padding={1} width={36}>
          <Text bold>{selectedSecret.name}</Text>
          <Text color={theme.dim}>scope: <Text>{selectedSecret.scope}</Text></Text>
          <Text color={theme.dim}>created: <Text>{selectedSecret.createdAt.slice(0, 10)}</Text></Text>
          <Text color={theme.dim}>updated: <Text>{selectedSecret.updatedAt.slice(0, 10)}</Text></Text>
          <Text color={theme.dim}>Value: ●●●●●●●●</Text>
          {policyBadgeTokens(selectedSecret.policy).length > 0 ? (
            <Text color="yellow">{policyBadgeTokens(selectedSecret.policy).join(" ")}</Text>
          ) : null}
        </Box>
      ) : null}
    </Box>
  );
}
