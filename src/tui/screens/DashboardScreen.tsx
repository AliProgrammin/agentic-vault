import { Box, Text } from "ink";
import type { ReactElement } from "react";
import type { AuditEvent } from "../../audit/index.js";
import { theme } from "../theme.js";

interface DashboardData {
  readonly globalCount: number;
  readonly projectCount: number;
  readonly riskyPolicyCount: number;
  readonly globalMtime: string;
  readonly projectMtime: string;
  readonly mcpOnline: boolean;
}

interface DashboardScreenProps {
  readonly dashboard: DashboardData;
  readonly audit: readonly AuditEvent[];
}

export function DashboardScreen(props: DashboardScreenProps): ReactElement {
  const { dashboard, audit } = props;
  const recentAudit = [...audit].slice(-8).reverse();

  return (
    <Box flexDirection="column" gap={1}>
      <Box flexDirection="row" gap={1}>
        <Box borderStyle="round" padding={1} flexDirection="column">
          <Text color={theme.dim}>global secrets</Text>
          <Text bold>{String(dashboard.globalCount)}</Text>
        </Box>
        <Box borderStyle="round" padding={1} flexDirection="column">
          <Text color={theme.dim}>project secrets</Text>
          <Text bold>{String(dashboard.projectCount)}</Text>
        </Box>
        <Box borderStyle="round" padding={1} flexDirection="column">
          <Text color={theme.dim}>MCP server</Text>
          <Text color={dashboard.mcpOnline ? "green" : "red"}>
            {dashboard.mcpOnline ? "● online" : "○ offline"}
          </Text>
        </Box>
        <Box borderStyle="round" padding={1} flexDirection="column">
          <Text color={theme.dim}>risky policies</Text>
          {dashboard.riskyPolicyCount > 0 ? (
            <Text color="yellow">{String(dashboard.riskyPolicyCount)}</Text>
          ) : (
            <Text>{String(dashboard.riskyPolicyCount)}</Text>
          )}
        </Box>
      </Box>

      <Box borderStyle="round" flexDirection="column" paddingX={1}>
        <Text color={theme.dim}>Dashboard | MCP {dashboard.mcpOnline ? "online" : "offline"}</Text>
        <Text color={theme.dim}>Vault mtimes | global={dashboard.globalMtime} | project={dashboard.projectMtime}</Text>
        <Text color={theme.dim}>Risky policies={String(dashboard.riskyPolicyCount)}</Text>
        <Text bold>Recent audit activity</Text>
        {recentAudit.length === 0 ? (
          <Text color={theme.dim}>No audit entries yet.</Text>
        ) : (
          recentAudit.map((entry) => (
            <Box key={entry.request_id} flexDirection="row" gap={1}>
              <Text color={entry.outcome === "allowed" ? "green" : "red"}>
                {entry.outcome === "allowed" ? "✓" : "✗"}
              </Text>
              <Text color={theme.dim}>{entry.ts}</Text>
              <Text>{entry.secret_name}</Text>
              <Text color={theme.dim}>{entry.target}</Text>
            </Box>
          ))
        )}
      </Box>
    </Box>
  );
}
