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

function StatCard(props: {
  readonly label: string;
  readonly children: ReactElement;
}): ReactElement {
  return (
    <Box
      borderStyle="round"
      borderColor={theme.border}
      backgroundColor={theme.backgroundPanel}
      flexDirection="column"
      paddingX={1}
      width={22}
    >
      <Text color={theme.textMuted}>{props.label}</Text>
      {props.children}
    </Box>
  );
}

export function DashboardScreen(props: DashboardScreenProps): ReactElement {
  const { dashboard, audit } = props;
  const recent = [...audit].slice(-8).reverse();

  return (
    <Box flexDirection="column" paddingX={1} gap={1}>
      <Box flexDirection="row" gap={1}>
        <StatCard label="global secrets">
          <Text bold color={theme.text}>{String(dashboard.globalCount)}</Text>
        </StatCard>
        <StatCard label="project secrets">
          <Text bold color={theme.text}>{String(dashboard.projectCount)}</Text>
        </StatCard>
        <StatCard label="MCP server">
          {dashboard.mcpOnline ? (
            <Text color={theme.success} bold>● online</Text>
          ) : (
            <Text color={theme.danger} bold>○ offline</Text>
          )}
        </StatCard>
        <StatCard label="risky policies">
          {dashboard.riskyPolicyCount > 0 ? (
            <Text color={theme.warning} bold>{String(dashboard.riskyPolicyCount)}</Text>
          ) : (
            <Text color={theme.dim}>{String(dashboard.riskyPolicyCount)}</Text>
          )}
        </StatCard>
      </Box>

      <Box
        borderStyle="round"
        borderColor={theme.border}
        backgroundColor={theme.backgroundPanel}
        flexDirection="column"
        paddingX={1}
      >
        <Text color={theme.text} bold>Recent activity</Text>
        {recent.length === 0 ? (
          <Text color={theme.textMuted}>No activity yet.</Text>
        ) : (
          recent.map((entry) => (
            <Box key={entry.request_id} flexDirection="row">
              <Text color={entry.outcome === "allowed" ? theme.success : theme.danger}>
                {entry.outcome === "allowed" ? "✓ " : "✗ "}
              </Text>
              <Box width={22}>
                <Text color={theme.textMuted}>{entry.ts.slice(0, 19).replace("T", " ")}</Text>
              </Box>
              <Box width={28}>
                <Text color={theme.text}>{entry.secret_name}</Text>
              </Box>
              <Text color={theme.textMuted}>{entry.target}</Text>
            </Box>
          ))
        )}
      </Box>
    </Box>
  );
}
