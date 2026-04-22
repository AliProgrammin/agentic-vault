import { Box, Text } from "ink";
import type { ReactElement } from "react";
import { formatAuditDetail, type AuditEvent, type RenderModel } from "../../audit/index.js";
import { theme } from "../theme.js";

interface AuditScreenProps {
  readonly entries: readonly AuditEvent[];
  readonly selected: number;
  readonly filter: string;
  readonly auditDetail: boolean;
  readonly model: RenderModel | null;
}

export function AuditScreen(props: AuditScreenProps): ReactElement {
  const { entries, selected, filter, auditDetail, model } = props;

  if (auditDetail && model !== null) {
    const lines = formatAuditDetail(model, { tty: false }).trimEnd().split("\n");
    return (
      <Box borderStyle="round" flexDirection="column" paddingX={1}>
        {lines.map((line, index) => (
          <Text key={`audit-detail:${String(index)}:${line}`}>{line}</Text>
        ))}
      </Box>
    );
  }

  return (
    <Box borderStyle="round" flexDirection="column">
      {filter.length > 0 ? (
        <Box paddingX={1}>
          <Text color={theme.dim}>filter: <Text color={theme.accent}>{filter}</Text></Text>
        </Box>
      ) : null}
      <Box paddingX={1} flexDirection="row">
        <Text bold color={theme.dim}>  {"OUTCOME".padEnd(8)}{"TIMESTAMP".padEnd(26)}{"SECRET".padEnd(24)}TARGET</Text>
      </Box>
      {entries.length === 0 ? (
        <Box paddingX={1}>
          <Text color={theme.dim}>No audit entries yet.</Text>
        </Box>
      ) : (
        entries.map((entry, index) => {
          const isSelected = index === selected;
          return (
            <Box key={entry.request_id} paddingX={1} flexDirection="row">
              {isSelected ? (
                <Text color={theme.accent}>
                  {"▶ "}
                  <Text color={entry.outcome === "allowed" ? "green" : "red"}>
                    {entry.outcome === "allowed" ? "✓" : "✗"}
                  </Text>
                  {"  "}
                  {entry.ts.padEnd(24)}
                  {"  "}
                  {entry.secret_name.slice(0, 22).padEnd(22)}
                  {"  "}
                  {entry.target}
                </Text>
              ) : (
                <Text>
                  {"  "}
                  <Text color={entry.outcome === "allowed" ? "green" : "red"}>
                    {entry.outcome === "allowed" ? "✓" : "✗"}
                  </Text>
                  {"  "}
                  {entry.ts.padEnd(24)}
                  {"  "}
                  {entry.secret_name.slice(0, 22).padEnd(22)}
                  {"  "}
                  {entry.target}
                </Text>
              )}
            </Box>
          );
        })
      )}
    </Box>
  );
}
