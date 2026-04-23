import { Box, Text } from "ink";
import { useCallback, type ReactElement } from "react";
import { theme } from "../theme.js";
import { useHitZone } from "../MouseContext.js";

export const TAB_LABELS = ["Dashboard", "Secrets", "Audit", "Policies"] as const;

interface TabBarProps {
  readonly activeIndex: number;
  readonly focusedIndex: number;
  readonly isFocused: boolean;
  readonly onTabClick?: (index: number) => void;
}

interface TabProps {
  readonly index: number;
  readonly label: string;
  readonly isActive: boolean;
  readonly isFocused: boolean;
  readonly onTabClick?: (index: number) => void;
}

function Tab(props: TabProps): ReactElement {
  const { index, label, isActive, isFocused } = props;
  const onClick = useCallback(() => props.onTabClick?.(index), [index, props]);
  const ref = useHitZone(`tab:${label}`, { onClick, enabled: props.onTabClick !== undefined });
  let content: ReactElement;
  if (isActive && isFocused) {
    content = (
      <Text backgroundColor={theme.primary} color={theme.background} bold>
        {` ▸ ${label} ◂ `}
      </Text>
    );
  } else if (isActive) {
    content = (
      <Text backgroundColor={theme.borderSubtle} color={theme.text} bold>
        {`  ${label}  `}
      </Text>
    );
  } else if (isFocused) {
    content = (
      <Text backgroundColor={theme.backgroundElement} color={theme.text} bold>
        {`  ${label}  `}
      </Text>
    );
  } else {
    content = <Text color={theme.textMuted}>{`  ${label}  `}</Text>;
  }
  return <Box ref={ref}>{content}</Box>;
}

export function TabBar(props: TabBarProps): ReactElement {
  return (
    <Box flexDirection="row" paddingX={1} backgroundColor={theme.backgroundPanel}>
      <Text color={theme.primary} bold>
        {"Agentic Vault  "}
      </Text>
      {TAB_LABELS.map((label, index) => (
        <Tab
          key={label}
          index={index}
          label={label}
          isActive={index === props.activeIndex}
          isFocused={props.isFocused && index === props.focusedIndex}
          {...(props.onTabClick !== undefined ? { onTabClick: props.onTabClick } : {})}
        />
      ))}
    </Box>
  );
}
