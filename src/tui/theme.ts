// OpenCode-inspired stepped dark palette. Each "step" is a visual elevation
// layer — background < panel < element — so buttons/interactive things
// visibly pop off their containing panel.
export const theme = {
  // Surface stack (lower = darker = deeper)
  background:        "#0a0a0a",  // app-level bg (usually unset — terminal default)
  backgroundPanel:   "#141414",  // bordered panel interior
  backgroundElement: "#1e1e1e",  // idle button / toolbar / list-item bg

  // Borders
  border:            "#484848",
  borderActive:      "#606060",
  borderSubtle:      "#3c3c3c",

  // Accent / semantic
  primary:           "#fab283",  // peach — primary action / current tab / focused button
  secondary:         "#5c9cf5",  // blue — secondary accents
  accentPurple:      "#9d7cd8",  // sparingly used (e.g. headings)
  success:           "#7fd88f",
  warning:           "#f5a742",
  danger:            "#e06c75",
  info:              "#56b6c2",

  // Text
  text:              "#eeeeee",
  textMuted:         "#808080",

  // Legacy aliases (some components still import these names — keep them
  // as aliases mapped to the new values so imports don't break).
  surface:           "#141414",  // alias → backgroundPanel
  surfaceElevated:   "#1e1e1e",  // alias → backgroundElement
  accent:            "#fab283",  // alias → primary
  accentMuted:       "#5c9cf5",  // alias → secondary
  dim:               "#808080",  // alias → textMuted
} as const;
