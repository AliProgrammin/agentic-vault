import type { CliDeps } from "../types.js";
import { runTuiApp, type RunTuiOptions } from "../../tui/index.js";

export async function cmdTui(
  deps: CliDeps,
  options: RunTuiOptions = {},
): Promise<void> {
  await runTuiApp(deps, options);
}
