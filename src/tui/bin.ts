#!/usr/bin/env node
import { createDefaultDeps } from "../cli/deps.js";
import { runTuiApp } from "./index.js";

async function main(): Promise<void> {
  const deps = createDefaultDeps({ debug: process.argv.includes("--debug") });
  await runTuiApp(deps);
}

void main();
