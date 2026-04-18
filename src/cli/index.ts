#!/usr/bin/env node
// Bin entry for the `secretproxy` CLI. Tests import from ./main and ./commands/*
// directly so this file is kept as a thin bootstrap that runs immediately.
import { createDefaultDeps } from "./deps.js";
import { runCli } from "./main.js";

async function main(): Promise<void> {
  const debug = process.argv.includes("--debug");
  const deps = createDefaultDeps({ debug });
  const exitCode = await runCli(process.argv.slice(2), deps);
  process.exit(exitCode);
}

void main();
