import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    cli: "src/cli/index.ts",
  },
  format: ["cjs"],
  target: "node20",
  platform: "node",
  clean: true,
  dts: true,
  sourcemap: true,
  shims: true,
  outExtension: () => ({ js: ".cjs" }),
});
