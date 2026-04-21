import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    globals: false,
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      include: ["src/vault/**", "src/policy/**", "src/audit/**", "src/tui/**"],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 75,
        statements: 80,
        "src/tui/**": {
          lines: 70,
          functions: 70,
          branches: 65,
          statements: 70,
        },
      },
    },
  },
});
