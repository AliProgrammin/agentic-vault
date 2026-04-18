import type { ZodError } from "zod";

export function stableStringify(value: unknown, indent = 2): string {
  return JSON.stringify(
    value,
    (_key, v: unknown) => {
      if (v !== null && typeof v === "object" && !Array.isArray(v)) {
        const rec = v as Record<string, unknown>;
        const sorted: Record<string, unknown> = {};
        for (const k of Object.keys(rec).sort()) {
          sorted[k] = rec[k];
        }
        return sorted;
      }
      return v;
    },
    indent,
  );
}

export function formatZodError(err: ZodError): string {
  return err.issues
    .map((issue) => {
      const path = issue.path.length > 0 ? issue.path.join(".") : "(root)";
      return `  - ${path}: ${issue.message}`;
    })
    .join("\n");
}
