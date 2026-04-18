import { z, type ZodError } from "zod";

export const FORBIDDEN_ENV_VAR_NAMES = [
  "LD_PRELOAD",
  "LD_LIBRARY_PATH",
  "DYLD_INSERT_LIBRARIES",
  "DYLD_LIBRARY_PATH",
  "NODE_OPTIONS",
  "PYTHONPATH",
] as const satisfies readonly string[];

const FORBIDDEN_ENV_VAR_SET: ReadonlySet<string> = new Set(FORBIDDEN_ENV_VAR_NAMES);

const FQDN_PATTERN =
  /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;
const ENV_VAR_PATTERN = /^[A-Z_][A-Z0-9_]*$/;

function hasWhitespace(value: string): boolean {
  return /\s/.test(value);
}

const fqdnSchema = z
  .string()
  .min(1, { message: "host must not be empty" })
  .refine((v) => !v.includes("*"), { message: "host must not contain '*'" })
  .refine((v) => !hasWhitespace(v), { message: "host must not contain whitespace" })
  .refine((v) => FQDN_PATTERN.test(v), {
    message:
      "host must be a plain FQDN without scheme, path, or port (e.g. 'api.example.com')",
  });

const binarySchema = z
  .string()
  .min(1, { message: "binary must not be empty" })
  .refine((v) => !v.includes("*"), { message: "binary must not contain '*'" })
  .refine((v) => !hasWhitespace(v), { message: "binary must not contain whitespace" });

const argPatternSchema = z
  .string()
  .min(1, { message: "arg pattern must not be empty" })
  .refine((v) => v.startsWith("^") && v.endsWith("$"), {
    message: "arg pattern must be anchored with '^' at start and '$' at end",
  })
  .refine(
    (v) => {
      try {
        new RegExp(v);
        return true;
      } catch {
        return false;
      }
    },
    { message: "arg pattern must be a valid regular expression" },
  );

const envVarNameSchema = z
  .string()
  .min(1, { message: "env var name must not be empty" })
  .refine((v) => ENV_VAR_PATTERN.test(v), {
    message: "env var name must match ^[A-Z_][A-Z0-9_]*$",
  })
  .refine((v) => !FORBIDDEN_ENV_VAR_SET.has(v), {
    message:
      "env var name appears in the forbidden-inject list (e.g. LD_PRELOAD, NODE_OPTIONS)",
  });

const commandSchema = z.object({
  binary: binarySchema,
  allowed_args_patterns: z.array(argPatternSchema),
  forbidden_args_patterns: z.array(argPatternSchema).optional(),
});

const rateLimitSchema = z.object({
  requests: z.number().int().positive({ message: "requests must be a positive integer" }),
  window_seconds: z
    .number()
    .int()
    .positive({ message: "window_seconds must be a positive integer" }),
});

export const policySchema = z
  .object({
    allowed_http_hosts: z.array(fqdnSchema),
    allowed_commands: z.array(commandSchema),
    allowed_env_vars: z.array(envVarNameSchema),
    rate_limit: rateLimitSchema,
  })
  .strict();

export type Policy = z.infer<typeof policySchema>;
export type CommandPolicy = Policy["allowed_commands"][number];

export function validatePolicy(input: unknown): Policy | ZodError {
  const result = policySchema.safeParse(input);
  if (result.success) {
    return result.data;
  }
  return result.error;
}
