import type { MasterPasswordStore } from "./store.js";
import type { TTYInterface } from "./tty.js";
import {
  KeychainBackendError,
  KeychainNoItemError,
  PasswordMismatchError,
  VaultLockedError,
  WeakPasswordError,
} from "./errors.js";

export const ROUTINE_ENV_VAR = "SECRETPROXY_PASSWORD";
export const INIT_ENV_VAR = "SECRETPROXY_INIT_PASSWORD";
export const MIN_INIT_PASSWORD_LENGTH = 12;

const FALLBACK_WARNING =
  `warning: using ${ROUTINE_ENV_VAR} env var as master password fallback. Run \`secretproxy init\` to stash the password in your OS keychain.`;

export interface RoutineResolverDeps {
  env: NodeJS.ProcessEnv;
  store: MasterPasswordStore;
  warn: (message: string) => void;
}

export type RoutineResolver = () => string;

export function createRoutineResolver(deps: RoutineResolverDeps): RoutineResolver {
  let warned = false;
  return (): string => {
    const envValue = deps.env[ROUTINE_ENV_VAR];
    if (typeof envValue === "string" && envValue.length > 0) {
      if (!warned) {
        warned = true;
        deps.warn(FALLBACK_WARNING);
      }
      return envValue;
    }

    try {
      return deps.store.readMasterPassword();
    } catch (err) {
      if (err instanceof KeychainNoItemError) {
        throw new VaultLockedError();
      }
      if (err instanceof KeychainBackendError) {
        throw err;
      }
      throw err;
    }
  };
}

export interface InitResolverDeps {
  env: NodeJS.ProcessEnv;
  tty: TTYInterface;
  minLength?: number;
}

export async function resolveInitPassword(deps: InitResolverDeps): Promise<string> {
  const envValue = deps.env[INIT_ENV_VAR];
  if (typeof envValue === "string" && envValue.length > 0) {
    return envValue;
  }

  if (!deps.tty.stdinIsTTY()) {
    return deps.tty.readStdinAll();
  }

  const minLength = deps.minLength ?? MIN_INIT_PASSWORD_LENGTH;
  const first = await deps.tty.promptHidden("Set master password: ");
  if (first.length < minLength) {
    throw new WeakPasswordError(minLength);
  }
  const confirm = await deps.tty.promptHidden("Confirm: ");
  if (confirm !== first) {
    throw new PasswordMismatchError();
  }
  return first;
}
