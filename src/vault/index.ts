export {
  createVault,
  unlockVault,
  VaultHandle,
  type CreateVaultOptions,
  type PublicSecretRecord,
} from "./vault.js";
export {
  VaultError,
  WrongPasswordError,
  VaultFormatError,
  VaultIdentifierError,
  VaultClosedError,
  VaultExistsError,
} from "./errors.js";
export { assertValidSecretName, isValidSecretName } from "./identifier.js";
export { DEFAULT_KDF_PARAMS, type KdfParams } from "./envelope.js";
