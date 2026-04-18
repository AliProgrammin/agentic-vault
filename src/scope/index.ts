export {
  VAULT_FILENAME,
  discoverProjectVault,
  getGlobalVaultPath,
  type ProjectVaultLocation,
} from "./discover.js";
export {
  ensureProjectGitignore,
  gitignoreAlreadyCovers,
  type GitignoreResult,
} from "./gitignore.js";
export {
  resolveSecret,
  listMerged,
  type MergeSources,
  type ResolvedSecret,
  type ScopedSecretEntry,
  type SecretScope,
} from "./merge.js";
export {
  ensureProjectVault,
  type EnsureProjectVaultResult,
} from "./ensure.js";
