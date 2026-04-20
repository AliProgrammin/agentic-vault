import { promises as fs } from "node:fs";
import * as crypto from "node:crypto";
import * as lockfile from "proper-lockfile";
import {
  VaultClosedError,
  VaultExistsError,
  VaultFormatError,
} from "./errors.js";
import {
  type Envelope,
  type KdfParams,
  DEFAULT_KDF_PARAMS,
  DEFAULT_SALT_LENGTH,
  ENVELOPE_VERSION,
  KDF_ALGORITHM,
  CIPHER,
  decryptPayload,
  deriveKey,
  encryptPayload,
  parseEnvelope,
  serializeEnvelope,
} from "./envelope.js";
import { assertValidSecretName } from "./identifier.js";
import { atomicWriteFile } from "./atomic.js";

export interface SecretRecord {
  value: string;
  created_at: string;
  updated_at: string;
  policy?: unknown;
}

export interface PublicSecretRecord {
  name: string;
  created_at: string;
  updated_at: string;
  policy?: unknown;
}

interface VaultPayload {
  version: 1;
  secrets: Record<string, SecretRecord>;
}

export interface CreateVaultOptions {
  kdfParams?: KdfParams;
}

const LOCK_OPTIONS: lockfile.LockOptions = {
  realpath: false,
  stale: 10_000,
  retries: { retries: 10, minTimeout: 50, maxTimeout: 500, factor: 1.5 },
};

function isEnoent(err: unknown): boolean {
  return (err as NodeJS.ErrnoException).code === "ENOENT";
}

function nowIso(): string {
  return new Date().toISOString();
}

function parsePayload(bytes: Buffer): VaultPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new VaultFormatError("decrypted vault payload is not valid JSON");
  }
  if (parsed === null || typeof parsed !== "object") {
    throw new VaultFormatError("decrypted vault payload must be an object");
  }
  const obj = parsed as Record<string, unknown>;
  const version = obj["version"];
  if (version !== 1) {
    throw new VaultFormatError(`unsupported payload version: ${String(version)}`);
  }
  const secrets = obj["secrets"];
  if (secrets === null || typeof secrets !== "object") {
    throw new VaultFormatError("payload.secrets missing");
  }
  const out: Record<string, SecretRecord> = {};
  for (const [k, v] of Object.entries(secrets as Record<string, unknown>)) {
    if (v === null || typeof v !== "object") {
      throw new VaultFormatError(`secret ${k} is not an object`);
    }
    const rec = v as Record<string, unknown>;
    const value = rec["value"];
    const createdAt = rec["created_at"];
    const updatedAt = rec["updated_at"];
    if (typeof value !== "string" || typeof createdAt !== "string" || typeof updatedAt !== "string") {
      throw new VaultFormatError(`secret ${k} has invalid fields`);
    }
    const record: SecretRecord = {
      value,
      created_at: createdAt,
      updated_at: updatedAt,
    };
    if ("policy" in rec) {
      record.policy = rec["policy"];
    }
    out[k] = record;
  }
  return { version: 1, secrets: out };
}

function serializePayload(payload: VaultPayload): Buffer {
  const secretsOut: Record<string, SecretRecord> = {};
  for (const [k, v] of Object.entries(payload.secrets)) {
    const rec: SecretRecord = {
      value: v.value,
      created_at: v.created_at,
      updated_at: v.updated_at,
    };
    if (v.policy !== undefined) {
      rec.policy = v.policy;
    }
    secretsOut[k] = rec;
  }
  const json = JSON.stringify({ version: 1, secrets: secretsOut });
  return Buffer.from(json, "utf8");
}

async function writeEnvelope(
  filePath: string,
  key: Buffer,
  salt: Buffer,
  params: KdfParams,
  payload: VaultPayload,
): Promise<void> {
  const plaintext = serializePayload(payload);
  const { nonce, ciphertext, tag } = encryptPayload(plaintext, key);
  plaintext.fill(0);
  const env: Envelope = {
    version: ENVELOPE_VERSION,
    kdf: {
      algorithm: KDF_ALGORITHM,
      memory: params.memory,
      iterations: params.iterations,
      parallelism: params.parallelism,
      salt: salt.toString("base64"),
    },
    cipher: CIPHER,
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    tag: tag.toString("base64"),
  };
  const bytes = serializeEnvelope(env);
  await atomicWriteFile(filePath, bytes);
}

export class VaultHandle {
  private readonly filePath: string;
  private key: Buffer;
  private readonly salt: Buffer;
  private readonly params: KdfParams;
  private payload: VaultPayload;
  private closed = false;

  public constructor(
    filePath: string,
    key: Buffer,
    salt: Buffer,
    params: KdfParams,
    payload: VaultPayload,
  ) {
    this.filePath = filePath;
    this.key = key;
    this.salt = salt;
    this.params = params;
    this.payload = payload;
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new VaultClosedError();
    }
  }

  public get(name: string): string | undefined {
    this.assertOpen();
    assertValidSecretName(name);
    const rec = this.payload.secrets[name];
    return rec === undefined ? undefined : rec.value;
  }

  public getRecord(name: string): PublicSecretRecord | undefined {
    this.assertOpen();
    assertValidSecretName(name);
    const rec = this.payload.secrets[name];
    if (rec === undefined) {
      return undefined;
    }
    const out: PublicSecretRecord = {
      name,
      created_at: rec.created_at,
      updated_at: rec.updated_at,
    };
    if (rec.policy !== undefined) {
      out.policy = rec.policy;
    }
    return out;
  }

  public set(name: string, value: string, policy?: unknown): void {
    this.assertOpen();
    assertValidSecretName(name);
    if (typeof value !== "string") {
      throw new TypeError("secret value must be a string");
    }
    const existing = this.payload.secrets[name];
    const now = nowIso();
    const record: SecretRecord = {
      value,
      created_at: existing?.created_at ?? now,
      updated_at: now,
    };
    if (policy !== undefined) {
      record.policy = policy;
    } else if (existing !== undefined && existing.policy !== undefined) {
      record.policy = existing.policy;
    }
    this.payload.secrets[name] = record;
  }

  public remove(name: string): boolean {
    this.assertOpen();
    assertValidSecretName(name);
    if (!(name in this.payload.secrets)) {
      return false;
    }
    delete this.payload.secrets[name];
    return true;
  }

  public list(): PublicSecretRecord[] {
    this.assertOpen();
    const out: PublicSecretRecord[] = [];
    for (const [name, rec] of Object.entries(this.payload.secrets)) {
      const pub: PublicSecretRecord = {
        name,
        created_at: rec.created_at,
        updated_at: rec.updated_at,
      };
      if (rec.policy !== undefined) {
        pub.policy = rec.policy;
      }
      out.push(pub);
    }
    return out;
  }

  public async save(): Promise<void> {
    this.assertOpen();
    const release = await lockfile.lock(this.filePath, LOCK_OPTIONS);
    try {
      await writeEnvelope(this.filePath, this.key, this.salt, this.params, this.payload);
    } finally {
      await release();
    }
  }

  public close(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.key.fill(0);
    this.key = Buffer.alloc(0);
    for (const name of Object.keys(this.payload.secrets)) {
      delete this.payload.secrets[name];
    }
  }

  public isClosed(): boolean {
    return this.closed;
  }

  /**
   * Derive a subkey for use by adjacent encrypted stores (e.g. the F13
   * encrypted-body-blob store). Uses HKDF-SHA-256 with a fixed info
   * string so callers cannot collide on the same subkey by accident.
   * The returned buffer is a new allocation; the master key is never
   * exposed.
   */
  public deriveSubkey(info: string, length: number = 32): Buffer {
    this.assertOpen();
    if (info.length === 0) {
      throw new TypeError("deriveSubkey info must not be empty");
    }
    if (length <= 0 || length > 64) {
      throw new TypeError("deriveSubkey length must be in (0, 64]");
    }
    const derived = crypto.hkdfSync(
      "sha256",
      this.key,
      this.salt,
      Buffer.from(info, "utf8"),
      length,
    );
    return Buffer.from(derived);
  }
}

export async function createVault(
  filePath: string,
  password: string,
  opts: CreateVaultOptions = {},
): Promise<VaultHandle> {
  try {
    await fs.access(filePath);
    throw new VaultExistsError(filePath);
  } catch (err) {
    if (!isEnoent(err)) {
      throw err;
    }
  }

  const params = opts.kdfParams ?? DEFAULT_KDF_PARAMS;
  const salt = crypto.randomBytes(DEFAULT_SALT_LENGTH);
  const key = await deriveKey(password, salt, params);
  const payload: VaultPayload = { version: 1, secrets: {} };
  await writeEnvelope(filePath, key, salt, params, payload);
  return new VaultHandle(filePath, key, salt, params, payload);
}

export async function unlockVault(filePath: string, password: string): Promise<VaultHandle> {
  const bytes = await fs.readFile(filePath);
  const env = parseEnvelope(bytes);
  const salt = Buffer.from(env.kdf.salt, "base64");
  const nonce = Buffer.from(env.nonce, "base64");
  const ciphertext = Buffer.from(env.ciphertext, "base64");
  const tag = Buffer.from(env.tag, "base64");
  const params: KdfParams = {
    memory: env.kdf.memory,
    iterations: env.kdf.iterations,
    parallelism: env.kdf.parallelism,
  };
  const key = await deriveKey(password, salt, params);
  let plaintext: Buffer;
  try {
    plaintext = decryptPayload(ciphertext, key, nonce, tag);
  } catch (err) {
    key.fill(0);
    throw err;
  }
  let payload: VaultPayload;
  try {
    payload = parsePayload(plaintext);
  } finally {
    plaintext.fill(0);
  }
  return new VaultHandle(filePath, key, salt, params, payload);
}
