import * as crypto from "node:crypto";
import * as argon2 from "argon2";
import { VaultFormatError, WrongPasswordError } from "./errors.js";

export const ENVELOPE_VERSION = 1;
export const CIPHER = "aes-256-gcm" as const;
export const KDF_ALGORITHM = "argon2id" as const;
export const KEY_LENGTH = 32;
export const NONCE_LENGTH = 12;
export const TAG_LENGTH = 16;
export const DEFAULT_SALT_LENGTH = 16;

export interface KdfParams {
  memory: number;
  iterations: number;
  parallelism: number;
}

export const DEFAULT_KDF_PARAMS: KdfParams = {
  memory: 65536,
  iterations: 3,
  parallelism: 4,
};

export interface Envelope {
  version: number;
  kdf: {
    algorithm: typeof KDF_ALGORITHM;
    memory: number;
    iterations: number;
    parallelism: number;
    salt: string;
  };
  cipher: typeof CIPHER;
  nonce: string;
  ciphertext: string;
  tag: string;
}

export async function deriveKey(
  password: string,
  salt: Buffer,
  params: KdfParams,
): Promise<Buffer> {
  const hash = await argon2.hash(password, {
    type: argon2.argon2id,
    salt,
    memoryCost: params.memory,
    timeCost: params.iterations,
    parallelism: params.parallelism,
    hashLength: KEY_LENGTH,
    raw: true,
  });
  return hash;
}

export function encryptPayload(plaintext: Buffer, key: Buffer): {
  nonce: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
} {
  const nonce = crypto.randomBytes(NONCE_LENGTH);
  const cipher = crypto.createCipheriv(CIPHER, key, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { nonce, ciphertext, tag };
}

export function decryptPayload(
  ciphertext: Buffer,
  key: Buffer,
  nonce: Buffer,
  tag: Buffer,
): Buffer {
  const decipher = crypto.createDecipheriv(CIPHER, key, nonce);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new WrongPasswordError();
  }
}

export function serializeEnvelope(env: Envelope): Buffer {
  return Buffer.from(JSON.stringify(env), "utf8");
}

export function parseEnvelope(bytes: Buffer): Envelope {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new VaultFormatError("vault file is not valid JSON");
  }
  if (parsed === null || typeof parsed !== "object") {
    throw new VaultFormatError("vault envelope must be an object");
  }
  const obj = parsed as Record<string, unknown>;

  const version = obj["version"];
  if (typeof version !== "number" || !Number.isInteger(version)) {
    throw new VaultFormatError("envelope.version missing or not integer");
  }
  if (version !== ENVELOPE_VERSION) {
    throw new VaultFormatError(`unsupported envelope version: ${String(version)}`);
  }

  const kdf = obj["kdf"];
  if (kdf === null || typeof kdf !== "object") {
    throw new VaultFormatError("envelope.kdf missing");
  }
  const kdfObj = kdf as Record<string, unknown>;
  const algorithm = kdfObj["algorithm"];
  if (algorithm !== KDF_ALGORITHM) {
    throw new VaultFormatError(`unsupported kdf algorithm: ${String(algorithm)}`);
  }
  const memory = kdfObj["memory"];
  const iterations = kdfObj["iterations"];
  const parallelism = kdfObj["parallelism"];
  const salt = kdfObj["salt"];
  if (
    typeof memory !== "number" ||
    typeof iterations !== "number" ||
    typeof parallelism !== "number" ||
    typeof salt !== "string"
  ) {
    throw new VaultFormatError("envelope.kdf fields invalid");
  }

  const cipher = obj["cipher"];
  if (cipher !== CIPHER) {
    throw new VaultFormatError(`unsupported cipher: ${String(cipher)}`);
  }

  const nonce = obj["nonce"];
  const ciphertext = obj["ciphertext"];
  const tag = obj["tag"];
  if (typeof nonce !== "string" || typeof ciphertext !== "string" || typeof tag !== "string") {
    throw new VaultFormatError("envelope binary fields missing");
  }

  return {
    version,
    kdf: {
      algorithm: KDF_ALGORITHM,
      memory,
      iterations,
      parallelism,
      salt,
    },
    cipher: CIPHER,
    nonce,
    ciphertext,
    tag,
  };
}
