// Encrypted audit body-blob store.
//
// Body-bearing fields for F13 audit entries — `request.body`, `response.body`,
// `stdout`, `stderr` — are captured, scrubbed (F6), capped (64 KiB request /
// 256 KiB response), and written to per-id files under
// `<baseDir>/audit-bodies/<id>.enc` as AES-256-GCM envelopes with a unique
// nonce per write. The encryption key is derived from the unlocked vault
// master key via HKDF so callers do not pass plaintext keys around.
//
// Metadata (timestamps, secret name, outcome, surface, code, stage timings,
// rate-limit state) lives in the plaintext JSONL alongside so the CLI's
// `audit --tail` and filter commands do not require an unlock.
//
// Per-id files make crash-safe pruning trivial: pruning is `unlink(<id>.enc)`
// — the JSONL is never rewritten, and a crash mid-prune leaves the store in a
// well-defined state (every file that exists still decrypts cleanly).
//
// This module does NOT perform scrubbing; callers must scrub the body
// artifacts against the in-scope secret set BEFORE calling `writeBody`.

import * as crypto from "node:crypto";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import { atomicWriteFile } from "../vault/atomic.js";
import type { BodyArtifact } from "./body-artifact.js";

const CIPHER = "aes-256-gcm" as const;
const NONCE_LENGTH = 12;
const KEY_LENGTH = 32;
const BLOB_ENVELOPE_VERSION = 1;
const BLOB_SUFFIX = ".enc";
const BODIES_SUBDIR = "audit-bodies";

export class BodyStoreError extends Error {
  public override readonly name: string = "BodyStoreError";
  public readonly code: string;
  public constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export class BodyNotFoundError extends BodyStoreError {
  public override readonly name = "BodyNotFoundError";
  public constructor(blobId: string) {
    super("BODY_NOT_FOUND", `audit body blob '${blobId}' not found`);
  }
}

export class BodyDecryptError extends BodyStoreError {
  public override readonly name = "BodyDecryptError";
  public constructor(blobId: string, reason: string) {
    super("BODY_DECRYPT_FAILED", `audit body blob '${blobId}' failed to decrypt: ${reason}`);
  }
}

export class BodyFormatError extends BodyStoreError {
  public override readonly name = "BodyFormatError";
  public constructor(blobId: string, reason: string) {
    super("BODY_FORMAT", `audit body blob '${blobId}' is malformed: ${reason}`);
  }
}

/**
 * Payload written to the encrypted store. `request` and `response` are each
 * optional because not every surface has both: an MCP `run_command`
 * invocation has `stdout` / `stderr`; an HTTP request has `request` and
 * `response` bodies. `env` is the command surface's scrubbed env-var VALUES
 * — captured only for rendering; env VALUES never leave the encrypted blob.
 */
export interface BodyBlobPayload {
  readonly request?: BodyArtifact;
  readonly response?: BodyArtifact;
  readonly stdout?: BodyArtifact;
  readonly stderr?: BodyArtifact;
}

interface BlobEnvelope {
  readonly version: number;
  readonly cipher: typeof CIPHER;
  readonly nonce: string;
  readonly ciphertext: string;
  readonly tag: string;
}

function blobIdPattern(): RegExp {
  // Accept UUIDs plus the looser set of chars existing request_id generators
  // might emit; disallow path-separators / dotfiles defensively.
  return /^[A-Za-z0-9_-]{8,128}$/;
}

function assertSafeBlobId(blobId: string): void {
  if (!blobIdPattern().test(blobId)) {
    throw new BodyStoreError("BODY_INVALID_ID", `invalid blob id '${blobId}'`);
  }
}

function keyIsValid(key: Buffer): boolean {
  return key.byteLength === KEY_LENGTH;
}

export interface BodyStoreOptions {
  readonly baseDir: string;
  readonly key: Buffer;
}

export class EncryptedBodyStore {
  private readonly baseDir: string;
  private readonly bodiesDir: string;
  private readonly key: Buffer;
  private dirEnsured = false;

  public constructor(options: BodyStoreOptions) {
    if (!keyIsValid(options.key)) {
      throw new TypeError(`body store key must be ${String(KEY_LENGTH)} bytes`);
    }
    this.baseDir = options.baseDir;
    this.bodiesDir = path.join(this.baseDir, BODIES_SUBDIR);
    this.key = Buffer.from(options.key);
  }

  public get directory(): string {
    return this.bodiesDir;
  }

  public pathFor(blobId: string): string {
    assertSafeBlobId(blobId);
    return path.join(this.bodiesDir, `${blobId}${BLOB_SUFFIX}`);
  }

  public async writeBody(blobId: string, payload: BodyBlobPayload): Promise<void> {
    assertSafeBlobId(blobId);
    await this.ensureDir();
    const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
    const nonce = crypto.randomBytes(NONCE_LENGTH);
    const cipher = crypto.createCipheriv(CIPHER, this.key, nonce);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    plaintext.fill(0);
    const env: BlobEnvelope = {
      version: BLOB_ENVELOPE_VERSION,
      cipher: CIPHER,
      nonce: nonce.toString("base64"),
      ciphertext: ciphertext.toString("base64"),
      tag: tag.toString("base64"),
    };
    await atomicWriteFile(this.pathFor(blobId), JSON.stringify(env));
  }

  public async readBody(blobId: string): Promise<BodyBlobPayload> {
    const filePath = this.pathFor(blobId);
    let raw: Buffer;
    try {
      raw = await fs.readFile(filePath);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        throw new BodyNotFoundError(blobId);
      }
      throw err;
    }
    let env: BlobEnvelope;
    try {
      const parsed = JSON.parse(raw.toString("utf8")) as unknown;
      if (parsed === null || typeof parsed !== "object") {
        throw new Error("envelope is not an object");
      }
      const obj = parsed as Record<string, unknown>;
      const version = obj["version"];
      const cipher = obj["cipher"];
      const nonce = obj["nonce"];
      const ciphertext = obj["ciphertext"];
      const tag = obj["tag"];
      if (
        typeof version !== "number" ||
        version !== BLOB_ENVELOPE_VERSION ||
        cipher !== CIPHER ||
        typeof nonce !== "string" ||
        typeof ciphertext !== "string" ||
        typeof tag !== "string"
      ) {
        throw new Error("envelope fields invalid");
      }
      env = { version, cipher: CIPHER, nonce, ciphertext, tag };
    } catch (err) {
      throw new BodyFormatError(blobId, (err as Error).message);
    }
    const nonce = Buffer.from(env.nonce, "base64");
    const ciphertext = Buffer.from(env.ciphertext, "base64");
    const tag = Buffer.from(env.tag, "base64");
    let plaintext: Buffer;
    try {
      const decipher = crypto.createDecipheriv(CIPHER, this.key, nonce);
      decipher.setAuthTag(tag);
      plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch (err) {
      throw new BodyDecryptError(blobId, (err as Error).message);
    }
    try {
      const parsed = JSON.parse(plaintext.toString("utf8")) as BodyBlobPayload;
      return parsed;
    } catch (err) {
      throw new BodyFormatError(blobId, `decrypted payload not valid JSON: ${(err as Error).message}`);
    } finally {
      plaintext.fill(0);
    }
  }

  public async hasBody(blobId: string): Promise<boolean> {
    try {
      await fs.access(this.pathFor(blobId));
      return true;
    } catch {
      return false;
    }
  }

  public async deleteBody(blobId: string): Promise<boolean> {
    try {
      await fs.unlink(this.pathFor(blobId));
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        return false;
      }
      throw err;
    }
  }

  public async listBlobs(): Promise<readonly BlobEntry[]> {
    await this.ensureDir();
    const out: BlobEntry[] = [];
    let entries: string[];
    try {
      entries = await fs.readdir(this.bodiesDir);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        return [];
      }
      throw err;
    }
    for (const name of entries) {
      if (!name.endsWith(BLOB_SUFFIX)) continue;
      const id = name.slice(0, -BLOB_SUFFIX.length);
      if (!blobIdPattern().test(id)) continue;
      const filePath = path.join(this.bodiesDir, name);
      let st;
      try {
        st = await fs.stat(filePath);
      } catch {
        continue;
      }
      if (!st.isFile()) continue;
      out.push({ blobId: id, bytes: st.size, mtimeMs: st.mtimeMs });
    }
    return out;
  }

  public async totalBytes(): Promise<number> {
    const blobs = await this.listBlobs();
    let total = 0;
    for (const b of blobs) total += b.bytes;
    return total;
  }

  private async ensureDir(): Promise<void> {
    if (this.dirEnsured) return;
    await fs.mkdir(this.bodiesDir, { recursive: true, mode: 0o700 });
    if (process.platform !== "win32") {
      try {
        await fs.chmod(this.bodiesDir, 0o700);
      } catch {
        // best-effort
      }
    }
    this.dirEnsured = true;
  }
}

export interface BlobEntry {
  readonly blobId: string;
  readonly bytes: number;
  readonly mtimeMs: number;
}
