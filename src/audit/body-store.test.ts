import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as crypto from "node:crypto";
import {
  BodyDecryptError,
  BodyFormatError,
  BodyNotFoundError,
  EncryptedBodyStore,
} from "./body-store.js";
import { classifyText } from "./body-artifact.js";

async function mkSandbox(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "secretproxy-body-"));
}

function key(): Buffer {
  return crypto.randomBytes(32);
}

describe("EncryptedBodyStore", () => {
  let sandbox: string;
  beforeEach(async () => { sandbox = await mkSandbox(); });
  afterEach(async () => { await fs.rm(sandbox, { recursive: true, force: true }); });

  it("round-trips a payload via encrypt/decrypt", async () => {
    const store = new EncryptedBodyStore({ baseDir: sandbox, key: key() });
    const id = "req-abcdefgh";
    const artifact = classifyText("hello world");
    await store.writeBody(id, { request: artifact, response: artifact });
    const round = await store.readBody(id);
    expect(round.request?.kind).toBe("text");
    expect(round.response?.kind).toBe("text");
    if (round.request?.kind === "text") {
      expect(round.request.text).toBe("hello world");
    }
  });

  it("raw bytes on disk do NOT contain the plaintext", async () => {
    const k = key();
    const store = new EncryptedBodyStore({ baseDir: sandbox, key: k });
    const id = "req-secretly";
    const plaintext = "SEKRET123-but-encrypted-on-disk";
    await store.writeBody(id, { response: classifyText(plaintext) });
    const onDisk = await fs.readFile(store.pathFor(id), "utf8");
    expect(onDisk).not.toContain(plaintext);
  });

  it("tampering with the ciphertext produces BodyDecryptError", async () => {
    const k = key();
    const store = new EncryptedBodyStore({ baseDir: sandbox, key: k });
    const id = "req-tamper1";
    await store.writeBody(id, { response: classifyText("tamperable") });
    const p = store.pathFor(id);
    const env = JSON.parse(await fs.readFile(p, "utf8")) as {
      nonce: string; ciphertext: string; tag: string; version: number; cipher: string;
    };
    const bytes = Buffer.from(env.ciphertext, "base64");
    bytes[0] = (bytes[0] ?? 0) ^ 0xff;
    env.ciphertext = bytes.toString("base64");
    await fs.writeFile(p, JSON.stringify(env));
    await expect(store.readBody(id)).rejects.toBeInstanceOf(BodyDecryptError);
  });

  it("invalid envelope yields BodyFormatError", async () => {
    const store = new EncryptedBodyStore({ baseDir: sandbox, key: key() });
    const id = "req-badenv1";
    await fs.mkdir(store.directory, { recursive: true });
    await fs.writeFile(store.pathFor(id), "{not json");
    await expect(store.readBody(id)).rejects.toBeInstanceOf(BodyFormatError);
  });

  it("missing blob yields BodyNotFoundError", async () => {
    const store = new EncryptedBodyStore({ baseDir: sandbox, key: key() });
    await expect(store.readBody("req-missing1")).rejects.toBeInstanceOf(BodyNotFoundError);
  });

  it("rejects unsafe blob ids", async () => {
    const store = new EncryptedBodyStore({ baseDir: sandbox, key: key() });
    await expect(store.writeBody("../../../etc/passwd", {})).rejects.toThrow(/invalid blob id/);
    await expect(store.writeBody("", {})).rejects.toThrow(/invalid blob id/);
  });

  it("rejects wrong key size", () => {
    expect(() => new EncryptedBodyStore({ baseDir: sandbox, key: Buffer.alloc(16) })).toThrow();
  });

  it("deleteBody removes the file and is idempotent", async () => {
    const store = new EncryptedBodyStore({ baseDir: sandbox, key: key() });
    const id = "req-deleteme";
    await store.writeBody(id, { response: classifyText("x") });
    expect(await store.hasBody(id)).toBe(true);
    expect(await store.deleteBody(id)).toBe(true);
    expect(await store.hasBody(id)).toBe(false);
    expect(await store.deleteBody(id)).toBe(false);
  });

  it("listBlobs reports per-id size + mtime", async () => {
    const store = new EncryptedBodyStore({ baseDir: sandbox, key: key() });
    await store.writeBody("req-alpha0001", { response: classifyText("a") });
    await store.writeBody("req-beta00002", { response: classifyText("bb") });
    const blobs = await store.listBlobs();
    expect(blobs.map((b) => b.blobId).sort()).toEqual([
      "req-alpha0001",
      "req-beta00002",
    ]);
    expect(blobs.every((b) => b.bytes > 0)).toBe(true);
  });
});
