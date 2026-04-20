import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { EncryptedBodyStore } from "./body-store.js";
import { classifyText } from "./body-artifact.js";
import { pruneBodies } from "./prune.js";

async function mkSandbox(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "secretproxy-prune-"));
}

async function setMtime(p: string, when: number): Promise<void> {
  await fs.utimes(p, when / 1000, when / 1000);
}

describe("pruneBodies", () => {
  let sandbox: string;
  beforeEach(async () => { sandbox = await mkSandbox(); });
  afterEach(async () => { await fs.rm(sandbox, { recursive: true, force: true }); });

  it("removes blobs older than maxAgeMs", async () => {
    const store = new EncryptedBodyStore({ baseDir: sandbox, key: crypto.randomBytes(32) });
    await store.writeBody("req-fresh-001", { response: classifyText("a") });
    await store.writeBody("req-stale-001", { response: classifyText("b") });
    // Backdate the second blob.
    await setMtime(store.pathFor("req-stale-001"), Date.now() - 3 * 24 * 60 * 60 * 1000);
    const r = await pruneBodies(store, { maxAgeMs: 24 * 60 * 60 * 1000 });
    expect(r.removedByAge).toEqual(["req-stale-001"]);
    expect(r.removedBySize).toHaveLength(0);
    expect(await store.hasBody("req-fresh-001")).toBe(true);
    expect(await store.hasBody("req-stale-001")).toBe(false);
  });

  it("removes oldest blobs when over the size cap", async () => {
    const store = new EncryptedBodyStore({ baseDir: sandbox, key: crypto.randomBytes(32) });
    await store.writeBody("req-oldest-01", { response: classifyText("a".repeat(1000)) });
    await new Promise((resolve) => setTimeout(resolve, 10));
    await store.writeBody("req-middle-01", { response: classifyText("b".repeat(1000)) });
    await new Promise((resolve) => setTimeout(resolve, 10));
    await store.writeBody("req-newest-01", { response: classifyText("c".repeat(1000)) });
    // Total > 2000 bytes; cap of 2000 should evict only req-oldest-01.
    const r = await pruneBodies(store, {
      maxAgeMs: Number.MAX_SAFE_INTEGER,
      maxBytes: 2000,
    });
    expect(r.removedByAge).toEqual([]);
    expect(r.removedBySize[0]).toBe("req-oldest-01");
    expect(await store.hasBody("req-oldest-01")).toBe(false);
    expect(await store.hasBody("req-newest-01")).toBe(true);
  });

  it("is a no-op on an empty store", async () => {
    const store = new EncryptedBodyStore({ baseDir: sandbox, key: crypto.randomBytes(32) });
    const r = await pruneBodies(store);
    expect(r.removedByAge).toHaveLength(0);
    expect(r.removedBySize).toHaveLength(0);
    expect(r.bytesBefore).toBe(0);
  });
});
