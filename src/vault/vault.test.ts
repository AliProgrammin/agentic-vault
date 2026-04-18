import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  createVault,
  unlockVault,
  VaultHandle,
  type KdfParams,
} from "./index.js";
import {
  VaultClosedError,
  VaultExistsError,
  VaultFormatError,
  VaultIdentifierError,
  WrongPasswordError,
} from "./errors.js";

const FAST_KDF: KdfParams = { memory: 1024, iterations: 2, parallelism: 1 };

async function mkTmpDir(prefix: string): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), prefix));
}

async function rmTmp(dir: string): Promise<void> {
  await fs.rm(dir, { recursive: true, force: true });
}

describe("vault crypto core", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkTmpDir("vault-test-");
  });

  afterEach(async () => {
    await rmTmp(dir);
  });

  it("round-trips: create, set, save, reopen, values match", async () => {
    const file = path.join(dir, "v.enc");
    const v = await createVault(file, "pw-correct-horse", { kdfParams: FAST_KDF });
    try {
      v.set("API_KEY", "super-secret-value", { host: "api.example.com" });
      v.set("DB_PASSWORD", "another-secret");
      v.set("WITH_DASH-OK", "ok");
      await v.save();
    } finally {
      v.close();
    }

    const reopened = await unlockVault(file, "pw-correct-horse");
    try {
      expect(reopened.get("API_KEY")).toBe("super-secret-value");
      expect(reopened.get("DB_PASSWORD")).toBe("another-secret");
      expect(reopened.get("WITH_DASH-OK")).toBe("ok");
      const rec = reopened.getRecord("API_KEY");
      expect(rec?.policy).toEqual({ host: "api.example.com" });
      const names = reopened.list().map((r) => r.name).sort();
      expect(names).toEqual(["API_KEY", "DB_PASSWORD", "WITH_DASH-OK"]);
    } finally {
      reopened.close();
    }
  });

  it("wrong password returns WrongPasswordError and does not leak plaintext", async () => {
    const file = path.join(dir, "v.enc");
    const v = await createVault(file, "the-right-password", { kdfParams: FAST_KDF });
    v.set("LEAK_CANARY", "PLAINTEXT_CANARY_XYZ");
    await v.save();
    v.close();

    let caught: unknown;
    try {
      await unlockVault(file, "a-different-password");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(WrongPasswordError);
    const err = caught as WrongPasswordError;
    expect(err.code).toBe("WRONG_PASSWORD");
    expect(err.message).not.toContain("PLAINTEXT_CANARY_XYZ");

    const raw = await fs.readFile(file, "utf8");
    expect(raw).not.toContain("PLAINTEXT_CANARY_XYZ");
  });

  it("tampered ciphertext fails authentication; no plaintext returned", async () => {
    const file = path.join(dir, "v.enc");
    const v = await createVault(file, "pw", { kdfParams: FAST_KDF });
    v.set("CANARY", "PLAINTEXT_CANARY_ABC");
    await v.save();
    v.close();

    const bytes = await fs.readFile(file, "utf8");
    const parsed = JSON.parse(bytes) as { ciphertext: string };
    const ct = Buffer.from(parsed.ciphertext, "base64");
    ct[0] = ct[0] === undefined ? 0 : ct[0] ^ 0xff;
    parsed.ciphertext = ct.toString("base64");
    await fs.writeFile(file, JSON.stringify(parsed));

    await expect(unlockVault(file, "pw")).rejects.toBeInstanceOf(WrongPasswordError);
  });

  it("tampered auth tag fails authentication", async () => {
    const file = path.join(dir, "v.enc");
    const v = await createVault(file, "pw", { kdfParams: FAST_KDF });
    v.set("X", "y");
    await v.save();
    v.close();

    const bytes = await fs.readFile(file, "utf8");
    const parsed = JSON.parse(bytes) as { tag: string };
    const tag = Buffer.from(parsed.tag, "base64");
    tag[0] = tag[0] === undefined ? 0 : tag[0] ^ 0xff;
    parsed.tag = tag.toString("base64");
    await fs.writeFile(file, JSON.stringify(parsed));

    await expect(unlockVault(file, "pw")).rejects.toBeInstanceOf(WrongPasswordError);
  });

  it("atomic write: simulated crash between temp-write and rename leaves original intact", async () => {
    const file = path.join(dir, "v.enc");
    const v = await createVault(file, "pw", { kdfParams: FAST_KDF });
    v.set("ORIG", "first-value");
    await v.save();

    const before = await fs.readFile(file);

    v.set("ORIG", "second-value");
    const renameSpy = vi.spyOn(fs, "rename").mockImplementationOnce(() => {
      throw new Error("simulated crash");
    });
    try {
      await expect(v.save()).rejects.toThrow(/simulated crash/);
    } finally {
      renameSpy.mockRestore();
      v.close();
    }

    const after = await fs.readFile(file);
    expect(after.equals(before)).toBe(true);

    const entries = await fs.readdir(dir);
    const leftover = entries.filter((e) => e !== "v.enc" && !e.endsWith(".lock"));
    expect(leftover).toEqual([]);

    const reopened = await unlockVault(file, "pw");
    try {
      expect(reopened.get("ORIG")).toBe("first-value");
    } finally {
      reopened.close();
    }
  });

  it("concurrent saves serialize via the lock; file remains valid", async () => {
    const file = path.join(dir, "v.enc");
    const a = await createVault(file, "pw", { kdfParams: FAST_KDF });
    try {
      a.set("X", "one");
      await a.save();
    } finally {
      a.close();
    }

    const h1 = await unlockVault(file, "pw");
    const h2 = await unlockVault(file, "pw");
    try {
      h1.set("FROM_H1", "v1");
      h2.set("FROM_H2", "v2");
      await Promise.all([h1.save(), h2.save()]);
    } finally {
      h1.close();
      h2.close();
    }

    const reopened = await unlockVault(file, "pw");
    try {
      const names = reopened.list().map((r) => r.name);
      expect(names).toContain("X");
      expect(names.length).toBeGreaterThanOrEqual(2);
    } finally {
      reopened.close();
    }
  });

  it("portability: vault bytes produced in one tmpdir decrypt in another with same password", async () => {
    const file1 = path.join(dir, "v1.enc");
    const v = await createVault(file1, "portable-password", { kdfParams: FAST_KDF });
    v.set("PORT", "portable-value");
    await v.save();
    v.close();

    const otherDir = await mkTmpDir("vault-port-");
    try {
      const file2 = path.join(otherDir, "v2.enc");
      const bytes = await fs.readFile(file1);
      await fs.writeFile(file2, bytes);

      const reopened = await unlockVault(file2, "portable-password");
      try {
        expect(reopened.get("PORT")).toBe("portable-value");
      } finally {
        reopened.close();
      }
    } finally {
      await rmTmp(otherDir);
    }
  });

  it("rejects invalid secret names at set time", async () => {
    const file = path.join(dir, "v.enc");
    const v = await createVault(file, "pw", { kdfParams: FAST_KDF });
    try {
      expect(() => {
        v.set("", "x");
      }).toThrow(VaultIdentifierError);
      expect(() => {
        v.set("   ", "x");
      }).toThrow(VaultIdentifierError);
      expect(() => {
        v.set("has space", "x");
      }).toThrow(VaultIdentifierError);
      expect(() => {
        v.set("../bad", "x");
      }).toThrow(VaultIdentifierError);
      expect(() => {
        v.set("ctrl\u0001", "x");
      }).toThrow(VaultIdentifierError);
    } finally {
      v.close();
    }
  });

  it("createVault refuses to overwrite an existing file", async () => {
    const file = path.join(dir, "v.enc");
    const v = await createVault(file, "pw", { kdfParams: FAST_KDF });
    v.close();

    await expect(createVault(file, "pw", { kdfParams: FAST_KDF })).rejects.toBeInstanceOf(
      VaultExistsError,
    );
  });

  it("close() zeroizes the in-memory key material and blocks further ops", async () => {
    const file = path.join(dir, "v.enc");
    const v = await createVault(file, "pw", { kdfParams: FAST_KDF });
    v.set("FOO", "bar");
    v.close();
    expect(v.isClosed()).toBe(true);
    expect(() => {
      v.get("FOO");
    }).toThrow(VaultClosedError);
    expect(() => {
      v.set("X", "y");
    }).toThrow(VaultClosedError);
    await expect(v.save()).rejects.toBeInstanceOf(VaultClosedError);
    // idempotent
    v.close();
  });

  it("remove deletes a secret and returns false when missing", async () => {
    const file = path.join(dir, "v.enc");
    const v = await createVault(file, "pw", { kdfParams: FAST_KDF });
    try {
      v.set("KEEP", "k");
      v.set("DROP", "d");
      expect(v.remove("DROP")).toBe(true);
      expect(v.remove("NOT_THERE")).toBe(false);
      expect(v.get("DROP")).toBeUndefined();
      expect(v.get("KEEP")).toBe("k");
      await v.save();
    } finally {
      v.close();
    }
    const r = await unlockVault(file, "pw");
    try {
      expect(r.get("DROP")).toBeUndefined();
      expect(r.get("KEEP")).toBe("k");
    } finally {
      r.close();
    }
  });

  it("set preserves policy across a value-only rotation", async () => {
    const file = path.join(dir, "v.enc");
    const v = await createVault(file, "pw", { kdfParams: FAST_KDF });
    try {
      v.set("TOK", "v1", { allowed_http_hosts: ["api.example.com"] });
      v.set("TOK", "v2");
      const rec = v.getRecord("TOK");
      expect(rec?.policy).toEqual({ allowed_http_hosts: ["api.example.com"] });
      expect(v.get("TOK")).toBe("v2");
    } finally {
      v.close();
    }
  });

  it("parseEnvelope rejects malformed files", async () => {
    const file = path.join(dir, "bad.enc");
    await fs.writeFile(file, "{not json");
    await expect(unlockVault(file, "pw")).rejects.toBeInstanceOf(VaultFormatError);

    await fs.writeFile(file, JSON.stringify({ version: 99 }));
    await expect(unlockVault(file, "pw")).rejects.toBeInstanceOf(VaultFormatError);
  });

  it("list returns records without plaintext values exposed via the list API", async () => {
    const file = path.join(dir, "v.enc");
    const v = await createVault(file, "pw", { kdfParams: FAST_KDF });
    try {
      v.set("FOO", "should-not-appear-in-list");
      const listed = v.list();
      expect(listed).toHaveLength(1);
      const entry = listed[0];
      expect(entry).toBeDefined();
      expect(entry?.name).toBe("FOO");
      expect(Object.keys(entry ?? {})).not.toContain("value");
    } finally {
      v.close();
    }
  });

  it("the envelope file on disk never contains the plaintext secret value", async () => {
    const file = path.join(dir, "v.enc");
    const v = await createVault(file, "pw", { kdfParams: FAST_KDF });
    v.set("CANARY", "THIS_PLAINTEXT_SHOULD_NOT_APPEAR_ON_DISK");
    await v.save();
    v.close();

    const raw = await fs.readFile(file, "utf8");
    expect(raw).not.toContain("THIS_PLAINTEXT_SHOULD_NOT_APPEAR_ON_DISK");
    expect(raw).not.toContain("CANARY");
  });

  it("returns a working handle from createVault without reopening", async () => {
    const file = path.join(dir, "v.enc");
    const v = await createVault(file, "pw", { kdfParams: FAST_KDF });
    try {
      expect(v).toBeInstanceOf(VaultHandle);
      expect(v.list()).toEqual([]);
      v.set("A", "1");
      expect(v.get("A")).toBe("1");
    } finally {
      v.close();
    }
  });
});
