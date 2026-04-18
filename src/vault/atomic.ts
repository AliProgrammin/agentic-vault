import { promises as fs } from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";

export async function atomicWriteFile(
  destPath: string,
  data: Buffer | string,
): Promise<void> {
  const dir = path.dirname(destPath);
  const base = path.basename(destPath);
  const suffix = crypto.randomBytes(8).toString("hex");
  const tempPath = path.join(dir, `.${base}.${suffix}.tmp`);

  let tempHandle;
  try {
    tempHandle = await fs.open(tempPath, "w", 0o600);
    await tempHandle.writeFile(data);
    await tempHandle.sync();
  } finally {
    if (tempHandle !== undefined) {
      await tempHandle.close();
    }
  }

  try {
    await fs.rename(tempPath, destPath);
  } catch (err) {
    await fs.unlink(tempPath).catch(() => undefined);
    throw err;
  }

  await fsyncDir(dir);
}

async function fsyncDir(dirPath: string): Promise<void> {
  let handle;
  try {
    handle = await fs.open(dirPath, "r");
    await handle.sync();
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "EISDIR" || code === "EPERM" || code === "EACCES") {
      return;
    }
    if (process.platform === "win32") {
      return;
    }
    throw err;
  } finally {
    if (handle !== undefined) {
      await handle.close();
    }
  }
}
