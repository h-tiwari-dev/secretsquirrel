import { copyFile, mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { createHash } from "node:crypto";

export const dataDir = (home: string) => join(home, ".config", "agent-vault");
const manifestPath = (home: string) => join(dataDir(home), "install.json");

export interface Manifest {
  /** Files that did not exist before we wrote them. Removed on uninstall if left empty. */
  created: string[];
}

export async function readManifest(home: string): Promise<Manifest> {
  try {
    return JSON.parse(await readFile(manifestPath(home), "utf8")) as Manifest;
  } catch {
    return { created: [] };
  }
}
export async function writeManifest(home: string, m: Manifest): Promise<void> {
  await mkdir(dataDir(home), { recursive: true });
  await writeFile(manifestPath(home), JSON.stringify(m, null, 2) + "\n", { mode: 0o600 });
}

/** Parse JSON or fail loudly. We must never overwrite a config we could not parse. */
export async function readJson(path: string): Promise<Record<string, any>> {
  if (!existsSync(path)) return {};
  const raw = await readFile(path, "utf8");
  if (raw.trim() === "") return {};
  try {
    const v = JSON.parse(raw);
    if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Error("not an object");
    return v;
  } catch (e) {
    throw new Error(`Refusing to modify ${path}: it is not valid JSON (${(e as Error).message}). Fix it and re-run.`);
  }
}

export async function backup(home: string, path: string, stamp: string): Promise<string | undefined> {
  if (!existsSync(path)) return undefined;
  const dir = join(dataDir(home), "backups", stamp);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const dest = join(dir, `${createHash("sha1").update(path).digest("hex").slice(0, 8)}-${basename(path)}`);
  await copyFile(path, dest);
  return dest;
}

/** Match the file's existing style (indent, trailing newline) so edits are minimal diffs and uninstall can restore bytes exactly. */
function detectStyle(raw: string | undefined): { indent: string | number; trailingNewline: boolean } {
  if (raw === undefined) return { indent: 2, trailingNewline: true };
  const m = raw.match(/\n([ \t]+)\S/);
  const indent = m ? (m[1].startsWith("\t") ? "\t" : m[1].length) : 2;
  return { indent, trailingNewline: raw.endsWith("\n") };
}

/** Atomic replace: write temp in the same dir, then rename. */
export async function writeJsonAtomic(path: string, value: unknown, mode = 0o600): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const raw = existsSync(path) ? await readFile(path, "utf8") : undefined;
  const { indent, trailingNewline } = detectStyle(raw);
  const tmp = `${path}.agent-vault.${process.pid}.tmp`;
  let mode2 = mode;
  if (raw !== undefined) mode2 = (await stat(path)).mode & 0o777; // keep the original permissions
  await writeFile(tmp, JSON.stringify(value, null, indent) + (trailingNewline ? "\n" : ""), { mode: mode2 });
  await rename(tmp, path);
}

export async function removeIfExists(path: string): Promise<void> {
  await rm(path, { recursive: true, force: true });
}
