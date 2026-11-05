import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

/** Small JSON state shared by the hook, `exec` and the MCP server (separate processes). Never contains secret values. */
export const stateDir = () => process.env.AGENT_VAULT_DIR ?? join(homedir(), ".config", "agent-vault");

async function readJson<T>(file: string, fallback: T): Promise<T> {
  try {
    return JSON.parse(await readFile(join(stateDir(), file), "utf8")) as T;
  } catch {
    return fallback;
  }
}
async function writeJson(file: string, data: unknown): Promise<void> {
  await mkdir(stateDir(), { recursive: true, mode: 0o700 });
  const p = join(stateDir(), file);
  const tmp = `${p}.${process.pid}.tmp`;
  await writeFile(tmp, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
  await rename(tmp, p);
}

/** Names known to be in the store, so the hook can recognise `$NAME` without calling a slow password manager. */
export const readNames = (): Promise<string[] | undefined> => readJson<string[] | undefined>("names.json", undefined);
export const writeNames = (names: string[]) => writeJson("names.json", [...new Set(names)].sort());
export async function addName(name: string): Promise<void> {
  const cur = (await readNames()) ?? [];
  if (!cur.includes(name)) await writeNames([...cur, name]);
}

/** Which programs the user allowed to use which secret: { GITHUB_TOKEN: ["gh","git"] }. */
export type Grants = Record<string, string[]>;
export const loadGrants = (): Promise<Grants> => readJson<Grants>("grants.json", {});
export async function addGrants(names: string[], exes: string[]): Promise<void> {
  const g = await loadGrants();
  for (const n of names) g[n] = [...new Set([...(g[n] ?? []), ...exes])].sort();
  await writeJson("grants.json", g);
}
export async function revokeGrants(name?: string): Promise<void> {
  const g = await loadGrants();
  if (name) delete g[name];
  await writeJson("grants.json", name ? g : {});
}

/** Auth failures recorded by `exec`, consumed by update_secret in the MCP server. */
export interface FailureRecord { at: number; command: string; exitCode: number | null; snippet: string }
export const readFailures = (): Promise<Record<string, FailureRecord>> => readJson("failures.json", {});
export async function recordFailures(names: string[], rec: FailureRecord): Promise<void> {
  const f = await readFailures();
  for (const n of names) f[n] = rec;
  await writeJson("failures.json", f);
}
export async function clearFailures(names: string[]): Promise<void> {
  const f = await readFailures();
  let changed = false;
  for (const n of names) if (n in f) { delete f[n]; changed = true; }
  if (changed) await writeJson("failures.json", f);
}
