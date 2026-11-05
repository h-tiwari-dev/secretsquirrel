import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export interface Config {
  defaultBackend: string; // keychain | 1password | bitwarden | pass | gopass
  onepasswordVault?: string;
  /** Extra stores searched (read-only fallback) after the default, in order. */
  fallbacks?: string[];
  /** Per-secret program allowlist, e.g. { "GITHUB_TOKEN": ["gh","git"], "AWS_*": ["aws"] }. Names may end in *. */
  allow?: Record<string, string[]>;
  /** Minutes an identical, already-approved command may re-run without a new popup. Default 10, 0 disables. */
  approvalTtlMinutes?: number;
}

export const CONFIG_PATH = process.env.AGENT_VAULT_CONFIG ?? join(homedir(), ".config", "agent-vault", "config.json");

export async function loadConfig(path: string = CONFIG_PATH): Promise<Config> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as Config;
  } catch {
    return { defaultBackend: "keychain" };
  }
}

export async function saveConfig(c: Config, path: string = CONFIG_PATH): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(c, null, 2) + "\n", { mode: 0o600 });
}
