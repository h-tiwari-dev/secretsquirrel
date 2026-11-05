import { loadConfig, type Config } from "../policy/config.js";
import { BitwardenBackend } from "./bitwarden.js";
import { KeychainBackend } from "./keychain.js";
import { OnePasswordBackend } from "./onepassword.js";
import { PassBackend } from "./pass.js";
import type { Backend } from "./types.js";

export function allBackends(cfg: Partial<Config> = {}): Backend[] {
  return [
    new KeychainBackend(),
    new OnePasswordBackend(cfg.onepasswordVault),
    new BitwardenBackend(),
    new PassBackend("pass"),
    new PassBackend("gopass"),
  ];
}

export interface Detected {
  backend: Backend;
  available: boolean;
  count?: number;
  installHint: string;
}

const HINTS: Record<string, string> = {
  keychain: "macOS only",
  "1password": "install `op` and run `op signin`",
  bitwarden: "install `bw`, then `export BW_SESSION=$(bw unlock --raw)`",
  pass: "install `pass` (brew install pass)",
  gopass: "install `gopass` (brew install gopass)",
};

/** Used by the init wizard: which stores exist, and how many agent-vault entries each already holds. */
export async function detectBackends(cfg: Partial<Config> = {}): Promise<Detected[]> {
  return Promise.all(
    allBackends(cfg).map(async (backend) => {
      const available = await backend.available().catch(() => false);
      const count = available ? await backend.list().then((l) => l.length).catch(() => undefined) : undefined;
      return { backend, available, count, installHint: HINTS[backend.id] ?? "" };
    }),
  );
}

export async function defaultBackend(): Promise<Backend> {
  const cfg = await loadConfig();
  const b = allBackends(cfg).find((x) => x.id === cfg.defaultBackend);
  if (!b) throw new Error(`Unknown backend "${cfg.defaultBackend}" in config.`);
  if (!(await b.available())) throw new Error(`Configured backend "${b.label}" is not available. Run \`agent-vault doctor\`.`);
  return b;
}
