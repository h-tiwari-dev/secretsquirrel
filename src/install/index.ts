import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
import { run } from "../backends/exec.js";
import { saveConfig, type Config } from "../policy/config.js";
import { AGENTS, type AgentId, type InstallCtx } from "./agents.js";
import { dataDir, readManifest, removeIfExists, writeManifest } from "./fsutil.js";

/** How agents will launch us: this exact node binary plus this exact built cli.js (works before and without npm publish). */
export function defaultServer(): { server: { command: string; args: string[] }; skillSource: string } {
  const cli = realpathSync(process.argv[1]);
  if (basename(cli) !== "cli.js") {
    throw new Error("Run the built CLI (`npm run build`, then `node dist/cli.js init`); installing from a dev/tsx entry would register a path that agents can't launch.");
  }
  return { server: { command: process.execPath, args: [cli, "mcp"] }, skillSource: join(dirname(cli), "..", "assets", "SKILL.md") };
}

export interface InstallOptions {
  home?: string;
  agents: AgentId[];
  config: Config;
  server?: { command: string; args: string[] };
  skillSource?: string;
  useClaudeCli?: boolean;
  claudeOnFailureBlock?: boolean;
}

async function claudeSupportsOnFailure(): Promise<boolean> {
  const r = await run("claude", ["--version"], { timeoutMs: 10_000 }).catch(() => undefined);
  const m = r?.stdout.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!m) return false;
  const [a, b, c] = [Number(m[1]), Number(m[2]), Number(m[3])];
  return a > 2 || (a === 2 && (b > 1 || (b === 1 && c >= 295)));
}

export interface InstallReport {
  agent: AgentId;
  actions: string[];
}

const stampNow = () => new Date().toISOString().replace(/[:.]/g, "-");

export async function install(opts: InstallOptions): Promise<InstallReport[]> {
  const home = opts.home ?? homedir();
  const d = opts.server && opts.skillSource ? { server: opts.server, skillSource: opts.skillSource } : defaultServer();
  const manifest = await readManifest(home);
  const ctx: InstallCtx = {
    home,
    stamp: stampNow(),
    server: d.server,
    skillSource: d.skillSource,
    manifest,
    useClaudeCli: opts.useClaudeCli ?? home === homedir(),
  };
  if (opts.claudeOnFailureBlock !== undefined) ctx.claudeOnFailureBlock = opts.claudeOnFailureBlock;
  else if (ctx.useClaudeCli) ctx.claudeOnFailureBlock = await claudeSupportsOnFailure();
  const reports: InstallReport[] = [];
  for (const a of AGENTS.filter((x) => opts.agents.includes(x.id))) {
    reports.push({ agent: a.id, actions: await a.install(ctx) });
  }
  await saveConfig(opts.config, join(dataDir(home), "config.json"));
  await writeManifest(home, manifest);
  return reports;
}

export async function uninstall(opts: { home?: string; agents?: AgentId[]; useClaudeCli?: boolean }): Promise<InstallReport[]> {
  const home = opts.home ?? homedir();
  const manifest = await readManifest(home);
  const ctx: InstallCtx = {
    home,
    stamp: stampNow(),
    server: { command: "", args: [] },
    skillSource: "",
    manifest,
    useClaudeCli: opts.useClaudeCli ?? home === homedir(),
  };
  const reports: InstallReport[] = [];
  for (const a of AGENTS.filter((x) => !opts.agents || opts.agents.includes(x.id))) {
    reports.push({ agent: a.id, actions: await a.uninstall(ctx) });
  }
  if (!opts.agents || AGENTS.every((x) => opts.agents!.includes(x.id))) {
    // Full uninstall: drop our own bookkeeping. Backups and the audit log stay on purpose.
    await removeIfExists(join(dataDir(home), "install.json"));
    await removeIfExists(join(dataDir(home), "config.json"));
  } else {
    await writeManifest(home, { created: manifest.created.filter((p) => !reports.some((r) => r.actions.some((s) => s.includes(p)))) });
  }
  return reports;
}
