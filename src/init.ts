import * as p from "@clack/prompts";
import { homedir } from "node:os";
import { allBackends, detectBackends } from "./backends/index.js";
import { OnePasswordBackend } from "./backends/onepassword.js";
import { AGENTS, type AgentId } from "./install/agents.js";
import { install, uninstall } from "./install/index.js";
import type { Config } from "./policy/config.js";
import { runWithSecrets } from "./runner/spawn.js";

export interface InitFlags {
  store?: string;
  vault?: string;
  agents?: string;
  yes?: boolean;
  home?: string;
}

function cancelled(v: unknown): asserts v is Exclude<typeof v, symbol> {
  if (p.isCancel(v)) {
    p.cancel("Cancelled. Nothing was changed.");
    process.exit(0);
  }
}

/** Round trip that leaves no residue: injection + redaction work and the store is reachable. */
async function selfTest(storeId: string, cfg: Config): Promise<string[]> {
  const problems: string[] = [];
  const fake = "selftest-" + Math.random().toString(36).slice(2, 12);
  const r = await runWithSecrets('echo "value=$AV_SELFTEST"', { AV_SELFTEST: fake });
  if (r.output.includes(fake) || !r.output.includes("[REDACTED]")) problems.push("output redaction failed");
  const b = allBackends(cfg).find((x) => x.id === storeId);
  if (!b || !(await b.available())) problems.push("store is not reachable");
  else await b.list().catch((e: Error) => problems.push(`store list failed: ${e.message}`));
  return problems;
}

export async function init(flags: InitFlags): Promise<void> {
  const home = flags.home ?? homedir();
  const interactive = !flags.yes && process.stdin.isTTY;
  p.intro("agent-vault setup");

  // 1. Stores: show what exists and how full each already is.
  const s = p.spinner();
  s.start("Looking for password stores");
  const detected = await detectBackends({ onepasswordVault: flags.vault });
  s.stop("Found stores");
  const ready = detected.filter((d) => d.available);
  const missing = detected.filter((d) => !d.available);
  if (missing.length) {
    p.note(missing.map((d) => `${d.backend.label}: ${d.installHint}`).join("\n"), "Not available");
  }
  if (ready.length === 0) {
    p.cancel("No supported password store is available. Install one of the above and re-run.");
    process.exit(1);
  }

  let storeId = flags.store;
  if (storeId && !ready.some((d) => d.backend.id === storeId)) {
    p.cancel(`Store "${storeId}" is not available. Ready: ${ready.map((d) => d.backend.id).join(", ")}`);
    process.exit(1);
  }
  if (!storeId) {
    if (!interactive) storeId = ready[0].backend.id;
    else {
      const choice = await p.select({
        message: "Which store should hold your agent secrets?",
        options: ready.map((d) => ({
          value: d.backend.id,
          label: d.backend.label,
          hint: `${d.count ?? "?"} agent-vault ${d.count === 1 ? "entry" : "entries"} already stored`,
        })),
      });
      cancelled(choice);
      storeId = choice as string;
    }
  }

  // 2. 1Password: which vault.
  let vault = flags.vault;
  if (storeId === "1password" && !vault && interactive) {
    const vaults = await new OnePasswordBackend().vaults();
    if (vaults.length > 1) {
      const v = await p.select({ message: "Which 1Password vault?", options: vaults.map((n) => ({ value: n, label: n })) });
      cancelled(v);
      vault = v as string;
    } else vault = vaults[0];
  }
  const config: Config = { defaultBackend: storeId, ...(vault ? { onepasswordVault: vault } : {}) };

  // 3. Agents.
  const found = await Promise.all(AGENTS.map(async (a) => ({ a, found: await a.detect(home) })));
  let agents: AgentId[];
  if (flags.agents) {
    agents = flags.agents.split(",").map((x) => x.trim()) as AgentId[];
    const bad = agents.filter((x) => !AGENTS.some((a) => a.id === x));
    if (bad.length) {
      p.cancel(`Unknown agent(s): ${bad.join(", ")}. Choose from: ${AGENTS.map((a) => a.id).join(", ")}`);
      process.exit(1);
    }
  } else if (!interactive) agents = found.filter((f) => f.found).map((f) => f.a.id);
  else {
    const pick = await p.multiselect({
      message: "Which agents should use it?",
      options: found.map((f) => ({ value: f.a.id, label: f.a.label, hint: f.found ? "detected" : "not detected" })),
      initialValues: found.filter((f) => f.found).map((f) => f.a.id),
      required: true,
    });
    cancelled(pick);
    agents = pick as AgentId[];
  }
  if (agents.length === 0) {
    p.cancel("No agents selected or detected.");
    process.exit(1);
  }

  // 4. Preview and confirm.
  p.note(
    [
      `Store: ${ready.find((d) => d.backend.id === storeId)!.backend.label}${vault ? ` (vault ${vault})` : ""}`,
      ...AGENTS.filter((a) => agents.includes(a.id)).flatMap((a) => [`${a.label}:`, ...a.files(home).map((f) => `  ${f}`)]),
      `Backups: ${home}/.config/agent-vault/backups/`,
    ].join("\n"),
    "This will change",
  );
  if (interactive) {
    const ok = await p.confirm({ message: "Apply these changes?" });
    cancelled(ok);
    if (!ok) {
      p.cancel("Nothing was changed.");
      return;
    }
  }

  // 5. Apply and test.
  const s2 = p.spinner();
  s2.start("Installing");
  const reports = await install({ home, agents, config });
  s2.stop("Installed");
  p.note(reports.flatMap((r) => r.actions.map((a) => `${r.agent}: ${a}`)).join("\n"), "Done");

  const problems = await selfTest(storeId, config);
  if (problems.length) p.log.warn(`Self-test problems: ${problems.join("; ")}. Run \`agent-vault doctor\`.`);
  else p.log.success("Self-test passed (injection, redaction, store reachable).");
  p.outro("Restart Claude Code / Cursor so they pick up the new MCP server. Undo anytime with `agent-vault uninstall`.");
}

export async function runUninstall(flags: { home?: string; agents?: string }): Promise<void> {
  p.intro("agent-vault uninstall");
  const reports = await uninstall({ home: flags.home, agents: flags.agents?.split(",") as AgentId[] | undefined });
  const lines = reports.flatMap((r) => r.actions.map((a) => `${r.agent}: ${a}`));
  p.note(lines.join("\n") || "Nothing to remove.", "Removed");
  p.outro("Your stored secrets were left untouched in your password store.");
}
