#!/usr/bin/env node
// Guard-hook fast path. It must not load anything else: a crash while loading unrelated modules would exit 1,
// which agents treat as "hook error, carry on", silently disabling the guard. Any failure here exits 2 (block).
if (process.argv[2] === "hook") {
  const agent = process.argv[3];
  if (agent !== "claude" && agent !== "cursor") {
    process.stderr.write("agent-vault hook failed closed: agent must be claude or cursor\n");
    process.exit(2);
  }
  try {
    await (await import("./hooks/index.js")).runHook(agent);
  } catch (e) {
    process.stderr.write(`agent-vault hook failed closed: ${(e as Error).message}\n`);
    process.exit(2);
  }
  process.exit(process.exitCode ?? 0);
}

const { Command } = await import("commander");
const { defaultBackend } = await import("./backends/index.js");
const { startMcp } = await import("./mcp/server.js");
const { Vault } = await import("./vault.js");

const program = new Command("agent-vault").description("Secret prompts for Claude Code and Cursor agents");

program
  .command("init")
  .description("Interactive setup: pick a store and which agents to wire up")
  .option("--store <id>", "keychain | 1password | bitwarden | pass | gopass")
  .option("--vault <name>", "1Password vault name")
  .option("--agents <list>", "comma list: claude,cursor")
  .option("-y, --yes", "non-interactive; accept defaults")
  .option("--home <dir>", "install into a different home directory (testing)")
  .action(async (o) => (await import("./init.js")).init(o));

program
  .command("uninstall")
  .description("Remove agent-vault from Claude Code and Cursor (stored secrets are kept)")
  .option("--agents <list>", "comma list: claude,cursor")
  .option("--home <dir>", "home directory (testing)")
  .action(async (o) => (await import("./init.js")).runUninstall(o));

program.command("mcp").description("Run the MCP server on stdio").action(async () => {
  await startMcp();
});

program.command("list").description("List stored secret names").action(async () => {
  const { backend, names } = await new Vault(await defaultBackend()).listNames();
  console.log(`${backend}:\n${names.map((n) => "  " + n).join("\n") || "  (none)"}`);
});

program.command("set <name>").description("Add or replace a secret via popup").action(async (name: string) => {
  console.log(JSON.stringify(await new Vault(await defaultBackend()).requestSecret(name, "Added from CLI")));
});

program.command("rollback <name>").description("Restore the previous value of a secret (swap; run twice to undo)").action(async (name: string) => {
  console.log(JSON.stringify(await new Vault(await defaultBackend()).rollback(name)));
});

program.command("doctor").description("Show detected secret stores and how many entries each holds").action(async () => {
  const { detectBackends } = await import("./backends/index.js");
  const { loadConfig } = await import("./policy/config.js");
  const cfg = await loadConfig();
  for (const d of await detectBackends(cfg)) {
    const mark = d.backend.id === cfg.defaultBackend ? " (default)" : "";
    const status = d.available ? `ready, ${d.count ?? "?"} agent-vault entries` : `unavailable: ${d.installHint}`;
    console.log(`${d.available ? "✔" : "✗"} ${d.backend.label}${mark} — ${status}`);
  }
});

program.parseAsync().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
