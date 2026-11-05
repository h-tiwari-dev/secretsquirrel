import { copyFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { commandExists, run } from "../backends/exec.js";
import { backup, readJson, removeIfExists, writeJsonAtomic, type Manifest } from "./fsutil.js";

export const SERVER_NAME = "agent-vault";

export interface InstallCtx {
  home: string;
  stamp: string;
  /** How agents launch our MCP server. */
  server: { command: string; args: string[] };
  /** Absolute path of the SKILL.md to copy. */
  skillSource: string;
  manifest: Manifest;
  /** Use `claude mcp add` instead of editing ~/.claude.json. Only safe against the real home. */
  useClaudeCli: boolean;
  /** Claude Code >= 2.1.295 supports "onFailure": "block" so a timed-out guard hook blocks instead of allowing. */
  claudeOnFailureBlock?: boolean;
}

export type AgentId = "claude" | "cursor";

export interface AgentInfo {
  id: AgentId;
  label: string;
  /** Files this installer will create or modify, for the preview. */
  files(home: string): string[];
  detect(home: string): Promise<boolean>;
  install(ctx: InstallCtx): Promise<string[]>;
  uninstall(ctx: InstallCtx): Promise<string[]>;
}

async function installSkill(ctx: InstallCtx, dir: string): Promise<string> {
  const dest = join(dir, "SKILL.md");
  await mkdir(dir, { recursive: true });
  await backup(ctx.home, dest, ctx.stamp);
  await copyFile(ctx.skillSource, dest);
  if (!ctx.manifest.created.includes(dest)) ctx.manifest.created.push(dest);
  return `skill → ${dest}`;
}

/** Merge our server entry into a JSON file's mcpServers, keeping everything else byte-for-byte semantically. */
async function mergeMcp(ctx: InstallCtx, path: string, entry: Record<string, unknown>): Promise<string> {
  const existed = existsSync(path);
  const cfg = await readJson(path);
  await backup(ctx.home, path, ctx.stamp);
  cfg.mcpServers = { ...(cfg.mcpServers ?? {}), [SERVER_NAME]: entry };
  await writeJsonAtomic(path, cfg);
  if (!existed && !ctx.manifest.created.includes(path)) ctx.manifest.created.push(path);
  return `mcp server → ${path}`;
}

async function unmergeMcp(ctx: InstallCtx, path: string): Promise<string | undefined> {
  if (!existsSync(path)) return undefined;
  const cfg = await readJson(path);
  if (!cfg.mcpServers || !(SERVER_NAME in cfg.mcpServers)) return undefined;
  await backup(ctx.home, path, ctx.stamp);
  delete cfg.mcpServers[SERVER_NAME];
  if (Object.keys(cfg.mcpServers).length === 0) delete cfg.mcpServers;
  if (Object.keys(cfg).length === 0 && ctx.manifest.created.includes(path)) await removeIfExists(path);
  else await writeJsonAtomic(path, cfg);
  return `removed mcp server from ${path}`;
}


const shq = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
// `|| exit 2`: if node or cli.js is missing the shell reports 127, which agents treat as a harmless hook error. Turn that into a block.
const hookCommand = (ctx: InstallCtx, kind: "claude" | "cursor") => `${shq(ctx.server.command)} ${shq(ctx.server.args[0])} hook ${kind} || exit 2`;
/** Recognise our own hook entries on uninstall/re-install without a marker field agents might reject. */
const isOurHook = (cmd: unknown, kind: "claude" | "cursor") =>
  typeof cmd === "string" && new RegExp(` hook ${kind}( \\|\\| exit 2)?$`).test(cmd) && cmd.includes("cli.js");

async function mergeClaudeHook(ctx: InstallCtx): Promise<string> {
  const path = join(ctx.home, ".claude", "settings.json");
  const existed = existsSync(path);
  const cfg = await readJson(path);
  await backup(ctx.home, path, ctx.stamp);
  const groups: any[] = (cfg.hooks?.PreToolUse ?? [])
    .map((g: any) => ({ ...g, hooks: (g.hooks ?? []).filter((h: any) => !isOurHook(h.command, "claude")) }))
    .filter((g: any) => g.hooks.length > 0);
  const handler: Record<string, unknown> = { type: "command", command: hookCommand(ctx, "claude"), timeout: 130 };
  if (ctx.claudeOnFailureBlock) handler.onFailure = "block";
  groups.push({ matcher: "Bash", hooks: [handler] });
  cfg.hooks = { ...(cfg.hooks ?? {}), PreToolUse: groups };
  await writeJsonAtomic(path, cfg);
  if (!existed && !ctx.manifest.created.includes(path)) ctx.manifest.created.push(path);
  return `guard hook → ${path} (PreToolUse/Bash)`;
}

async function unmergeClaudeHook(ctx: InstallCtx): Promise<string | undefined> {
  const path = join(ctx.home, ".claude", "settings.json");
  if (!existsSync(path)) return undefined;
  const cfg = await readJson(path);
  const pre: any[] | undefined = cfg.hooks?.PreToolUse;
  if (!pre || !JSON.stringify(pre).includes(" hook claude")) return undefined;
  await backup(ctx.home, path, ctx.stamp);
  const kept = pre
    .map((g: any) => ({ ...g, hooks: (g.hooks ?? []).filter((h: any) => !isOurHook(h.command, "claude")) }))
    .filter((g: any) => g.hooks.length > 0);
  if (kept.length) cfg.hooks.PreToolUse = kept;
  else delete cfg.hooks.PreToolUse;
  if (Object.keys(cfg.hooks).length === 0) delete cfg.hooks;
  if (Object.keys(cfg).length === 0 && ctx.manifest.created.includes(path)) await removeIfExists(path);
  else await writeJsonAtomic(path, cfg);
  return `removed guard hook from ${path}`;
}

async function mergeCursorHook(ctx: InstallCtx): Promise<string> {
  const path = join(ctx.home, ".cursor", "hooks.json");
  const existed = existsSync(path);
  const cfg = await readJson(path);
  await backup(ctx.home, path, ctx.stamp);
  const list: any[] = (cfg.hooks?.beforeShellExecution ?? []).filter((h: any) => !isOurHook(h.command, "cursor"));
  list.push({ command: hookCommand(ctx, "cursor"), timeout: 10, failClosed: true });
  cfg.version ??= 1;
  cfg.hooks = { ...(cfg.hooks ?? {}), beforeShellExecution: list };
  await writeJsonAtomic(path, cfg);
  if (!existed && !ctx.manifest.created.includes(path)) ctx.manifest.created.push(path);
  return `guard hook → ${path} (beforeShellExecution)`;
}

async function unmergeCursorHook(ctx: InstallCtx): Promise<string | undefined> {
  const path = join(ctx.home, ".cursor", "hooks.json");
  if (!existsSync(path)) return undefined;
  const cfg = await readJson(path);
  const list: any[] | undefined = cfg.hooks?.beforeShellExecution;
  if (!list || !list.some((h: any) => isOurHook(h.command, "cursor"))) return undefined;
  await backup(ctx.home, path, ctx.stamp);
  const kept = list.filter((h: any) => !isOurHook(h.command, "cursor"));
  if (kept.length) cfg.hooks.beforeShellExecution = kept;
  else delete cfg.hooks.beforeShellExecution;
  if (Object.keys(cfg.hooks).length === 0) delete cfg.hooks;
  const created = ctx.manifest.created.includes(path);
  if (created && Object.keys(cfg).every((k) => k === "version")) await removeIfExists(path);
  else await writeJsonAtomic(path, cfg);
  return `removed guard hook from ${path}`;
}

export const claude: AgentInfo = {
  id: "claude",
  label: "Claude Code",
  files: (home) => [
    join(home, ".claude.json") + " (mcpServers)",
    join(home, ".claude", "settings.json") + " (PreToolUse guard hook)",
    join(home, ".claude", "skills", SERVER_NAME, "SKILL.md"),
  ],
  detect: async (home) => existsSync(join(home, ".claude")) || (await commandExists("claude")),

  async install(ctx) {
    const done: string[] = [];
    if (ctx.useClaudeCli && (await commandExists("claude"))) {
      await run("claude", ["mcp", "remove", SERVER_NAME, "--scope", "user"]).catch(() => undefined); // idempotent re-install
      const r = await run("claude", ["mcp", "add", "--scope", "user", SERVER_NAME, "--", ctx.server.command, ...ctx.server.args]);
      if (r.code !== 0) throw new Error(`\`claude mcp add\` failed: ${r.stderr.trim() || r.stdout.trim()}`);
      done.push("mcp server → claude mcp add (user scope)");
    } else {
      done.push(await mergeMcp(ctx, join(ctx.home, ".claude.json"), { type: "stdio", command: ctx.server.command, args: ctx.server.args, env: {} }));
    }
    done.push(await mergeClaudeHook(ctx));
    done.push(await installSkill(ctx, join(ctx.home, ".claude", "skills", SERVER_NAME)));
    return done;
  },

  async uninstall(ctx) {
    const done: string[] = [];
    if (ctx.useClaudeCli && (await commandExists("claude"))) {
      const r = await run("claude", ["mcp", "remove", SERVER_NAME, "--scope", "user"]).catch(() => undefined);
      if (r?.code === 0) done.push("removed mcp server via claude mcp remove");
    } else {
      const m = await unmergeMcp(ctx, join(ctx.home, ".claude.json"));
      if (m) done.push(m);
    }
    const h = await unmergeClaudeHook(ctx);
    if (h) done.push(h);
    const skillDir = join(ctx.home, ".claude", "skills", SERVER_NAME);
    if (existsSync(skillDir)) {
      await removeIfExists(skillDir);
      done.push(`removed ${skillDir}`);
    }
    return done;
  },
};

export const cursor: AgentInfo = {
  id: "cursor",
  label: "Cursor (IDE and cursor-agent CLI)",
  files: (home) => [
    join(home, ".cursor", "mcp.json") + " (mcpServers)",
    join(home, ".cursor", "hooks.json") + " (beforeShellExecution guard hook)",
    join(home, ".cursor", "skills", SERVER_NAME, "SKILL.md"),
  ],
  detect: async (home) => existsSync(join(home, ".cursor")) || (await commandExists("cursor")) || (await commandExists("cursor-agent")),

  async install(ctx) {
    return [
      await mergeMcp(ctx, join(ctx.home, ".cursor", "mcp.json"), { command: ctx.server.command, args: ctx.server.args }),
      await mergeCursorHook(ctx),
      await installSkill(ctx, join(ctx.home, ".cursor", "skills", SERVER_NAME)),
    ];
  },

  async uninstall(ctx) {
    const done: string[] = [];
    const m = await unmergeMcp(ctx, join(ctx.home, ".cursor", "mcp.json"));
    if (m) done.push(m);
    const h = await unmergeCursorHook(ctx);
    if (h) done.push(h);
    const skillDir = join(ctx.home, ".cursor", "skills", SERVER_NAME);
    if (existsSync(skillDir)) {
      await removeIfExists(skillDir);
      done.push(`removed ${skillDir}`);
    }
    return done;
  },
};

export const AGENTS: AgentInfo[] = [claude, cursor];
