import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { install, uninstall } from "../src/install/index.js";

const SKILL = join(process.cwd(), "assets", "SKILL.md");
const server = { command: "/usr/bin/node", args: ["/opt/agent-vault/dist/cli.js", "mcp"] };
const cfg = { defaultBackend: "keychain" };

function fakeHome(seed: Record<string, unknown> = {}) {
  const home = mkdtempSync(join(tmpdir(), "av-home-"));
  for (const [rel, content] of Object.entries(seed)) {
    const p = join(home, rel);
    mkdirSync(join(p, ".."), { recursive: true });
    writeFileSync(p, typeof content === "string" ? content : JSON.stringify(content, null, 2) + "\n");
  }
  return home;
}
const J = (home: string, rel: string) => JSON.parse(readFileSync(join(home, rel), "utf8"));
const opts = (home: string, agents: ("claude" | "cursor")[] = ["claude", "cursor"]) => ({ home, agents, config: cfg, server, skillSource: SKILL, useClaudeCli: false });

describe("install into existing configs", () => {
  const claudeJson = { numStartups: 7, mcpServers: { other: { type: "stdio", command: "x", args: [] } } };
  const cursorMcp = { mcpServers: { figma: { url: "https://example.test/mcp" } } };
  const cursorHooks = { version: 1, hooks: { afterFileEdit: [{ command: "fmt.sh" }] } };
  const claudeSettings = { model: "opus", hooks: { SessionStart: [{ matcher: "*", hooks: [{ type: "command", command: "bash x.sh", timeout: 10 }] }] } };

  it("adds our server, keeps everything else, installs skills, writes config and backups", async () => {
    const home = fakeHome({ ".claude.json": claudeJson, ".cursor/mcp.json": cursorMcp, ".cursor/hooks.json": cursorHooks, ".claude/settings.json": claudeSettings });
    await install(opts(home));
    const c = J(home, ".claude.json");
    expect(c.numStartups).toBe(7);
    expect(c.mcpServers.other).toEqual(claudeJson.mcpServers.other);
    expect(c.mcpServers["agent-vault"]).toMatchObject({ command: server.command, args: server.args });
    const cu = J(home, ".cursor/mcp.json");
    expect(cu.mcpServers.figma).toEqual(cursorMcp.mcpServers.figma);
    expect(cu.mcpServers["agent-vault"].args).toEqual(server.args);
    expect(existsSync(join(home, ".claude/skills/agent-vault/SKILL.md"))).toBe(true);
    expect(existsSync(join(home, ".cursor/skills/agent-vault/SKILL.md"))).toBe(true);
    expect(J(home, ".config/agent-vault/config.json").defaultBackend).toBe("keychain");
    const backups = readdirSync(join(home, ".config/agent-vault/backups"));
    expect(backups.length).toBe(1);
    // Guard hooks merged next to the user's existing hooks.
    const ch = J(home, ".cursor/hooks.json");
    expect(ch.hooks.afterFileEdit).toEqual(cursorHooks.hooks.afterFileEdit);
    expect(ch.hooks.beforeShellExecution).toHaveLength(1);
    expect(ch.hooks.beforeShellExecution[0]).toMatchObject({ failClosed: true, timeout: 10 });
    expect(ch.hooks.beforeShellExecution[0].command).toMatch(/cli\.js' hook cursor \|\| exit 2$/);
    const st = J(home, ".claude/settings.json");
    expect(st.model).toBe("opus");
    expect(st.hooks.SessionStart).toEqual(claudeSettings.hooks.SessionStart);
    expect(st.hooks.PreToolUse).toHaveLength(1);
    expect(st.hooks.PreToolUse[0].matcher).toBe("Bash");
    expect(st.hooks.PreToolUse[0].hooks[0].command).toMatch(/cli\.js' hook claude \|\| exit 2$/);
    expect(st.hooks.PreToolUse[0].hooks[0].onFailure).toBeUndefined(); // only when the real claude version supports it
  });

  it("adds onFailure:block only when asked (Claude Code >= 2.1.295)", async () => {
    const home = fakeHome();
    await install({ ...opts(home, ["claude"]), claudeOnFailureBlock: true });
    expect(J(home, ".claude/settings.json").hooks.PreToolUse[0].hooks[0].onFailure).toBe("block");
  });

  it("keeps the user's own PreToolUse hooks and does not duplicate ours on re-install", async () => {
    const mine = { matcher: "Bash", hooks: [{ type: "command", command: "my-linter.sh" }] };
    const home = fakeHome({ ".claude/settings.json": { hooks: { PreToolUse: [mine] } } });
    await install(opts(home, ["claude"]));
    await install(opts(home, ["claude"]));
    const pre = J(home, ".claude/settings.json").hooks.PreToolUse;
    expect(pre).toHaveLength(2);
    expect(pre[0]).toEqual(mine);
    await uninstall({ home, useClaudeCli: false });
    expect(J(home, ".claude/settings.json")).toEqual({ hooks: { PreToolUse: [mine] } });
  });

  it("is idempotent", async () => {
    const home = fakeHome({ ".claude.json": claudeJson, ".cursor/mcp.json": cursorMcp });
    await install(opts(home));
    const once = [readFileSync(join(home, ".claude.json"), "utf8"), readFileSync(join(home, ".cursor/mcp.json"), "utf8")];
    await install(opts(home));
    expect([readFileSync(join(home, ".claude.json"), "utf8"), readFileSync(join(home, ".cursor/mcp.json"), "utf8")]).toEqual(once);
  });

  it("uninstall restores the original configs exactly and removes skills", async () => {
    const home = fakeHome({ ".claude.json": claudeJson, ".cursor/mcp.json": cursorMcp, ".cursor/hooks.json": cursorHooks, ".claude/settings.json": claudeSettings });
    await install(opts(home));
    await uninstall({ home, useClaudeCli: false });
    expect(J(home, ".cursor/hooks.json")).toEqual(cursorHooks);
    expect(J(home, ".claude/settings.json")).toEqual(claudeSettings);
    expect(J(home, ".claude.json")).toEqual(claudeJson);
    expect(J(home, ".cursor/mcp.json")).toEqual(cursorMcp);
    expect(existsSync(join(home, ".claude/skills/agent-vault"))).toBe(false);
    expect(existsSync(join(home, ".cursor/skills/agent-vault"))).toBe(false);
  });

  it("only touches the agents you picked", async () => {
    const home = fakeHome({ ".claude.json": claudeJson });
    await install(opts(home, ["claude"]));
    expect(existsSync(join(home, ".cursor"))).toBe(false);
  });
});

describe("fresh home and failure modes", () => {
  it("removes files it created when uninstalling", async () => {
    const home = fakeHome();
    await install(opts(home));
    expect(existsSync(join(home, ".cursor/mcp.json"))).toBe(true);
    await uninstall({ home, useClaudeCli: false });
    expect(existsSync(join(home, ".cursor/mcp.json"))).toBe(false);
    expect(existsSync(join(home, ".claude.json"))).toBe(false);
    expect(existsSync(join(home, ".cursor/hooks.json"))).toBe(false);
    expect(existsSync(join(home, ".claude/settings.json"))).toBe(false);
  });

  it("refuses to overwrite a config it cannot parse, and leaves it byte-identical", async () => {
    const broken = '{ "mcpServers": { oops ';
    const home = fakeHome({ ".cursor/mcp.json": broken });
    await expect(install(opts(home, ["cursor"]))).rejects.toThrow(/not valid JSON/);
    expect(readFileSync(join(home, ".cursor/mcp.json"), "utf8")).toBe(broken);
  });
});
