import { evaluateCommand } from "./core.js";

const shq = (v: string) => `'${v.replace(/'/g, `'\\''`)}'`;

/** Real dependencies for the injection planner, loaded lazily so the plain guard path stays tiny. */
async function realDeps(): Promise<import("./inject.js").Deps> {
  const [{ readNames, writeNames, loadGrants, addGrants }, { loadConfig }, { OsascriptPrompter }, { defaultBackend }] = await Promise.all([
    import("../policy/state.js"),
    import("../policy/config.js"),
    import("../prompt/osascript.js"),
    import("../backends/index.js"),
  ]);
  let backend: Awaited<ReturnType<typeof defaultBackend>> | undefined;
  const be = async () => (backend ??= await defaultBackend());
  const prompter = new OsascriptPrompter();
  return {
    knownNames: async () => {
      const cached = await readNames();
      if (cached) return cached;
      const names = (await (await be()).list()).filter((n) => !n.endsWith("__PREV"));
      await writeNames(names); // first run: remember, so later hooks do not wait on the password manager
      return names;
    },
    allow: async () => (await loadConfig()).allow,
    grants: loadGrants,
    addGrants,
    prompter: () => prompter,
    storeLabel: async () => (await be()).label,
    wrap: (names, command) =>
      `${shq(process.execPath)} ${shq(process.argv[1])} exec --names ${names.join(",")} --cmd-b64 ${Buffer.from(command, "utf8").toString("base64")}`,
  };
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Claude Code PreToolUse (Bash) and Cursor beforeShellExecution.
 * Fails CLOSED: any parse problem or crash blocks (exit 2), so a broken hook never silently disables the guard.
 */
export async function runHook(kind: "claude" | "cursor", deps?: import("./inject.js").Deps): Promise<void> {
  try {
    const input = JSON.parse(await readStdin()) as Record<string, any>;
    const command: string | undefined =
      kind === "claude" ? (input.tool_name === "Bash" ? input.tool_input?.command : undefined) : (input.command ?? input.tool_input?.command);

    if (command === undefined) {
      if (kind === "cursor") process.stdout.write(JSON.stringify({ permission: "allow" }));
      return; // not a shell command: no opinion
    }
    const v = evaluateCommand(command);
    if (kind === "claude") {
      if (v.deny) {
        process.stdout.write(
          JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: v.reason } }),
        );
        return;
      }
      // Secrets: rewrite the command so the values are injected into that one process. The agent only wrote env var names.
      const { planInjection } = await import("./inject.js");
      const plan = await planInjection(command, deps ?? (await realDeps()));
      if (plan.kind === "deny") {
        process.stdout.write(
          JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: plan.reason } }),
        );
      } else if (plan.kind === "rewrite") {
        process.stdout.write(
          JSON.stringify({
            hookSpecificOutput: {
              hookEventName: "PreToolUse",
              permissionDecision: "allow",
              permissionDecisionReason: `agent-vault injects ${plan.names.join(", ")} into this command; the agent never sees the values.`,
              updatedInput: { ...input.tool_input, command: plan.command },
            },
          }),
        );
      }
      return; // no output = normal permission flow continues
    }
    process.stdout.write(
      JSON.stringify(v.deny ? { permission: "deny", user_message: "agent-vault blocked a command that would expose a secret.", agent_message: v.reason } : { permission: "allow" }),
    );
  } catch (e) {
    process.stderr.write(`agent-vault hook failed closed: ${(e as Error).message}\n`);
    process.exit(2);
  }
}
