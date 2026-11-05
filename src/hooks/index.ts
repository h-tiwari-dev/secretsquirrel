import { evaluateCommand } from "./core.js";

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Claude Code PreToolUse (Bash) and Cursor beforeShellExecution.
 * Fails CLOSED: any parse problem or crash blocks (exit 2), so a broken hook never silently disables the guard.
 */
export async function runHook(kind: "claude" | "cursor"): Promise<void> {
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
