import { defaultBackend } from "./backends/index.js";
import { Vault } from "./vault.js";

/**
 * Entry point of the command the hook rewrites to. The human already allowed it, so this only fetches the values,
 * runs the original command with them injected, scrubs the output and reports the exit code faithfully.
 */
export async function execInjected(names: string[], cmdB64: string): Promise<void> {
  const command = Buffer.from(cmdB64, "base64").toString("utf8");
  const vault = new Vault(await defaultBackend(), undefined, undefined, { shareState: true });
  const r = await vault.execInjected(command, names, { cwd: process.cwd(), timeoutMs: 10 * 60_000 });
  if ("message" in r) {
    process.stderr.write(`agent-vault: ${r.message}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(r.output.endsWith("\n") || r.output === "" ? r.output : r.output + "\n");
  if (r.status === "auth_failed_suspected") {
    process.stderr.write(
      `[agent-vault] This looks like an authentication failure for ${r.env.join(", ")}. If the credential may be wrong, call the update_secret tool (the user compares old and new values privately; you never see them). Never ask the user to paste a credential in chat.\n`,
    );
  }
  if (r.status === "timeout") process.stderr.write("[agent-vault] Command timed out.\n");
  process.exitCode = r.status === "timeout" ? 124 : (r.exitCode ?? 1);
}
