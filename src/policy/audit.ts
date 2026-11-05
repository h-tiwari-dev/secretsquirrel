import { appendFile, mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

const PATH = process.env.AGENT_VAULT_AUDIT ?? join(homedir(), ".config", "agent-vault", "audit.log");

export type AuditEvent =
  | { event: "run"; names: string[]; status: string }
  | { event: "store"; name: string; status: string }
  | { event: "update"; name: string; status: string }
  | { event: "rollback"; name: string; status: string };

/** Names and outcomes only. Values and commands never go in the log. */
export async function audit(e: AuditEvent): Promise<void> {
  try {
    await mkdir(dirname(PATH), { recursive: true });
    await appendFile(PATH, JSON.stringify({ t: new Date().toISOString(), ...e }) + "\n", { mode: 0o600 });
  } catch {
    /* auditing must never break the flow */
  }
}
