import { assertValidName, assertValidValue, type Backend } from "./backends/types.js";
import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { audit } from "./policy/audit.js";
import { checkAllowlist, type AllowRules } from "./policy/allowlist.js";
import { agentText, codePoints, visible, clip } from "./policy/sanitize.js";
import { OsascriptPrompter, type Prompter } from "./prompt/osascript.js";
import { runWithSecrets, type RunOutcome } from "./runner/spawn.js";

export type RunResult =
  | { status: "ok" | "failed" | "timeout"; exitCode: number | null; output: string }
  | { status: "auth_failed_suspected"; exitCode: number | null; output: string; env: string[]; hint: string }
  | { status: "denied" | "cancelled" | "rejected" | "suppressed"; message: string };

export type UpdateResult =
  | { status: "updated"; message: string }
  | { status: "declined" | "cancelled" | "not_found" | "cooldown" | "not_allowed"; message: string };

const PREV = "__PREV";
export const MAX_COMMAND_CHARS = 600;
export const MAX_COMMAND_LINES = 5;
const DEFAULT_TIMEOUT_S = 120;
const UPDATE_COOLDOWN_MS = 5 * 60_000;
const DENY_SUPPRESS_MS = 10 * 60_000;
const WINDOW_MS = 10 * 60_000;
const MAX_PROMPTS_PER_WINDOW = 8;
const SUSPECTED_TTL_MS = 2 * 60_000;

interface FailureRecord {
  at: number;
  command: string;
  exitCode: number | null;
  snippet: string;
}

/** Single entry point shared by the MCP server and CLI. Plaintext never leaves this module except into the child env or the human-facing popup. */
export class Vault {
  private lastUpdatePrompt = new Map<string, number>();
  /** Names from the most recent auth_failed_suspected run. update_secret is only allowed for these, once. */
  private suspected = new Map<string, FailureRecord>();
  private deniedUntil = new Map<string, number>();
  private promptTimes: number[] = [];

  constructor(
    private backend: Backend,
    private prompter: Prompter = new OsascriptPrompter(),
    private now: () => number = Date.now,
    private policy: { allow?: AllowRules; approvalTtlMs?: number } = {},
  ) {}

  /** Exact (names, cwd, command) approvals remembered briefly so a re-run after update_secret does not re-prompt. */
  private approved = new Map<string, { until: number; names: string[] }>();
  private approvalKey(names: string[], command: string, cwd: string | undefined, timeoutSec: number): string {
    let dir = cwd ?? process.cwd();
    try { dir = realpathSync(dir); } catch { /* keep the raw string */ }
    return createHash("sha256").update(JSON.stringify([[...names].sort(), dir, timeoutSec, command])).digest("hex");
  }
  private forget(names: string[]): void {
    for (const [k, v] of this.approved) if (v.names.some((n) => names.includes(n))) this.approved.delete(k);
  }

  async listNames(): Promise<{ backend: string; names: string[] }> {
    const names = (await this.backend.list()).filter((n) => !n.endsWith(PREV));
    return { backend: this.backend.label, names };
  }

  /** Global budget so a looping or injected agent cannot spam the human with prompts. */
  private budgetExceeded(): boolean {
    const t = this.now();
    this.promptTimes = this.promptTimes.filter((x) => t - x < WINDOW_MS);
    return this.promptTimes.length >= MAX_PROMPTS_PER_WINDOW;
  }
  private spend(): void {
    this.promptTimes.push(this.now());
  }

  /** Make sure `name` exists in the store, prompting the human if not. `context` must be text WE generated, never agent free text. */
  private async ensure(name: string, context?: string): Promise<boolean> {
    assertValidName(name);
    if ((await this.backend.get(name)) !== undefined) return true;
    const value = await this.prompter.askValue(name, this.backend.label, context);
    if (!value) return false;
    assertValidValue(value);
    await this.backend.set(name, value);
    await audit({ event: "store", name, status: "stored" });
    return true;
  }

  async requestSecret(name?: string, hint?: string): Promise<{ status: "stored" | "exists" | "cancelled" | "suppressed"; name?: string }> {
    if (this.budgetExceeded() || (this.deniedUntil.get("*request") ?? 0) > this.now()) return { status: "suppressed" };
    this.spend();
    const existing = (await this.listNames()).names;
    const chosen = await this.prompter.pickKey(existing, name, agentText(hint, 120));
    if (!chosen) {
      this.deniedUntil.set("*request", this.now() + DENY_SUPPRESS_MS);
      return { status: "cancelled" };
    }
    assertValidName(chosen);
    if (chosen.endsWith(PREV)) return { status: "cancelled" };
    if (existing.includes(chosen)) return { status: "exists", name: chosen };
    // The value dialog deliberately carries no agent-written text.
    return (await this.ensure(chosen)) ? { status: "stored", name: chosen } : { status: "cancelled" };
  }

  async run(command: string, env: string[], opts: { cwd?: string; timeoutMs?: number } = {}): Promise<RunResult> {
    for (const n of env) {
      assertValidName(n);
      if (n.endsWith(PREV)) throw new Error(`"${n}" is reserved.`);
    }
    const unique = [...new Set(env)];

    // The human must be able to audit the whole command at a glance. Refuse instead of truncating.
    if (codePoints(command) > MAX_COMMAND_CHARS || command.split(/\r\n|\n|\r/).length > MAX_COMMAND_LINES) {
      return {
        status: "rejected",
        message: `Command is too long to review safely (limit ${MAX_COMMAND_CHARS} characters and ${MAX_COMMAND_LINES} lines). Do not pad, split or obfuscate it to get around the limit; tell the user what you need to do and ask how to proceed.`,
      };
    }

    const refusal = checkAllowlist(command, unique, this.policy.allow);
    if (refusal) {
      await audit({ event: "run", names: unique, status: "rejected" });
      return { status: "rejected", message: refusal };
    }

    // Tracked per secret name, so adding a second name to a denied request does not buy a fresh prompt.
    const blocked = unique.some((n) => (this.deniedUntil.get(n) ?? 0) > this.now());
    if (blocked) {
      return { status: "suppressed", message: "The user recently denied a command using these secrets. Do not ask again; ask the user in chat what they want." };
    }
    const timeoutSec = opts.timeoutMs ? Math.round(opts.timeoutMs / 1000) : DEFAULT_TIMEOUT_S;
    const akey = this.approvalKey(unique, command, opts.cwd, timeoutSec);
    const cached = (this.approved.get(akey)?.until ?? 0) > this.now();
    if (!cached && this.budgetExceeded()) {
      return { status: "suppressed", message: "Too many prompts in a short time. Stop requesting secrets and ask the user in chat how to proceed." };
    }
    if (!cached) this.spend();

    const unreferenced = unique.filter((n) => !new RegExp(`\\$\\{?${n}\\b`).test(command));
    // Informed consent: the human sees the whole command, directory and limits, and which secrets go into it.
    if (!cached && !(await this.prompter.approveRun({ names: unique, command, cwd: opts.cwd, timeoutSec, unreferenced }))) {
      this.forget(unique);
      for (const n of unique) this.deniedUntil.set(n, this.now() + DENY_SUPPRESS_MS);
      await audit({ event: "run", names: unique, status: "denied" });
      return { status: "denied", message: "The user denied this command. Do not retry it, reword it, or approach it another way; ask the user what they want." };
    }
    const secrets: Record<string, string> = {};
    for (const n of unique) {
      if (!(await this.ensure(n, `Needed by the command you just approved: ${clip(visible(command), 160)}`))) {
        this.forget(unique);
        for (const m of unique) this.deniedUntil.set(m, this.now() + DENY_SUPPRESS_MS);
        await audit({ event: "run", names: unique, status: "cancelled" });
        return { status: "cancelled", message: `The user did not provide ${n}. Do not ask again; tell the user what is blocked.` };
      }
      secrets[n] = (await this.backend.get(n))!;
    }
    // Fixed expiry, set only by a fresh human approval, and only once every secret resolved.
    const ttl = this.policy.approvalTtlMs ?? 10 * 60_000;
    if (!cached && ttl > 0) this.approved.set(akey, { until: this.now() + ttl, names: unique });
    const r: RunOutcome = await runWithSecrets(command, secrets, opts);
    if (r.timedOut) {
      await audit({ event: "run", names: unique, status: "timeout" });
      return { status: "timeout", exitCode: r.exitCode, output: r.output };
    }
    if (r.authFailureSuspected) {
      // Remember what actually ran, so update_secret can show the human facts rather than agent claims.
      for (const n of unique) this.suspected.set(n, { at: this.now(), command: clip(visible(command), 300), exitCode: r.exitCode, snippet: clip(visible(r.output), 400) });
      await audit({ event: "run", names: unique, status: "auth_failed_suspected" });
      return {
        status: "auth_failed_suspected",
        exitCode: r.exitCode,
        output: r.output,
        env: unique,
        hint: "The command looks like it failed authentication, but this is a heuristic (a 403 can also mean missing permission). If one of these secrets is plausibly wrong, call update_secret with that single env name. Do not ask the user to paste a value in chat.",
      };
    }
    // A later run that is not an auth failure means the earlier suspicion is stale.
    for (const n of unique) this.suspected.delete(n);
    await audit({ event: "run", names: unique, status: r.withheld ? "withheld" : r.exitCode === 0 ? "ok" : "failed" });
    return { status: r.exitCode === 0 ? "ok" : "failed", exitCode: r.exitCode, output: r.output };
  }

  /**
   * User-confirmed replacement of a wrong secret. Only allowed right after a run flagged this secret as
   * auth_failed_suspected; the dialog shows the command and output WE recorded, not agent claims.
   * The human sees old and new side by side; the agent only learns the outcome.
   */
  async updateSecret(name: string, ctx: { reason?: string } = {}): Promise<UpdateResult> {
    assertValidName(name);
    if (name.endsWith(PREV)) throw new Error(`"${name}" is reserved.`);
    const failure = this.suspected.get(name);
    if (failure && this.now() - failure.at > SUSPECTED_TTL_MS) this.suspected.delete(name);
    if (!failure || this.now() - failure.at > SUSPECTED_TTL_MS) {
      return {
        status: "not_allowed",
        message: `update_secret only works right after run_with_secrets reports auth_failed_suspected for ${name}. Run the command first; do not ask the user to paste a value in chat.`,
      };
    }
    const old = await this.backend.get(name);
    if (old === undefined) {
      this.suspected.delete(name);
      return { status: "not_found", message: `${name} is not stored. Use request_secret to add it.` };
    }
    const last = this.lastUpdatePrompt.get(name);
    if (last !== undefined && this.now() - last < UPDATE_COOLDOWN_MS) {
      return {
        status: "cooldown",
        message: `The user was already asked about ${name} a moment ago. Do not ask again; tell the user the credential may be wrong and let them decide.`,
      };
    }
    if (this.budgetExceeded()) {
      return { status: "cooldown", message: "Too many prompts in a short time. Tell the user the credential may be wrong and let them decide." };
    }
    this.spend();
    this.lastUpdatePrompt.set(name, this.now());
    this.suspected.delete(name); // one prompt per failure

    const d = await this.prompter.reviewUpdate({
      name,
      storeLabel: this.backend.label,
      oldValue: old,
      command: failure.command,
      exitCode: failure.exitCode,
      snippet: failure.snippet,
      reason: agentText(ctx.reason, 120),
    });
    if (d.action === "cancel") {
      await audit({ event: "update", name, status: "cancelled" });
      return { status: "cancelled", message: "The user closed the update dialog. Nothing changed. Do not ask again." };
    }
    if (d.action === "keep") {
      await audit({ event: "update", name, status: "declined" });
      return { status: "declined", message: `The user chose to keep the current ${name}. The failure is likely not the credential; investigate other causes.` };
    }
    assertValidValue(d.newValue);
    // One-slot backup, backend-agnostic. Written first so a failed main write cannot lose the old value.
    await this.backend.set(name + PREV, old);
    await this.backend.set(name, d.newValue);
    await audit({ event: "update", name, status: "updated" });
    return { status: "updated", message: `${name} was updated by the user. You may re-run the failed command once with run_with_secrets.` };
  }

  /** Swap current and previous. Running it twice undoes itself. */
  async rollback(name: string): Promise<{ status: "rolled_back" | "no_backup" }> {
    assertValidName(name);
    const prev = await this.backend.get(name + PREV);
    const cur = await this.backend.get(name);
    if (prev === undefined) return { status: "no_backup" };
    await this.backend.set(name, prev);
    if (cur !== undefined) await this.backend.set(name + PREV, cur);
    await audit({ event: "rollback", name, status: "rolled_back" });
    return { status: "rolled_back" };
  }
}
