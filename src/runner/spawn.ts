import { spawn } from "node:child_process";
import { StringDecoder } from "node:string_decoder";
import { leaksTransformed, redact } from "./redact.js";

const MAX_OUTPUT = 100_000;
const BASE_ENV_KEYS = ["PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL", "TERM", "TMPDIR", "SSH_AUTH_SOCK"];

export interface RunOutcome {
  exitCode: number | null;
  timedOut: boolean;
  output: string; // stdout+stderr interleaved, redacted, truncated
  authFailureSuspected: boolean;
  /** Output was dropped because the secret appeared in a form simple redaction cannot safely scrub. */
  withheld: boolean;
}

const AUTH_PATTERNS = [
  /\b401\b/, /\b403\b/, /unauthori[sz]ed/i, /authentication failed/i, /invalid (api )?(token|key|credentials?|password)/i,
  /bad credentials/i, /permission denied \(publickey/i, /access denied/i, /incorrect password/i,
  /not authenticated/i, /expired token/i, /invalid_grant/i, /could not authenticate/i,
];

export function looksLikeAuthFailure(exitCode: number | null, output: string): boolean {
  if (exitCode === 0) return false;
  return AUTH_PATTERNS.some((p) => p.test(output));
}

/** Kill the whole process group so backgrounded descendants (`cmd &`, nohup) cannot outlive the approved run holding the secret in their env. */
function killGroup(pid: number | undefined): void {
  if (pid === undefined) return;
  try {
    process.kill(-pid, "SIGKILL");
  } catch {
    /* already gone */
  }
}

export function runWithSecrets(
  command: string,
  secrets: Record<string, string>,
  opts: { cwd?: string; timeoutMs?: number; inheritEnv?: boolean } = {},
): Promise<RunOutcome> {
  const env: Record<string, string> = {};
  // inheritEnv: the hook-injected command should behave exactly as the agent's own shell would (its PATH, region, etc.).
  if (opts.inheritEnv) for (const [k, v] of Object.entries(process.env)) { if (v !== undefined) env[k] = v; }
  else for (const k of BASE_ENV_KEYS) if (process.env[k] !== undefined) env[k] = process.env[k]!;
  Object.assign(env, secrets);
  const values = Object.values(secrets);

  return new Promise((resolve) => {
    const child = spawn("/bin/sh", ["-c", command], { cwd: opts.cwd, env, stdio: ["ignore", "pipe", "pipe"], detached: true });
    // One decoder per stream: a multibyte character (or secret) split across chunks must not be mangled before redaction.
    const dec = { out: new StringDecoder("utf8"), err: new StringDecoder("utf8") };
    let buf = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      killGroup(child.pid);
    }, opts.timeoutMs ?? 120_000);
    const add = (d: StringDecoder, b: Buffer) => {
      if (buf.length < MAX_OUTPUT * 2) buf += d.write(b);
    };
    child.stdout.on("data", (b: Buffer) => add(dec.out, b));
    child.stderr.on("data", (b: Buffer) => add(dec.err, b));
    const finish = (code: number | null, extra = "") => {
      clearTimeout(timer);
      killGroup(child.pid); // sweep leftovers even on a clean exit
      buf += dec.out.end() + dec.err.end();
      // Redact the whole buffer at once so secrets split across chunks are still caught.
      let output = redact(buf + extra, values);
      let withheld = false;
      if (leaksTransformed(output, values)) {
        withheld = true;
        output = "[output withheld: it contained a secret in a transformed form (spaced, reversed or split) that cannot be safely redacted. Do not try to display secrets.]";
      } else if (output.length > MAX_OUTPUT) {
        output = output.slice(0, MAX_OUTPUT) + "\n[output truncated]";
      }
      resolve({ exitCode: code, timedOut, output, withheld, authFailureSuspected: !withheld && looksLikeAuthFailure(code, output) });
    };
    child.on("error", (e) => finish(127, `spawn error: ${e.message}`));
    child.on("exit", () => {
      // The shell is done. Kill leftovers now: a backgrounded grandchild holding our pipes open would otherwise
      // stall a successful command until the timeout and misreport it. Damn few legitimate commands need to outlive this.
      killGroup(child.pid);
      setTimeout(() => {
        child.stdout.destroy();
        child.stderr.destroy();
      }, 300).unref();
    });
    child.on("close", (code) => finish(code));
  });
}
