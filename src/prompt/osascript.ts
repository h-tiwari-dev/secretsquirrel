import { spawn } from "node:child_process";
import { run } from "../backends/exec.js";
import { clip, codePoints, nonAscii, visible } from "../policy/sanitize.js";
import { startUpdateForm, type UpdateDecision, type UpdateRequest } from "./webform.js";

/** All dynamic text goes in as argv to `on run argv`, never interpolated into script source. */
async function osa(script: string, args: string[]): Promise<string | undefined> {
  const r = await run("osascript", ["-e", script, "--", ...args], { timeoutMs: 10 * 60_000 });
  if (r.code !== 0) return undefined; // user cancelled (-128) or error
  return r.stdout.replace(/\n$/, "");
}

const CHOOSE = `on run argv
  set theTitle to item 1 of argv
  set thePrompt to item 2 of argv
  set theDefault to item 3 of argv
  set theItems to {}
  repeat with i from 4 to count of argv
    set end of theItems to item i of argv
  end repeat
  set r to choose from list theItems with title theTitle with prompt thePrompt default items {theDefault}
  if r is false then error number -128
  return item 1 of r
end run`;

const HIDDEN = `on run argv
  set r to display dialog (item 2 of argv) with title (item 1 of argv) default answer "" with hidden answer buttons {"Cancel", "Save"} default button "Save" with icon caution
  return text returned of r
end run`;

const TEXT = `on run argv
  set r to display dialog (item 2 of argv) with title (item 1 of argv) default answer (item 3 of argv) buttons {"Cancel", "OK"} default button "OK"
  return text returned of r
end run`;

const CONFIRM = `on run argv
  set r to display dialog (item 2 of argv) with title (item 1 of argv) buttons {"Deny", "Allow"} default button "Deny" cancel button "Deny" with icon caution
  return button returned of r
end run`;

const USE = `on run argv
  set theButtons to {}
  repeat with i from 3 to count of argv
    set end of theButtons to item i of argv
  end repeat
  set r to display dialog (item 2 of argv) with title (item 1 of argv) buttons theButtons default button 1 cancel button 1 with icon caution giving up after 110
  if gave up of r then return "Deny"
  return button returned of r
end run`;

const PIN_DIALOG = `on run argv
  display dialog ("Code: " & item 1 of argv & return & return & "Type it into the agent-vault page in your browser to compare the old and new values for " & item 2 of argv & ". Do not share it with anyone.") with title "agent-vault: unlock" buttons {"OK"} default button "OK" giving up after 600
end run`;

export interface RunApproval {
  names: string[];
  command: string;
  cwd?: string;
  timeoutSec: number;
  /** Injected names the command text never references as $NAME / ${NAME}. */
  unreferenced: string[];
}

export interface UseApproval {
  names: string[];
  /** Names that are not stored yet: the user will be asked for the value right after. */
  missing: string[];
  command: string;
  storeLabel: string;
  /** Programs "Always allow" would grant. Undefined when the command is too complex to grant by program name. */
  programs?: string[];
}
export type UseChoice = "deny" | "once" | "always";

export const NEW_ENTRY = "＋ New secret…";

export interface Prompter {
  /** Pick or create an env var name. `suggested` is pre-selected / pre-filled. */
  pickKey(existing: string[], suggested?: string, hint?: string): Promise<string | undefined>;
  /** Ask for a secret value (masked). */
  askValue(name: string, backendLabel: string, context?: string): Promise<string | undefined>;
  /** Approve injecting secrets into a specific command. */
  approveRun(d: RunApproval): Promise<boolean>;
  /** Hook flow: one-time decision about a program using a secret. "always" remembers (name, program). */
  approveUse(d: UseApproval): Promise<UseChoice>;
  /** Side-by-side old/new review. Plaintext stays between this process and the human. */
  reviewUpdate(req: UpdateRequest): Promise<UpdateDecision>;
}

export class OsascriptPrompter implements Prompter {
  async pickKey(existing: string[], suggested?: string, hint?: string): Promise<string | undefined> {
    const items = [...existing];
    if (suggested && !items.includes(suggested)) items.unshift(suggested + "  (new)");
    items.push(NEW_ENTRY);
    const def = suggested ? (existing.includes(suggested) ? suggested : suggested + "  (new)") : items[0];
    const msg = `Select the secret an agent is asking for.${hint ? `\n\nUnverified text from the agent: ${hint}` : ""}`;
    const choice = await osa(CHOOSE, ["agent-vault", msg, def, ...items]);
    if (!choice) return undefined;
    if (choice === NEW_ENTRY) {
      return osa(TEXT, ["agent-vault: new secret", "Environment variable name (e.g. GITHUB_TOKEN):", suggested ?? ""]);
    }
    return choice.replace(/  \(new\)$/, "");
  }

  async askValue(name: string, backendLabel: string, context?: string): Promise<string | undefined> {
    const msg = `Enter the value for ${name}.\nIt is saved to ${backendLabel} and is not returned to the agent.${context ? `\n\n${context}` : ""}`;
    return osa(HIDDEN, ["agent-vault", msg]);
  }

  async approveRun(d: RunApproval): Promise<boolean> {
    // The command is shown whole (Vault rejects long commands instead of truncating) with hidden characters made visible.
    const lines = [
      "An agent wants to run this command with secrets injected:",
      "",
      visible(d.command),
      "",
      `Length: ${codePoints(d.command)} characters`,
      `Directory: ${d.cwd ? clip(visible(d.cwd), 200) : "(agent's current directory)"}`,
      `Time limit: ${d.timeoutSec}s`,
      `Secrets injected: ${d.names.join(", ")}`,
    ];
    const odd = nonAscii(d.command + (d.cwd ?? ""));
    if (odd.length) {
      lines.push("", `WARNING: contains non-ASCII characters (${odd.slice(0, 8).join(", ")}${odd.length > 8 ? ", …" : ""}). Look-alike letters can disguise a hostname or path.`);
    }
    if (d.unreferenced.length) {
      lines.push("", `WARNING: the command text never mentions ${d.unreferenced.join(", ")}. It may still read them from its environment, so check that it needs them.`);
    }
    lines.push("", "Allowing means this command may do anything with these secrets, including sending them over the network.");
    return (await osa(CONFIRM, ["agent-vault: approve", lines.join("\n")])) === "Allow";
  }

  async approveUse(d: UseApproval): Promise<UseChoice> {
    const lines = [
      `An agent's command wants to use ${d.names.join(", ")} (from ${d.storeLabel}):`,
      "",
      visible(d.command),
    ];
    if (d.missing.length) lines.push("", `${d.missing.join(", ")} is not stored yet. You will be asked for the value next.`);
    const odd = nonAscii(d.command);
    if (odd.length) lines.push("", `WARNING: contains non-ASCII characters (${odd.slice(0, 8).join(", ")}). Look-alike letters can disguise a hostname.`);
    lines.push("", "The agent never sees the value. The command may still send it anywhere, so only allow what you recognise.");
    if (d.programs) {
      lines.push("", `Always allow: ${d.programs.join(", ")} may use ${d.names.join(", ")} from now on without asking. Any other program asks again.`);
    } else {
      lines.push("", "This command is too complex to remember (substitutions, redirects or functions), so it can only be allowed once.");
    }
    const buttons = d.programs ? ["Deny", "Allow once", "Always allow"] : ["Deny", "Allow once"];
    const r = await osa(USE, ["agent-vault: secret use", lines.join("\n"), ...buttons]);
    return r === "Always allow" ? "always" : r === "Allow once" ? "once" : "deny";
  }

  async reviewUpdate(req: UpdateRequest): Promise<UpdateDecision> {
    const form = await startUpdateForm(req);
    // The code lives only in this native dialog and the page's check. The agent never receives it.
    const dlg = spawn("osascript", ["-e", PIN_DIALOG, "--", form.pin, req.name], { stdio: "ignore" });
    dlg.on("error", () => {});
    try {
      return await form.result;
    } finally {
      form.close();
      dlg.kill();
    }
  }
}
