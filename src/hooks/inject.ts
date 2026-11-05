import { checkAllowlist, grantablePrograms, scanQuotes, type AllowRules } from "../policy/allowlist.js";
import type { Prompter } from "../prompt/osascript.js";

/** `NAME=@vault cmd` declares that cmd needs NAME from the vault (for tools that read the variable themselves, such as gh or aws). */
const DECLARE = /(^|[\s;&|(])([A-Za-z_][A-Za-z0-9_]{0,127})=@vault(?=$|[\s;&|)])/g;

export interface Deps {
  knownNames(): Promise<string[]>;
  allow(): Promise<AllowRules | undefined>;
  grants(): Promise<Record<string, string[]>>;
  addGrants(names: string[], programs: string[]): Promise<void>;
  prompter(): Prompter;
  storeLabel(): Promise<string>;
  wrap(names: string[], command: string): string;
}

export type Injection =
  | { kind: "none" }
  | { kind: "deny"; reason: string }
  | { kind: "rewrite"; command: string; names: string[] };

/** Which stored secrets does this command use? Explicit `NAME=@vault`, or `$NAME` / `${NAME}` of a stored name. */
export function findNames(command: string, known: string[]): { names: string[]; declared: string[]; command: string } {
  const declared: string[] = [];
  const clean = command.replace(DECLARE, (_m, pre: string, name: string) => {
    declared.push(name);
    return pre;
  });
  const text = scanQuotes(clean)?.plain ?? clean; // nothing expands inside single quotes
  const implicit = known.filter((n) => new RegExp(`\\$\\{?${n}\\b`).test(text));
  return { names: [...new Set([...declared, ...implicit])], declared, command: clean.replace(/^\s+/, "") };
}

/**
 * Decide what the hook does with a Bash command. Silent when every program in the command already has a grant for
 * every secret it uses; otherwise ask the human once (and remember "always" per secret + program).
 */
export async function planInjection(command: string, d: Deps): Promise<Injection> {
  const known = await d.knownNames();
  const found = findNames(command, known);
  if (!found.names.length) return { kind: "none" };
  const { names } = found;
  const clean = found.command;
  const missing = names.filter((n) => !known.includes(n));

  const hard = checkAllowlist(clean, names, await d.allow());
  if (hard) return { kind: "deny", reason: `Blocked by your agent-vault allowlist: ${hard}` };

  const grants = await d.grants();
  const rules = Object.fromEntries(names.map((n) => [n, grants[n] ?? []]));
  const silent = missing.length === 0 && checkAllowlist(clean, names, rules) === undefined;
  if (!silent) {
    const programs = grantablePrograms(clean, names);
    const choice = await d.prompter().approveUse({ names, missing, command: clean, storeLabel: await d.storeLabel(), programs });
    if (choice === "deny") {
      return { kind: "deny", reason: `The user declined to let this command use ${names.join(", ")}. Do not retry, reword or work around it; tell the user what is blocked and ask how to proceed.` };
    }
    if (choice === "always" && programs) await d.addGrants(names, programs);
  }
  return { kind: "rewrite", command: d.wrap(names, clean), names };
}
