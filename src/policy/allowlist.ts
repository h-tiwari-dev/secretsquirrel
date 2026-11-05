/**
 * Per-secret program allowlist. Two users:
 *  - config `allow` (hard policy): { "GITHUB_TOKEN": ["gh","git"], "AWS_*": ["aws"] }
 *  - grants (what the human clicked "Always allow" for): { "GITHUB_TOKEN": ["gh"] }
 *
 * This is a text check, not a sandbox. It refuses constructs that hide or redirect execution, but an allowed program
 * can still run code through its own config; the human's approval remains the real control.
 */
export type AllowRules = Record<string, string[]>;

/** Plumbing that may surround an allowed program. None of these can execute programs or write files. */
export const HELPERS = new Set(["printf", "echo", "true", "false", "test", "[", "cd", "jq", "grep", "head", "tail", "wc", "sort", "uniq"]);
/** Helpers that may take a restricted secret as an argument, but only when piped straight into an allowed program. */
const FEEDERS = new Set(["printf", "echo"]);
const TRUSTED_DIRS = ["/usr/bin/", "/bin/", "/usr/local/bin/", "/opt/homebrew/bin/"];
/** Expansions that run programs. Checked with single-quoted text removed (nothing expands inside single quotes). */
const SUBST = /\$\(|`|<\(|>\(|\$\{?IFS\b/;
/** Constructs that make the executable impossible to determine. Checked with all quoted text blanked. */
const OPAQUE = /\beval\b|\bsource\b|(?:^|[\s;&|(])\.\s+\S|\b(?:ba|z|da|k)?sh\s+-\w*c\b|\bexec\b|\bxargs\b|\bcommand\b|\bbuiltin\b|\benv\b|\bnohup\b|\btime\b|\bsudo\b|[(){}]/;
/** Assignments that change how an allowed program resolves or runs other programs. */
const DANGEROUS_ASSIGN = /^(?:PATH|IFS|SHELL|ENV|BASH_ENV|GIT_[A-Z_]*|GH_[A-Z_]*|LD_[A-Z_]*|DYLD_[A-Z_]*|NODE_OPTIONS|PYTHON[A-Z_]*|npm_config_[A-Za-z_]*)=/i;

/** The one git credential-helper form the skill recommends: `-c credential.helper='!f(){ echo k=v; echo password=$NAME; }; f'` */
const CRED_HELPER = /-c\s+credential\.helper='!f\(\)\{(?:\s*echo\s+[A-Za-z_]+=(?:[^;'`$()\\]|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)*;)+\s*\};\s*f'/g;

const toRe = (pat: string) => new RegExp(`^${pat.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`);

export function allowedFor(name: string, rules: AllowRules | undefined): string[] | undefined {
  if (!rules) return undefined;
  const hit = Object.entries(rules).filter(([pat]) => toRe(pat).test(name));
  return hit.length ? hit.flatMap(([, v]) => v) : undefined;
}

/**
 * Quote-aware view of a command. `plain` drops single-quoted text (no expansion happens inside it).
 * `blank` also blanks double-quoted text, except `$NAME` references, so operators inside strings never split or confuse parsing.
 * Returns undefined for an unterminated quote.
 */
export function scanQuotes(cmd: string): { plain: string; blank: string } | undefined {
  let plain = "";
  let blank = "";
  let mode: "none" | "single" | "double" = "none";
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (mode === "single") {
      if (c === "'") { mode = "none"; plain += "'"; blank += "'"; }
      continue;
    }
    if (mode === "double") {
      if (c === "\\" && i + 1 < cmd.length) { plain += c + cmd[i + 1]; blank += "xx"; i++; continue; }
      if (c === '"') { mode = "none"; plain += c; blank += c; continue; }
      plain += c;
      if (c === "$") {
        const m = /^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/.exec(cmd.slice(i));
        if (m) { blank += "$" + m[1]; i += m[0].length - 1; plain += m[0].slice(1); continue; }
      }
      blank += "x";
      continue;
    }
    if (c === "\\" && i + 1 < cmd.length) { plain += c + cmd[i + 1]; blank += c + cmd[i + 1]; i++; continue; }
    if (c === "'") { mode = "single"; plain += "'"; blank += "'"; continue; }
    if (c === '"') { mode = "double"; plain += c; blank += c; continue; }
    plain += c; blank += c;
  }
  return mode === "none" ? { plain, blank } : undefined;
}

interface Seg { words: string[]; sep: string; text: string }

function segments(blank: string): Seg[] {
  const parts = blank.split(/(\n|;|&&|\|\||\||&)/);
  const out: Seg[] = [];
  for (let i = 0; i < parts.length; i += 2) {
    const text = parts[i].trim();
    if (text) out.push({ words: text.split(/\s+/), text, sep: parts[i + 1] ?? "" });
  }
  return out;
}

/** Index of the first word that is not a leading VAR=value assignment. */
const execIndex = (words: string[]) => words.findIndex((w) => !/^[A-Za-z_][A-Za-z0-9_]*=/.test(w));
const baseName = (w: string) => w.replace(/^.*\//, "");

/** Executable names in each pipeline segment (basename only). Quoted program names are not understood and yield "". */
export function executables(command: string): string[] {
  const q = scanQuotes(command);
  if (!q) return [];
  return segments(q.blank).flatMap((s) => {
    const i = execIndex(s.words);
    if (i < 0) return [];
    const w = s.words[i];
    return [/["'\\]/.test(w) ? "" : baseName(w)];
  });
}

/** Returns a human-readable refusal, or undefined when the command satisfies every rule that applies to `names`. */
export function checkAllowlist(command: string, names: string[], rules: AllowRules | undefined): string | undefined {
  const applicable = names.map((n) => [n, allowedFor(n, rules)] as const).filter((x): x is [string, string[]] => x[1] !== undefined);
  if (!applicable.length) return undefined;
  const plainMsg = "Write one plain command.";

  // Remove the single recommended git credential helper, then inspect what is left.
  const q = scanQuotes(command.replace(CRED_HELPER, " "));
  if (!q) return `This secret is restricted to specific programs, and this command has an unbalanced quote. ${plainMsg}`;
  // Harmless redirections only; anything else could write the secret to a file.
  const blank = q.blank.replace(/\d*>&\d+/g, " ").replace(/&?>\s*\/dev\/null/g, " ").replace(/\d*>\s*\/dev\/null/g, " ");
  if (/[<>]/.test(blank)) return `This secret is restricted to specific programs, and redirections (other than to /dev/null or 2>&1) are not allowed with it. ${plainMsg}`;
  if (SUBST.test(q.plain) || OPAQUE.test(blank)) {
    return `This secret is restricted to specific programs, and this command uses constructs (substitution, functions, braces, eval, sh -c, xargs, env, command, source, $IFS) that hide which program runs. ${plainMsg}`;
  }

  const segs = segments(blank);
  for (const [name, allowed] of applicable) {
    const ok = new Set([...allowed, ...HELPERS]);
    const ref = new RegExp(`\\$\\{?${name}\\b`);
    let ran = false;
    for (let i = 0; i < segs.length; i++) {
      const s = segs[i];
      const x = execIndex(s.words);
      if (s.words.slice(0, x < 0 ? s.words.length : x).some((w) => DANGEROUS_ASSIGN.test(w))) {
        return `Assignments like PATH=, IFS=, GIT_*, GH_* before a command are not allowed with ${name}. ${plainMsg}`;
      }
      if (x < 0) continue;
      const word = s.words[x];
      if (/["'\\]/.test(word)) return `Quoted or escaped program names are not allowed with ${name}. ${plainMsg}`;
      if (word.includes("/") && !TRUSTED_DIRS.some((d) => word.startsWith(d))) {
        return `${name} may only be used with programs found on the normal PATH (${allowed.join(", ") || "none granted"}); "${word}" is a path. Do not run local executables with it.`;
      }
      const exe = baseName(word);
      if (!ok.has(exe)) return `${name} may only be used with: ${allowed.join(", ") || "(nothing granted yet)"}. This command runs: ${exe}.`;
      if (allowed.includes(exe)) {
        ran = true;
        const args = s.words.slice(x + 1);
        if (exe === "git" && args.some((a) => /^-c$|^--config-env|^--exec-path|^-C$|^--git-dir|^--work-tree/.test(a) || /^-c./.test(a))) {
          return `git -c, --exec-path and similar options can run arbitrary programs, so they are not allowed with ${name}.`;
        }
        if (exe === "gh" && args.some((a) => /^(?:alias|extension|ext)$/.test(a) || /^--hostname/.test(a) || /^-h$/.test(a))) {
          return `gh alias/extension and --hostname can run other programs or send ${name} to another host, so they are not allowed.`;
        }
      } else if (ref.test(s.text)) {
        // A helper that mentions the secret: only printf/echo feeding straight into an allowed program is tolerated.
        const next = segs[i + 1];
        const nx = next ? execIndex(next.words) : -1;
        const nextExe = nx >= 0 ? baseName(next.words[nx]) : "";
        if (!(FEEDERS.has(exe) && s.sep === "|" && allowed.includes(nextExe))) {
          return `${name} may only be passed to ${allowed.join(", ") || "granted programs"}. "${exe}" is not one of them; do not process or print the secret.`;
        }
      }
    }
    if (!ran) return `${name} may only be used with: ${allowed.join(", ") || "(nothing granted yet)"}, and this command runs none of them.`;
  }
  return undefined;
}

/** Non-helper programs a plain command runs, or undefined if the command is not simple enough to grant by program name. */
export function grantablePrograms(command: string, names: string[]): string[] | undefined {
  const exes = [...new Set(executables(command).filter((e) => e && !HELPERS.has(e)))];
  if (!exes.length) return undefined;
  const rules = Object.fromEntries(names.map((n) => [n, exes]));
  return checkAllowlist(command, names, rules) === undefined ? exes : undefined;
}
