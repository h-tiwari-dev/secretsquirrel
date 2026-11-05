import { scanQuotes } from "../policy/allowlist.js";

export interface Verdict {
  deny: boolean;
  reason?: string;
}

const NUDGE = "Use the agent-vault MCP tools instead (list_secrets, then run_with_secrets with env var names). Never read or print secrets directly, and never ask the user to paste them.";

/** Env var names that look like credentials. */
const SECRETISH = "[A-Za-z0-9_]*(?:TOKEN|SECRET|PASSW(?:OR)?D|PASSWD|API_?KEY|PRIVATE_?KEY|CREDENTIAL|ACCESS_?KEY)[A-Za-z0-9_]*";
const SECRET_REF = new RegExp(`\\$\\{?(${SECRETISH})\\}?`, "i");
const SECRET_NAME = new RegExp(`^${SECRETISH}$`, "i");

/** Direct reads from password stores. These would hand the agent plaintext without the user's approval popup. */
// Match the tool name after start, whitespace, a shell separator, a path slash or a quote, so `/usr/bin/security` and `"op"` are caught too.
const START = "(?:^|[\\s;&|(`{/\"'])";
const tool = (name: string) => `${START}${name}["']?\\s+`;
const STORE_READS: { re: RegExp; what: string }[] = [
  { re: new RegExp(`${tool("security")}(?:-\\S+\\s+)*(?:find-(?:generic|internet)-password|dump-keychain|export)\\b`, "i"), what: "macOS Keychain" },
  // Stdin/indirect forms (`echo find-generic-password ... | security -i`, quote-split subcommands): block the telltale words anywhere.
  { re: /find-(?:generic|internet)-?["']*password|dump-?["']*keychain/i, what: "macOS Keychain" },
  { re: new RegExp(`${tool("security")}(?:-\\S+\\s+)*-i\\b`), what: "macOS Keychain (interactive mode)" },
  { re: new RegExp(`${tool("op")}(?:--?\\S+\\s+)*(?:read|inject|run|item\\s+get|document\\s+get)\\b`, "i"), what: "1Password" },
  { re: new RegExp(`${tool("bw")}(?:--?\\S+\\s+)*(?:get|list\\s+items|export|unlock)\\b`, "i"), what: "Bitwarden" },
  { re: new RegExp(`${tool("bws")}(?:--?\\S+\\s+)*(?:secret\\s+(?:get|list)|run)\\b`, "i"), what: "Bitwarden Secrets Manager" },
  { re: new RegExp(`${tool("(?:pass|gopass)")}(?:--?\\S+\\s+)*(?:show|otp|-c|cat)\\b`, "i"), what: "pass" },
  // Scripting the UI can click "Allow" on the approval dialog or fake one to phish the user.
  { re: new RegExp(`${tool("osascript")}[^\\n]*?(?:System Events|keystroke|key code|\\bclick\\b|display dialog|hidden answer)`, "i"), what: "UI scripting (it could approve or spoof agent-vault dialogs)" },
  { re: new RegExp(`${tool("cliclick")}`, "i"), what: "UI scripting (it could approve or spoof agent-vault dialogs)" },
  // Reading another process's environment would expose secrets injected into an approved command.
  { re: new RegExp(`${tool("ps")}-?[a-zA-Z]*e[a-zA-Z]*w`, "i"), what: "process environments (ps eww)" },
  { re: new RegExp(`${tool("ps")}(?:-\\S+\\s+)*-[a-zA-Z]*E`), what: "process environments (ps -E)" }, // case-sensitive: -e is harmless
  { re: /\/proc\/[^\s/]*\/environ/, what: "process environments (/proc/*/environ)" },
  { re: new RegExp(`${tool("lsof")}(?:-\\S+\\s+)*-p`, "i"), what: "process details (lsof -p)" },
  { re: new RegExp(`${tool("launchctl")}(?:getenv|export|print)\\b`, "i"), what: "launchd environment" },
];

const PRINTERS = new Set(["echo", "printf", "print"]);

/** Split on shell separators outside of quotes would be ideal; a plain split errs on the side of more segments, which is fine for deny rules. */
function segments(cmd: string): string[] {
  return cmd.split(/\n|;|&&|\|\||\|/).map((s) => s.trim()).filter(Boolean);
}

export function evaluateCommand(command: string): Verdict {
  if (typeof command !== "string" || command.length === 0) return { deny: false };

  for (const { re, what } of STORE_READS) {
    if (re.test(command)) {
      return { deny: true, reason: `Blocked: this touches ${what} directly, which could expose secrets or bypass the user's approval. ${NUDGE}` };
    }
  }

  // Single-quoted text is not run by this shell (a git credential helper's `echo password=$TOKEN` goes to git, not to the agent).
  for (const seg of segments(scanQuotes(command)?.plain ?? command)) {
    const words = seg.split(/\s+/);
    const head = words[0].replace(/^[("'`]+/, "");

    // echo / printf of a credential-looking variable.
    if (PRINTERS.has(head) && SECRET_REF.test(seg)) {
      return { deny: true, reason: `Blocked: printing a credential environment variable. ${NUDGE}` };
    }

    // Bare env dumps. `env FOO=1 cmd` and `env -i cmd` are fine; `env`, `env -0`, `printenv` alone are dumps.
    if (/^(?:env|printenv)(?:\s+-\S+)*$/.test(seg) || /^(?:export\s+-p|declare\s+-x|declare\s+-p|set)$/.test(seg)) {
      return { deny: true, reason: `Blocked: dumping the whole environment can expose secrets. Name the single non-secret variable you need. ${NUDGE}` };
    }
    // printenv SOME_TOKEN
    if (head === "printenv" && words.slice(1).some((w) => SECRET_NAME.test(w))) {
      return { deny: true, reason: `Blocked: printing a credential environment variable. ${NUDGE}` };
    }
  }
  return { deny: false };
}
