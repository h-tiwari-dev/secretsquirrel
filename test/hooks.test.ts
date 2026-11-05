import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { evaluateCommand } from "../src/hooks/core.js";

const denied = (c: string) => evaluateCommand(c).deny;

describe("guard: blocks secret exposure", () => {
  it.each([
    'security find-generic-password -s agent-vault -a GITHUB_TOKEN -w',
    'security find-internet-password -s github.com -w',
    'security dump-keychain -d',
    'op read op://Private/GitHub/password',
    'op item get GitHub --fields password --reveal',
    'op run --env-file=.env -- env',
    'bw get password github',
    'bw list items --search github',
    'bws secret list',
    'pass show agent-vault/GITHUB_TOKEN',
    'gopass show -o agent-vault/X',
    'X=$(security find-generic-password -a Y -w); curl -H "Authorization: $X" api',
    'cd /tmp && bw get item abc',
    'echo $GITHUB_TOKEN',
    'echo "token=${AWS_SECRET_ACCESS_KEY}"',
    'printf "%s" "$DB_PASSWORD"',
    'printenv',
    'env',
    'env | sort',
    'export -p',
    'printenv GITHUB_TOKEN',
    'ls; env',
    '/usr/bin/security find-generic-password -s agent-vault -w',
    '"/usr/bin/security" find-generic-password -a X -w',
    '/opt/homebrew/bin/op read op://a/b/c',
    'ps eww',
    'ps -E',
    'ps auxeww',
    'cat /proc/1234/environ',
    'lsof -p 4321',
    'launchctl getenv GITHUB_TOKEN',
    "echo 'find-generic-password -s agent-vault -a X -w' | security -i",
    'security find-generic-"password" -a X -w',
    'osascript -e \'tell application "System Events" to click button "Allow"\'',
    'osascript -e \'tell app "System Events" to keystroke "x"\'',
    'cliclick c:100,200',
  ])("denies: %s", (c) => expect(denied(c)).toBe(true));
});

describe("guard: leaves ordinary work alone", () => {
  it.each([
    'git commit -m "fix env handling and token refresh"',
    'env FOO=1 npm test',
    'env -i PATH=/bin ls',
    'echo hello world',
    'echo "$HOME"',
    'printenv HOME',
    'grep -rn TOKEN src/',
    'cat package.json',
    'npm run security-audit',
    'curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user',
    'gh auth status',
    'aws s3 ls',
    'pass-through --flag',
    'operator read file',
    'ls ~/.password-store',
    'set -e && npm ci',
    'docker run --env-file .env app',
    'ps aux',
    'ps -ef',
    'lsof -i :3000',
    'ls /opt/passage/show',
    'cd ~/notes && ls',
    "osascript -e 'display notification \"build done\"'",
    'security -h',
  ])("allows: %s", (c) => expect(denied(c)).toBe(false));

  it("always points to the agent-vault tools in the reason", () => {
    expect(evaluateCommand("printenv").reason).toMatch(/run_with_secrets/);
  });
});

describe("hook process: protocol and fail-closed behaviour", () => {
  const cli = join(process.cwd(), "dist", "cli.js");
  const run = (kind: string, stdin: string) => spawnSync(process.execPath, [cli, "hook", kind], { input: stdin, encoding: "utf8" });

  it("claude: deny JSON for a bad command, silence for a good one, silence for non-Bash tools", () => {
    const bad = run("claude", JSON.stringify({ tool_name: "Bash", tool_input: { command: "printenv" } }));
    expect(bad.status).toBe(0);
    const j = JSON.parse(bad.stdout);
    expect(j.hookSpecificOutput).toMatchObject({ hookEventName: "PreToolUse", permissionDecision: "deny" });
    expect(run("claude", JSON.stringify({ tool_name: "Bash", tool_input: { command: "ls" } })).stdout).toBe("");
    expect(run("claude", JSON.stringify({ tool_name: "Read", tool_input: { file_path: "/x" } })).stdout).toBe("");
  });

  it("cursor: permission deny/allow", () => {
    expect(JSON.parse(run("cursor", JSON.stringify({ command: "bw get password x" })).stdout).permission).toBe("deny");
    expect(JSON.parse(run("cursor", JSON.stringify({ command: "ls" })).stdout).permission).toBe("allow");
  });

  it("fails closed (exit 2) on garbage input", () => {
    for (const kind of ["claude", "cursor"]) {
      const r = run(kind, "not json {{{");
      expect(r.status).toBe(2);
      expect(r.stderr).toMatch(/failed closed/);
    }
  });
});
