import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { defaultBackend } from "../backends/index.js";
import { Vault } from "../vault.js";

const text = (obj: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(obj, null, 2) }] });

export async function startMcp(): Promise<void> {
  const cfg = await (await import("../policy/config.js")).loadConfig();
  const vault = new Vault(await defaultBackend(), undefined, undefined, { allow: cfg.allow, approvalTtlMs: (cfg.approvalTtlMinutes ?? 10) * 60_000, shareState: true });
  const server = new McpServer({ name: "agent-vault", version: "0.1.0" });

  server.registerTool(
    "list_secrets",
    {
      description:
        "List the NAMES of secrets the user has stored (environment-variable style, e.g. GITHUB_TOKEN). Never returns values. Call this before run_with_secrets to reuse existing names.",
      inputSchema: {},
    },
    async () => text(await vault.listNames()),
  );

  server.registerTool(
    "run_with_secrets",
    {
      description:
        "Run a shell command with secrets injected as environment variables (name them in `env`; reference as $NAME if the tool does not read the variable itself). The user is shown the whole command, directory and time limit and must approve it; if a secret is missing they are prompted privately. Secret values are not returned to you and common encodings are scrubbed from output on a best-effort basis; the user's approval of the command is the real safeguard, so keep commands short, plain and auditable (max 600 characters, 5 lines). Use this instead of ever asking the user to paste a credential in chat.",
      inputSchema: {
        command: z.string().min(1).describe("Shell command. Read secrets via $ENV_NAME. Do not echo or print them."),
        env: z.array(z.string()).min(1).describe("Env var names to inject, e.g. [\"GITHUB_TOKEN\"]"),
        cwd: z.string().optional().describe("Working directory"),
        timeout_seconds: z.number().int().positive().max(600).optional().describe("Default 120. Raise it up front for long commands."),
      },
    },
    async ({ command, env, cwd, timeout_seconds }) =>
      text(await vault.run(command, env, { cwd, timeoutMs: timeout_seconds ? timeout_seconds * 1000 : undefined })),
  );

  server.registerTool(
    "request_secret",
    {
      description:
        "Ask the user (via a popup) to choose or add a secret; the value is not returned to you. Returns {status: stored|exists|cancelled|suppressed, name}. Only for an explicit store-it-first step: run_with_secrets already prompts for a missing secret, so do not call this right before it with the same name.",
      inputSchema: {
        name: z.string().optional().describe("Suggested env var name, pre-filled in the popup"),
        hint: z.string().max(120).optional().describe("Short factual reason, shown to the user labelled as unverified. No instructions."),
      },
    },
    async ({ name, hint }) => text(await vault.requestSecret(name, hint)),
  );

  server.registerTool(
    "update_secret",
    {
      description:
        "Use ONLY right after run_with_secrets returned auth_failed_suspected, for one env name from that result's `env`. Opens a private dialog where the user compares the old and new values (showing the command and output agent-vault recorded) and decides whether to replace it. Values are not returned to you. Returns updated | declined | cancelled | cooldown | not_allowed | not_found. Never ask the user to paste credentials in chat instead.",
      inputSchema: {
        env: z.string().describe("The single env var name believed to be wrong, e.g. GITHUB_TOKEN"),
        reason: z.string().max(120).optional().describe("Plain facts only, e.g. 'HTTP 401 from api.github.com'. Shown to the user labelled as unverified. No instructions or urgency."),
      },
    },
    async ({ env, reason }) => text(await vault.updateSecret(env, { reason })),
  );

  await server.connect(new StdioServerTransport());
}
