import { assertValidName, assertValidValue, type Backend } from "./types.js";
import { commandExists, run } from "./exec.js";

const TAG = "agent-vault";

/** 1Password via `op`. Item title == env var name, stored in one vault, tagged "agent-vault". */
export class OnePasswordBackend implements Backend {
  readonly id = "1password";
  readonly label: string;
  constructor(private vault: string = "Private") {
    this.label = `1Password (${vault})`;
  }

  async available(): Promise<boolean> {
    if (!(await commandExists("op"))) return false;
    const r = await run("op", ["whoami"], { timeoutMs: 15_000 }).catch(() => undefined);
    return r?.code === 0;
  }

  async vaults(): Promise<string[]> {
    const r = await run("op", ["vault", "list", "--format", "json"]);
    if (r.code !== 0) return [];
    return (JSON.parse(r.stdout) as { name: string }[]).map((v) => v.name);
  }

  private async items(): Promise<{ id: string; title: string }[]> {
    const r = await run("op", ["item", "list", "--vault", this.vault, "--tags", TAG, "--format", "json"]);
    if (r.code !== 0) throw new Error("1Password: could not list items (is the CLI signed in?)");
    return JSON.parse(r.stdout || "[]") as { id: string; title: string }[];
  }

  async list(): Promise<string[]> {
    return (await this.items()).map((i) => i.title).sort();
  }

  async get(name: string): Promise<string | undefined> {
    assertValidName(name);
    const r = await run("op", ["read", `op://${this.vault}/${name}/password`]);
    return r.code === 0 ? r.stdout.replace(/\n$/, "") : undefined;
  }

  async set(name: string, value: string): Promise<void> {
    assertValidName(name);
    assertValidValue(value);
    const existing = (await this.items()).find((i) => i.title === name);
    // Archive (not delete) the old item: that is our versioned backup, restorable from 1Password's Archive.
    if (existing) {
      const d = await run("op", ["item", "delete", existing.id, "--vault", this.vault, "--archive"]);
      if (d.code !== 0) throw new Error(`1Password: could not archive old ${name}`);
    }
    const template = {
      title: name,
      category: "PASSWORD",
      tags: [TAG],
      fields: [{ id: "password", type: "CONCEALED", purpose: "PASSWORD", label: "password", value }],
    };
    // Template over stdin: the value never appears in argv.
    const r = await run("op", ["item", "create", "--vault", this.vault, "--format", "json", "-"], { input: JSON.stringify(template) });
    if (r.code !== 0) throw new Error(`1Password: write failed for ${name}`);
  }
}
