import { assertValidName, assertValidValue, type Backend } from "./types.js";
import { commandExists, run } from "./exec.js";

const FOLDER = "agent-vault";

interface BwItem {
  id: string;
  name: string;
  folderId?: string | null;
  login?: { password?: string | null; username?: string | null };
  [k: string]: unknown;
}

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64");

/** Bitwarden vault via `bw`. Requires an unlocked session (BW_SESSION). Items live in folder "agent-vault". */
export class BitwardenBackend implements Backend {
  readonly id = "bitwarden";
  readonly label = "Bitwarden";

  async available(): Promise<boolean> {
    if (!(await commandExists("bw"))) return false;
    const r = await run("bw", ["status"], { timeoutMs: 15_000 }).catch(() => undefined);
    if (r?.code !== 0) return false;
    try {
      return (JSON.parse(r.stdout) as { status: string }).status === "unlocked";
    } catch {
      return false;
    }
  }

  private async folderId(create: boolean): Promise<string | undefined> {
    const r = await run("bw", ["list", "folders", "--search", FOLDER]);
    if (r.code !== 0) throw new Error("Bitwarden: vault is locked. Run `bw unlock` and export BW_SESSION.");
    const f = (JSON.parse(r.stdout || "[]") as { id: string; name: string }[]).find((x) => x.name === FOLDER);
    if (f) return f.id;
    if (!create) return undefined;
    const c = await run("bw", ["create", "folder"], { input: b64({ name: FOLDER }) });
    if (c.code !== 0) throw new Error("Bitwarden: could not create folder");
    return (JSON.parse(c.stdout) as { id: string }).id;
  }

  private async items(): Promise<BwItem[]> {
    const fid = await this.folderId(false);
    if (!fid) return [];
    const r = await run("bw", ["list", "items", "--folderid", fid]);
    if (r.code !== 0) throw new Error("Bitwarden: could not list items");
    return JSON.parse(r.stdout || "[]") as BwItem[];
  }

  async list(): Promise<string[]> {
    return (await this.items()).map((i) => i.name).sort();
  }

  async get(name: string): Promise<string | undefined> {
    assertValidName(name);
    return (await this.items()).find((i) => i.name === name)?.login?.password ?? undefined;
  }

  async set(name: string, value: string): Promise<void> {
    assertValidName(name);
    assertValidValue(value);
    const existing = (await this.items()).find((i) => i.name === name);
    if (existing) {
      existing.login = { ...(existing.login ?? {}), password: value };
      const r = await run("bw", ["edit", "item", existing.id], { input: b64(existing) });
      if (r.code !== 0) throw new Error(`Bitwarden: update failed for ${name}`);
      return;
    }
    const folderId = await this.folderId(true);
    const item = { organizationId: null, folderId, type: 1, name, notes: "Managed by agent-vault", login: { username: name, password: value } };
    const r = await run("bw", ["create", "item"], { input: b64(item) });
    if (r.code !== 0) throw new Error(`Bitwarden: write failed for ${name}`);
  }
}
