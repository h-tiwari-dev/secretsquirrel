import { readdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { assertValidName, assertValidValue, type Backend } from "./types.js";
import { commandExists, run } from "./exec.js";

const PREFIX = "agent-vault";

/** `pass` or `gopass`. Entries live at agent-vault/NAME. */
export class PassBackend implements Backend {
  readonly id: string;
  readonly label: string;
  constructor(private bin: "pass" | "gopass" = "pass") {
    this.id = bin;
    this.label = bin === "pass" ? "pass (GPG store)" : "gopass";
  }

  async available(): Promise<boolean> {
    return commandExists(this.bin);
  }

  private storeDir(): string {
    return process.env.PASSWORD_STORE_DIR ?? join(homedir(), ".password-store");
  }

  async list(): Promise<string[]> {
    try {
      const files = await readdir(join(this.storeDir(), PREFIX));
      return files.filter((f) => f.endsWith(".gpg") || f.endsWith(".age")).map((f) => f.replace(/\.(gpg|age)$/, "")).sort();
    } catch {
      return [];
    }
  }

  async get(name: string): Promise<string | undefined> {
    assertValidName(name);
    const args = this.bin === "pass" ? ["show", `${PREFIX}/${name}`] : ["show", "-o", `${PREFIX}/${name}`];
    const r = await run(this.bin, args);
    if (r.code !== 0) return undefined;
    return r.stdout.split("\n")[0]; // first line is the password by pass convention
  }

  async set(name: string, value: string): Promise<void> {
    assertValidName(name);
    assertValidValue(value);
    const args = this.bin === "pass" ? ["insert", "-m", "-f", `${PREFIX}/${name}`] : ["insert", "-f", `${PREFIX}/${name}`];
    // Value over stdin, never argv. pass/gopass keep git history of the store, which doubles as our versioned backup.
    const r = await run(this.bin, args, { input: value + "\n" });
    if (r.code !== 0) throw new Error(`${this.bin}: write failed for ${name}`);
  }
}
