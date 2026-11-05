import { assertValidName, assertValidValue, type Backend } from "./types.js";
import { run } from "./exec.js";

const SERVICE = "agent-vault";

/** Escape for `security -i`, which parses double-quoted shell-like strings. */
function q(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

export class KeychainBackend implements Backend {
  readonly id = "keychain";
  readonly label = "macOS Keychain";

  async available(): Promise<boolean> {
    return process.platform === "darwin";
  }

  async list(): Promise<string[]> {
    // dump-keychain without -d prints attributes only (no secrets, no auth prompt).
    const r = await run("security", ["dump-keychain"]);
    const names = new Set<string>();
    // One record per "class:" block. The service attr prints as "svce" or as 0x00000007 depending on keychain.
    for (const rec of r.stdout.split(/^class: /m)) {
      const svc = rec.match(/(?:"svce"|0x00000007)\s*<blob>="(.*)"/)?.[1];
      const acct = rec.match(/"acct"<blob>="(.*)"/)?.[1];
      if (svc === SERVICE && acct) names.add(acct);
    }
    return [...names].sort();
  }

  async get(name: string): Promise<string | undefined> {
    assertValidName(name);
    const r = await run("security", ["find-generic-password", "-s", SERVICE, "-a", name, "-w"]);
    if (r.code !== 0) return undefined;
    return r.stdout.replace(/\n$/, "");
  }

  async set(name: string, value: string): Promise<void> {
    assertValidName(name);
    assertValidValue(value);
    // Value goes over stdin to `security -i`, never argv (visible in `ps`).
    const r = await run("security", ["-i"], {
      input: `add-generic-password -U -s ${q(SERVICE)} -a ${q(name)} -w ${q(value)}\n`,
    });
    if (r.code !== 0 || /error|fail/i.test(r.stderr)) {
      throw new Error(`Keychain write failed for ${name}.`);
    }
  }
}
