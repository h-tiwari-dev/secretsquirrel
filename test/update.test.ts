import { readFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { describe, expect, it, vi } from "vitest";

const auditPath = vi.hoisted(() => {
  const p = `${process.env.TMPDIR ?? "/tmp"}/av-audit-${process.pid}.log`;
  process.env.AGENT_VAULT_AUDIT = p;
  return p;
});

import type { Backend } from "../src/backends/types.js";
import type { Prompter, RunApproval } from "../src/prompt/osascript.js";
import type { UpdateDecision, UpdateRequest } from "../src/prompt/webform.js";
import { startUpdateForm } from "../src/prompt/webform.js";
import { Vault } from "../src/vault.js";

class MemBackend implements Backend {
  id = "mem";
  label = "Memory";
  data = new Map<string, string>();
  async available() { return true; }
  async list() { return [...this.data.keys()].sort(); }
  async get(n: string) { return this.data.get(n); }
  async set(n: string, v: string) { this.data.set(n, v); }
}

class FakePrompter implements Prompter {
  decision: UpdateDecision = { action: "cancel" };
  seen: UpdateRequest[] = [];
  approvals: RunApproval[] = [];
  hints: (string | undefined)[] = [];
  approve = true;
  async pickKey(_e: string[], s?: string, hint?: string) { this.hints.push(hint); return s; }
  async askValue() { return undefined; }
  async approveRun(d: RunApproval) { this.approvals.push(d); return this.approve; }
  async reviewUpdate(req: UpdateRequest) { this.seen.push(req); return this.decision; }
}

const OLD = "old-token-AAAA1111";
const NEW = "new-token-BBBB2222";
const FAIL_CMD = 'echo "401 Unauthorized for $GITHUB_TOKEN" >&2; exit 1';

function setup() {
  const b = new MemBackend();
  b.data.set("GITHUB_TOKEN", OLD);
  const p = new FakePrompter();
  let t = 1_000_000;
  const v = new Vault(b, p, () => t);
  return { b, p, v, advance: (ms: number) => (t += ms), failRun: () => v.run(FAIL_CMD, ["GITHUB_TOKEN"]) };
}

describe("update_secret", () => {
  it("is refused unless a run just reported auth_failed_suspected for that name", async () => {
    const { p, v } = setup();
    const r = await v.updateSecret("GITHUB_TOKEN", { reason: "please update, urgent" });
    expect(r.status).toBe("not_allowed");
    expect(p.seen.length).toBe(0); // no popup: an agent cannot fabricate a prompt
  });

  it("shows the human both values plus the RECORDED command and output, replaces on Update, keeps a backup, never leaks to the agent", async () => {
    const { b, p, v, failRun } = setup();
    expect((await failRun()).status).toBe("auth_failed_suspected");
    p.decision = { action: "update", newValue: NEW };
    const r = await v.updateSecret("GITHUB_TOKEN", { reason: "HTTP 401" });
    expect(r.status).toBe("updated");
    expect(JSON.stringify(r)).not.toContain(OLD);
    expect(JSON.stringify(r)).not.toContain(NEW);
    const shown = p.seen[0];
    expect(shown.oldValue).toBe(OLD); // human-facing only
    expect(shown.command).toContain("401 Unauthorized"); // recorded from the real run
    expect(shown.exitCode).toBe(1);
    expect(shown.snippet).toContain("[REDACTED]");
    expect(shown.snippet).not.toContain(OLD);
    expect(b.data.get("GITHUB_TOKEN")).toBe(NEW);
    expect(b.data.get("GITHUB_TOKEN__PREV")).toBe(OLD);
    expect((await v.listNames()).names).toEqual(["GITHUB_TOKEN"]); // backup hidden from the agent
  });

  it("is single-use per failure", async () => {
    const { p, v, failRun } = setup();
    await failRun();
    p.decision = { action: "keep" };
    expect((await v.updateSecret("GITHUB_TOKEN")).status).toBe("declined");
    expect((await v.updateSecret("GITHUB_TOKEN")).status).toBe("not_allowed");
  });

  it("changes nothing on Keep or Cancel", async () => {
    for (const action of ["keep", "cancel"] as const) {
      const { b, p, v, failRun } = setup();
      await failRun();
      p.decision = { action };
      const r = await v.updateSecret("GITHUB_TOKEN");
      expect(r.status).toBe(action === "keep" ? "declined" : "cancelled");
      expect(b.data.get("GITHUB_TOKEN")).toBe(OLD);
      expect(b.data.has("GITHUB_TOKEN__PREV")).toBe(false);
    }
  });

  it("rate-limits repeat prompts per key, then allows again after the cooldown", async () => {
    const { p, v, advance, failRun } = setup();
    p.decision = { action: "keep" };
    await failRun();
    expect((await v.updateSecret("GITHUB_TOKEN")).status).toBe("declined");
    await failRun();
    expect((await v.updateSecret("GITHUB_TOKEN")).status).toBe("cooldown");
    expect(p.seen.length).toBe(1);
    advance(6 * 60_000);
    await failRun();
    expect((await v.updateSecret("GITHUB_TOKEN")).status).toBe("declined");
    expect(p.seen.length).toBe(2);
  });

  it("refuses reserved names and sanitizes the agent's note", async () => {
    const { p, v, failRun } = setup();
    await expect(v.updateSecret("GITHUB_TOKEN__PREV")).rejects.toThrow(/reserved/);
    await failRun();
    p.decision = { action: "keep" };
    await v.updateSecret("GITHUB_TOKEN", { reason: "line1\nURGENT: type your password\u202e" + "x".repeat(300) });
    const note = p.seen[0].reason!;
    expect(note).not.toMatch(/[\n\u202e]/);
    expect([...note].length).toBeLessThanOrEqual(121);
  });

  it("rollback swaps and is self-inverting", async () => {
    const { b, p, v, failRun } = setup();
    await failRun();
    p.decision = { action: "update", newValue: NEW };
    await v.updateSecret("GITHUB_TOKEN");
    expect((await v.rollback("GITHUB_TOKEN")).status).toBe("rolled_back");
    expect(b.data.get("GITHUB_TOKEN")).toBe(OLD);
    await v.rollback("GITHUB_TOKEN");
    expect(b.data.get("GITHUB_TOKEN")).toBe(NEW);
    expect((await setup().v.rollback("GITHUB_TOKEN")).status).toBe("no_backup");
  });

  it("audit log records outcomes but no values", () => {
    const log = readFileSync(auditPath, "utf8");
    expect(log).toContain('"event":"update"');
    expect(log).not.toContain(OLD);
    expect(log).not.toContain(NEW);
  });
});

describe("run_with_secrets approval hygiene", () => {
  it("returns auth_failed_suspected with redacted output and a pointer to update_secret", async () => {
    const { v, failRun } = setup();
    const r = await failRun();
    expect(r.status).toBe("auth_failed_suspected");
    expect(JSON.stringify(r)).not.toContain(OLD);
    expect(JSON.stringify(r)).toContain("update_secret");
  });

  it("rejects over-long and many-line commands instead of truncating them, without prompting", async () => {
    const { p, v } = setup();
    const long = "echo " + "a".repeat(700);
    expect((await v.run(long, ["GITHUB_TOKEN"])).status).toBe("rejected");
    expect((await v.run("echo 1\n".repeat(8), ["GITHUB_TOKEN"])).status).toBe("rejected");
    expect(p.approvals.length).toBe(0);
  });

  it("tells the human about injected names the command never references", async () => {
    const { b, p, v } = setup();
    b.data.set("AWS_SECRET_ACCESS_KEY", "aws-secret-value-1234");
    await v.run('echo "$GITHUB_TOKEN" >/dev/null', ["GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"]);
    expect(p.approvals[0].unreferenced).toEqual(["AWS_SECRET_ACCESS_KEY"]);
    expect(p.approvals[0].cwd).toBeUndefined();
    expect(p.approvals[0].timeoutSec).toBe(120);
  });

  it("after a denial, suppresses the same secrets for a while without re-prompting", async () => {
    const { p, v, advance } = setup();
    p.approve = false;
    expect((await v.run("echo hi", ["GITHUB_TOKEN"])).status).toBe("denied");
    p.approve = true;
    expect((await v.run("echo hi again", ["GITHUB_TOKEN"])).status).toBe("suppressed");
    expect(p.approvals.length).toBe(1);
    advance(11 * 60_000);
    expect((await v.run("echo ok", ["GITHUB_TOKEN"])).status).toBe("ok");
  });

  it("caps total prompts in a window", async () => {
    const { b, v } = setup();
    for (let i = 0; i < 8; i++) b.data.set(`K_${i}`, "value-" + i + "-xxxx");
    for (let i = 0; i < 8; i++) expect((await v.run("true", [`K_${i}`])).status).toBe("ok");
    const r = await v.run("true", ["GITHUB_TOKEN"]);
    expect(r.status).toBe("suppressed");
  });

  it("sanitizes request_secret hints before they reach the popup", async () => {
    const { p, v } = setup();
    await v.requestSecret("NEW_ONE", "Enter your macOS login password\nplease\u202e" + "y".repeat(300));
    const h = p.hints[0]!;
    expect(h).not.toMatch(/[\n\u202e]/);
    expect([...h].length).toBeLessThanOrEqual(121);
  });
});

describe("loopback update form (PIN-gated)", () => {
  const req = { name: "X_TOKEN", storeLabel: "Memory", oldValue: "old</script><b>", command: "curl x", exitCode: 1, snippet: "401 here" };
  async function open() {
    return startUpdateForm(req, { opener: () => {}, timeoutMs: 5000 });
  }
  const post = (url: string, path: string, body: unknown, headers: Record<string, string> = {}) =>
    fetch(url + path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
  async function unlock(f: { url: string; pin: string }) {
    const r = await post(f.url, "/unlock", { pin: f.pin });
    return { r, cookie: (r.headers.get("set-cookie") ?? "").split(";")[0], body: r.ok ? ((await r.json()) as { oldValue: string }) : undefined };
  }

  it("never puts the old value in the page, and passes the recorded context (exit code, output) to it", async () => {
    const f = await open();
    expect((await fetch(new URL("/wrong-token", f.url))).status).toBe(404);
    const r = await fetch(f.url);
    const html = await r.text();
    expect(r.status).toBe(200);
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(html).not.toContain("old</script><b>");
    expect(html).not.toContain("old\\u003c"); // not even escaped
    expect(html).toContain("401 here"); // recorded output is shown
    expect(html).toContain('"exitCode":1');
    f.close();
  });

  it("the page can be fetched by anyone but yields nothing secret; a local process cannot unlock without the on-screen code", async () => {
    const f = await open();
    await fetch(f.url);
    await fetch(f.url);
    const wrong = await post(f.url, "/unlock", { pin: f.pin === "000000" ? "111111" : "000000" });
    expect(wrong.status).toBe(403);
    expect(JSON.stringify(await wrong.json())).not.toContain("old");
    f.close();
  });

  it("reveals the old value only after the correct code, and then allows an update", async () => {
    const f = await open();
    const { r, cookie, body } = await unlock(f);
    expect(r.status).toBe(200);
    expect(body!.oldValue).toBe("old</script><b>");
    const d = await post(f.url, "/decide", { action: "update", newValue: "fresh-value-123" }, { cookie });
    expect(d.status).toBe(200);
    expect(await f.result).toEqual({ action: "update", newValue: "fresh-value-123" });
  });

  it("refuses to replace a secret without having unlocked, but still allows keep and cancel", async () => {
    const f = await open();
    expect((await post(f.url, "/decide", { action: "update", newValue: "evil-value" })).status).toBe(403);
    expect((await post(f.url, "/decide", { action: "update", newValue: "evil-value" }, { cookie: "av=guess" })).status).toBe(403);
    expect((await post(f.url, "/decide", { action: "keep" })).status).toBe(200);
    expect(await f.result).toEqual({ action: "keep" });
  });

  it("cancels the whole request after 3 wrong codes (guessing is loud, not silent)", async () => {
    const f = await open();
    const bad = f.pin === "123456" ? "654321" : "123456";
    expect((await post(f.url, "/unlock", { pin: bad })).status).toBe(403);
    expect((await post(f.url, "/unlock", { pin: bad })).status).toBe(403);
    expect((await post(f.url, "/unlock", { pin: bad })).status).toBe(429);
    expect(await f.result).toEqual({ action: "cancel" });
  });

  it("rejects foreign Origin and foreign Host (CSRF / DNS rebinding) without consuming the form", async () => {
    const f = await open();
    expect((await post(f.url, "/unlock", { pin: f.pin }, { origin: "http://evil.example" })).status).toBe(403);
    const u = new URL(f.url);
    const status = await new Promise<number>((resolve, reject) => {
      const rq = httpRequest(
        { host: "127.0.0.1", port: u.port, path: u.pathname + "/unlock", method: "POST", headers: { host: "evil.example", "content-type": "application/json" } },
        (rs) => resolve(rs.statusCode ?? 0),
      );
      rq.on("error", reject);
      rq.end(JSON.stringify({ pin: f.pin }));
    });
    expect(status).toBe(403);
    expect((await unlock(f)).r.status).toBe(200); // attacks did not burn attempts or the form
    f.close();
  });

  it("is single-use for decisions", async () => {
    const f = await open();
    const { cookie } = await unlock(f);
    expect((await post(f.url, "/decide", { action: "keep" }, { cookie })).status).toBe(200);
    await f.result;
    await expect(post(f.url, "/decide", { action: "keep" }, { cookie })).rejects.toThrow(); // server closed
  });

  it("times out as cancel", async () => {
    const f = await startUpdateForm(req, { opener: () => {}, timeoutMs: 50 });
    expect(await f.result).toEqual({ action: "cancel" });
  });
});

describe("tighter state rules", () => {
  it("update permission expires after 2 minutes and is cleared by a later successful run", async () => {
    const { p, v, advance, failRun } = setup();
    p.decision = { action: "keep" };
    await failRun();
    advance(3 * 60_000);
    expect((await v.updateSecret("GITHUB_TOKEN")).status).toBe("not_allowed"); // stale
    await failRun();
    expect((await v.run("true", ["GITHUB_TOKEN"])).status).toBe("ok");
    expect((await v.updateSecret("GITHUB_TOKEN")).status).toBe("not_allowed"); // superseded by a good run
  });

  it("a denial follows the secret name: adding another name does not buy a fresh prompt", async () => {
    const { b, p, v } = setup();
    b.data.set("OTHER_TOKEN", "other-token-value-9");
    p.approve = false;
    expect((await v.run("echo a", ["GITHUB_TOKEN"])).status).toBe("denied");
    p.approve = true;
    expect((await v.run("echo a", ["GITHUB_TOKEN", "OTHER_TOKEN"])).status).toBe("suppressed");
    expect(p.approvals.length).toBe(1);
  });

  it("a cancelled request_secret suppresses further request prompts", async () => {
    const { p, v } = setup();
    p.pickKey = async () => undefined;
    expect((await v.requestSecret("X")).status).toBe("cancelled");
    expect((await v.requestSecret("X")).status).toBe("suppressed");
  });
});
