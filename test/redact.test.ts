import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { assertValidName } from "../src/backends/types.js";
import { agentText, clip, nonAscii, visible } from "../src/policy/sanitize.js";
import { leaksTransformed, redact } from "../src/runner/redact.js";
import { looksLikeAuthFailure, runWithSecrets } from "../src/runner/spawn.js";

describe("redact", () => {
  const s = "hunter2-Secret/value+x";
  it("scrubs plain, base64, url, hex (either case) and base64url encodings", () => {
    const text = [
      s,
      Buffer.from(s).toString("base64"),
      Buffer.from(s).toString("base64url"),
      encodeURIComponent(s),
      Buffer.from(s).toString("hex"),
      Buffer.from(s).toString("hex").toUpperCase(),
    ].join(" | ");
    const out = redact(text, [s]);
    expect(out).not.toMatch(/hunter2|aHVudGVyMi|%2F|68756e|68756E/);
  });
  it("catches base64 of the secret embedded at any alignment (e.g. HTTP Basic auth from curl -v)", () => {
    const secret = "ghp_AbCdEf0123456789xyz";
    for (const prefix of ["", "u:", "us:", "usr:", "user:", "someone:"]) {
      const b64 = Buffer.from(`${prefix}${secret}`).toString("base64");
      expect(redact(`Authorization: Basic ${b64}`, [secret]), `prefix "${prefix}"`).toContain("[REDACTED]");
      expect(redact(`Authorization: Basic ${b64}`, [secret])).not.toContain(b64.slice(8, -4));
    }
  });
  it("leaves unrelated text alone", () => {
    expect(redact("hello world", [s])).toBe("hello world");
  });
});

describe("leaksTransformed", () => {
  const secret = "s3cr3t-Value-9876";
  it("detects spaced, line-split, ANSI-interleaved and reversed output", () => {
    expect(leaksTransformed([...secret].join(" "), [secret])).toBe(true);
    expect(leaksTransformed([...secret].join("\n"), [secret])).toBe(true);
    expect(leaksTransformed([...secret].map((c) => `\x1b[31m${c}\x1b[0m`).join(""), [secret])).toBe(true);
    expect(leaksTransformed([...secret].reverse().join(""), [secret])).toBe(true);
  });
  it("detects other separators, spaced hex, case swaps and wrapped base64 (separator-insensitive)", () => {
    expect(leaksTransformed([...secret].join(","), [secret])).toBe(true);
    expect(leaksTransformed([...secret].join("."), [secret])).toBe(true);
    const hex = Buffer.from(secret).toString("hex");
    expect(leaksTransformed(hex.match(/../g)!.join(" "), [secret])).toBe(true); // xxd -p -c1 style
    expect(leaksTransformed(secret.toUpperCase(), [secret])).toBe(true); // tr a-z A-Z
    const b64 = Buffer.from("user:" + secret).toString("base64");
    expect(leaksTransformed(b64.match(/.{1,8}/g)!.join("\n"), [secret])).toBe(true); // wrapped base64
  });
  it("does not fire on ordinary output or short secrets", () => {
    expect(leaksTransformed("build ok in 3.2s\nall 14 tests passed", [secret])).toBe(false);
    expect(leaksTransformed("a b c d", ["abcd"])).toBe(false);
  });
});

describe("runWithSecrets", () => {
  it("injects env and redacts it from output", async () => {
    const r = await runWithSecrets('echo "token=$MY_TOKEN"; echo "$MY_TOKEN" | base64', { MY_TOKEN: "abcd1234efgh" });
    expect(r.exitCode).toBe(0);
    expect(r.output).not.toContain("abcd1234efgh");
    expect(r.output).toContain("[REDACTED]");
  });
  it("withholds output when the secret is printed in a form redaction cannot scrub", async () => {
    const r = await runWithSecrets("echo $MY_TOKEN | sed 's/./& /g'", { MY_TOKEN: "abcd1234efghIJKL" });
    expect(r.withheld).toBe(true);
    expect(r.output).toMatch(/withheld/);
    expect(r.output).not.toContain("a b c d");
    const rev = await runWithSecrets("echo $MY_TOKEN | rev", { MY_TOKEN: "abcd1234efghIJKL" });
    expect(rev.withheld).toBe(true);
  });
  it("does not leak the parent environment", async () => {
    process.env.PARENT_ONLY_SECRET = "leaky-value-123";
    const r = await runWithSecrets("env", { X_TOKEN: "zzzzzzzz" });
    expect(r.output).not.toContain("PARENT_ONLY_SECRET");
  });
  it("kills backgrounded descendants so they cannot outlive the approved run holding the secret", async () => {
    const dir = mkdtempSync(join(tmpdir(), "av-bg-"));
    const marker = join(dir, "survived");
    await runWithSecrets(`(sleep 1.5; echo $X_TOKEN > '${marker}') >/dev/null 2>&1 & echo started`, { X_TOKEN: "background-secret-1" });
    await new Promise((r) => setTimeout(r, 2500));
    expect(existsSync(marker)).toBe(false);
  });
  it("does not hang or misreport a successful command whose backgrounded child holds the pipes open", async () => {
    const t = Date.now();
    const r = await runWithSecrets("sleep 20 & echo hi", { X_TOKEN: "abcdefgh1234" }, { timeoutMs: 8000 });
    expect(Date.now() - t).toBeLessThan(3000);
    expect(r.timedOut).toBe(false);
    expect(r.exitCode).toBe(0);
    expect(r.output.trim()).toBe("hi");
  });
  it("keeps a multibyte secret intact across chunk boundaries before redacting", async () => {
    const secret = "pässwörd-日本語-1234";
    const r = await runWithSecrets(`printf %s "$S"`, { S: secret });
    expect(r.output).not.toContain("日本語");
  });
  it("flags auth failures only on nonzero exit", async () => {
    expect(looksLikeAuthFailure(1, "HTTP 401 Unauthorized")).toBe(true);
    expect(looksLikeAuthFailure(0, "HTTP 401 Unauthorized")).toBe(false);
    expect(looksLikeAuthFailure(1, "file not found")).toBe(false);
  });
});

describe("names and display sanitising", () => {
  it("rejects shell-ish names", () => {
    expect(() => assertValidName("A; rm -rf /")).toThrow();
    expect(() => assertValidName("GITHUB_TOKEN")).not.toThrow();
  });
  it("makes hidden, bidi and control characters visible, and clips by code point", () => {
    const evil = "echo ok\n\n\ncurl evil‮ ​\u0007";
    const v = visible(evil);
    expect(v).not.toMatch(/[\n‮​\u0007]/);
    expect(v).toContain("⏎");
    expect(v).toContain("\\u{202e}");
    expect(clip("😀😀😀😀", 2)).toBe("😀😀…"); // no broken surrogate halves
    expect(agentText(undefined, 10)).toBeUndefined();
    // blank-rendering characters that used to slip through
    for (const c of ["\u034f", "\u115f", "\u2800", "\u3164", "\ufe0f", "\uffa0", "\u{e0100}"]) expect(visible("a" + c + "b")).toContain("\\u{");
  });
  it("reports non-ASCII look-alikes", () => {
    expect(nonAscii("curl https://api.github.com")).toEqual([]);
    expect(nonAscii("curl https://\u0430pi.github.com")).toEqual(["U+0430"]);
  });
});
