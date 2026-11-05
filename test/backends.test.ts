import { readFileSync, existsSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { BitwardenBackend } from "../src/backends/bitwarden.js";
import { OnePasswordBackend } from "../src/backends/onepassword.js";
import { PassBackend } from "../src/backends/pass.js";
import type { Backend } from "../src/backends/types.js";
import { makeStubs } from "./stubs.js";

const stubs = makeStubs();
const SECRET1 = "s3cr3t-first-VALUE";
const SECRET2 = "s3cr3t-second-VALUE";

beforeAll(() => {
  process.env.PATH = `${stubs.dir}:${process.env.PATH}`;
  process.env.PASSWORD_STORE_DIR = stubs.store;
});

function contract(name: string, make: () => Backend) {
  describe(name, () => {
    it("is available, empty, then round-trips set/get/list/update", async () => {
      const b = make();
      expect(await b.available()).toBe(true);
      expect(await b.list()).toEqual([]);
      expect(await b.get("GITHUB_TOKEN")).toBeUndefined();
      await b.set("GITHUB_TOKEN", SECRET1);
      expect(await b.get("GITHUB_TOKEN")).toBe(SECRET1);
      expect(await b.list()).toEqual(["GITHUB_TOKEN"]);
      await b.set("GITHUB_TOKEN", SECRET2);
      expect(await b.get("GITHUB_TOKEN")).toBe(SECRET2);
      expect(await b.list()).toEqual(["GITHUB_TOKEN"]);
    });
    it("rejects hostile names and multiline values", async () => {
      const b = make();
      await expect(b.set("../x", "v")).rejects.toThrow();
      await expect(b.set("OK_NAME", "a\nb")).rejects.toThrow();
    });
  });
}

contract("1Password backend (stub op)", () => new OnePasswordBackend("Private"));
contract("Bitwarden backend (stub bw)", () => new BitwardenBackend());
contract("pass backend (stub pass)", () => new PassBackend("pass"));

describe("argv hygiene", () => {
  it("no secret value ever appeared in any CLI's argv", () => {
    const log = readFileSync(stubs.argvLog, "utf8");
    expect(log.length).toBeGreaterThan(0);
    expect(log).not.toContain(SECRET1);
    expect(log).not.toContain(SECRET2);
    expect(existsSync(stubs.store)).toBe(true);
  });
});
