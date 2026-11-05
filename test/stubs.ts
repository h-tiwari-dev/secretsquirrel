import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Creates fake `op`, `bw`, `pass` executables. Every argv is appended to argv.log so tests can prove secrets never hit argv. */
export function makeStubs() {
  const dir = mkdtempSync(join(tmpdir(), "av-stubs-"));
  const state = join(dir, "state.json");
  const argvLog = join(dir, "argv.log");
  const store = join(dir, "pass-store");
  writeFileSync(state, JSON.stringify({ op: [], bwFolders: [], bwItems: [] }));

  const prelude = `
const fs = require("fs");
const S = ${JSON.stringify(state)};
const st = () => JSON.parse(fs.readFileSync(S, "utf8"));
const save = (s) => fs.writeFileSync(S, JSON.stringify(s));
const a = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(argvLog)}, process.argv[1].split("/").pop() + " " + a.join(" ") + "\\n");
const stdin = () => { try { return fs.readFileSync(0, "utf8"); } catch { return ""; } };
`;
  const write = (name: string, body: string) => {
    const p = join(dir, name);
    writeFileSync(p, `#!/usr/bin/env node\n${prelude}\n${body}`);
    chmodSync(p, 0o755);
  };

  write("op", `
const s = st();
if (a[0] === "whoami") process.exit(0);
if (a[0] === "vault") { console.log(JSON.stringify([{ name: "Private" }])); process.exit(0); }
if (a[0] === "item" && a[1] === "list") { console.log(JSON.stringify(s.op.filter(i => !i.archived).map(i => ({ id: i.id, title: i.title })))); process.exit(0); }
if (a[0] === "read") { const n = a[1].split("/")[3]; const i = s.op.find(x => x.title === n && !x.archived); if (!i) process.exit(1); console.log(i.value); process.exit(0); }
if (a[0] === "item" && a[1] === "delete") { const i = s.op.find(x => x.id === a[2]); i.archived = true; save(s); process.exit(0); }
if (a[0] === "item" && a[1] === "create") { const t = JSON.parse(stdin()); s.op.push({ id: "id" + s.op.length, title: t.title, value: t.fields[0].value }); save(s); console.log("{}"); process.exit(0); }
process.exit(2);
`);

  write("bw", `
const s = st();
if (a[0] === "status") { console.log(JSON.stringify({ status: "unlocked" })); process.exit(0); }
if (a[0] === "list" && a[1] === "folders") { console.log(JSON.stringify(s.bwFolders)); process.exit(0); }
if (a[0] === "create" && a[1] === "folder") { const f = JSON.parse(Buffer.from(stdin().trim(), "base64").toString()); f.id = "f1"; s.bwFolders.push(f); save(s); console.log(JSON.stringify(f)); process.exit(0); }
if (a[0] === "list" && a[1] === "items") { console.log(JSON.stringify(s.bwItems)); process.exit(0); }
if (a[0] === "create" && a[1] === "item") { const i = JSON.parse(Buffer.from(stdin().trim(), "base64").toString()); i.id = "i" + s.bwItems.length; s.bwItems.push(i); save(s); console.log(JSON.stringify(i)); process.exit(0); }
if (a[0] === "edit" && a[1] === "item") { const i = JSON.parse(Buffer.from(stdin().trim(), "base64").toString()); s.bwItems = s.bwItems.map(x => x.id === a[2] ? i : x); save(s); console.log("{}"); process.exit(0); }
process.exit(2);
`);

  write("pass", `
const path = require("path");
const root = ${JSON.stringify(store)};
const file = (n) => path.join(root, n + ".gpg");
if (a[0] === "show") { try { process.stdout.write(fs.readFileSync(file(a[1]), "utf8")); } catch { process.exit(1); } process.exit(0); }
if (a[0] === "insert") { const n = a[a.length - 1]; fs.mkdirSync(path.dirname(file(n)), { recursive: true }); fs.writeFileSync(file(n), stdin()); process.exit(0); }
process.exit(2);
`);

  return { dir, argvLog, store };
}
