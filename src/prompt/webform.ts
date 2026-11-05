import { randomBytes, randomInt, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { run } from "../backends/exec.js";

export interface UpdateRequest {
  name: string;
  storeLabel: string;
  oldValue: string;
  /** Recorded from the run that failed, not supplied by the agent. */
  command?: string;
  exitCode?: number | null;
  /** Redacted output snippet from that run. */
  snippet?: string;
  /** Unverified note from the agent. */
  reason?: string;
}
export type UpdateDecision = { action: "update"; newValue: string } | { action: "keep" } | { action: "cancel" };

export interface FormHandle {
  url: string;
  /** 6-digit code the human must type into the page. Show it ONLY in a native dialog, never to the agent. */
  pin: string;
  result: Promise<UpdateDecision>;
  close(): void;
}

/** Keep JSON safe inside a <script type="application/json"> block. */
const safeJson = (o: unknown) => JSON.stringify(o).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026");

const PAGE = (data: string) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>agent-vault: update secret</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--mut:#666;--bd:#d0d0d0;--ac:#0b57d0;--bad:#b3261e;--card:#f6f6f6}
@media(prefers-color-scheme:dark){:root{--bg:#161616;--fg:#eee;--mut:#9a9a9a;--bd:#3a3a3a;--ac:#8ab4f8;--bad:#f2b8b5;--card:#222}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;margin:0;padding:24px 16px}
main{max-width:640px;margin:0 auto}h1{font-size:20px;margin:0 0 4px}.mut{color:var(--mut)}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px 16px;margin:14px 0}
code{font:13px ui-monospace,monospace;word-break:break-all}label{display:block;font-weight:600;margin:12px 0 4px}
.row{display:flex;gap:8px}input{flex:1;font:14px ui-monospace,monospace;padding:9px 10px;border:1px solid var(--bd);border-radius:8px;background:var(--bg);color:var(--fg)}
button{font:inherit;padding:9px 14px;border-radius:8px;border:1px solid var(--bd);background:var(--bg);color:var(--fg);cursor:pointer}
button.p{background:var(--ac);color:#fff;border-color:var(--ac)}button:disabled{opacity:.45;cursor:not-allowed}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:18px}#warn{color:var(--bad);min-height:1.4em;margin-top:6px}
</style></head><body><main>
<h1>Update secret <code id="name"></code>?</h1>
<p class="mut">An agent's command appears to have failed authentication. Values stay on this machine. <b>The agent never sees either one.</b></p>
<div class="card"><div class="mut">Store</div><code id="store"></code><div class="mut" style="margin-top:8px">Command that failed (recorded by agent-vault)</div><code id="cmd"></code>
<div class="mut" style="margin-top:8px">Exit code <code id="exit"></code> and output (secrets scrubbed)</div><code id="snip"></code>
<div id="reasonbox" class="mut" style="margin-top:8px"></div></div>
<div class="card" id="gate"><b>Unlock to compare values.</b>
<div class="mut">A dialog on your screen shows a 6-digit code. Type it here. Nothing secret is on this page until you do.</div>
<div class="row" style="margin-top:8px"><input id="pin" inputmode="numeric" maxlength="6" autocomplete="off" autofocus placeholder="6-digit code"><button id="unlock" type="button" class="p">Unlock</button></div><div id="pinmsg" class="mut"></div></div>
<div id="vals" hidden>
<label for="old">Current value</label>
<div class="row"><input id="old" type="password" readonly><button id="oldt" type="button">Reveal</button></div>
<label for="new">New value</label>
<div class="row"><input id="new" type="password" autocomplete="off" spellcheck="false"><button id="newt" type="button">Reveal</button></div></div>
<div id="warn" role="status"></div>
<div class="actions"><button class="p" id="upd" disabled>Update</button><button id="keep">Keep old</button><button id="cancel">Cancel</button></div>
<p class="mut" id="done"></p>
<script id="d" type="application/json">${data}</script>
<script>
const D=JSON.parse(document.getElementById("d").textContent);const $=id=>document.getElementById(id);
$("name").textContent=D.name;$("store").textContent=D.storeLabel;$("cmd").textContent=D.command||"(not provided)";
$("exit").textContent=D.exitCode==null?"?":String(D.exitCode);$("snip").textContent=D.snippet||"(none)";
if(D.reason)$("reasonbox").textContent="Unverified note from the agent: "+D.reason;
let OLD=null;
async function post(path,b){return fetch(location.pathname+path,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(b)})}
$("unlock").onclick=async()=>{const r=await post("/unlock",{pin:$("pin").value.trim()});
 if(r.ok){const j=await r.json();OLD=j.oldValue;$("old").value=OLD;$("gate").hidden=true;$("vals").hidden=false;$("new").focus();check()}
 else{const j=await r.json().catch(()=>({}));$("pinmsg").textContent=j.locked?"Too many wrong codes. This request was cancelled.":"Wrong code. Attempts left: "+(j.left??"?");if(j.locked)document.querySelectorAll("button").forEach(x=>x.disabled=true)}};
function tog(i,b){$(b).onclick=()=>{const s=$(i).type==="password";$(i).type=s?"text":"password";$(b).textContent=s?"Hide":"Reveal"}}
tog("old","oldt");tog("new","newt");
function check(){const v=$("new").value;let w="";
 if(v&&OLD!==null&&v===OLD)w="The new value is identical to the current one.";
 else if(/[\\r\\n]/.test(v))w="Newlines are not supported.";
 else if(v&&/^\\s|\\s$/.test(v))w="Heads up: the new value has leading or trailing whitespace.";
 $("warn").textContent=w;$("upd").disabled=OLD===null||!v||v===OLD||/[\\r\\n]/.test(v)}
$("new").addEventListener("input",check);
async function send(b){document.querySelectorAll("button").forEach(x=>x.disabled=true);
 const r=await post("/decide",b);
 $("done").textContent=r.ok?"Done. You can close this tab.":"Rejected by agent-vault.";if(r.ok)setTimeout(()=>window.close(),400)}
$("upd").onclick=()=>send({action:"update",newValue:$("new").value});
$("keep").onclick=()=>send({action:"keep"});$("cancel").onclick=()=>send({action:"cancel"});
</script></main></body></html>`;

export interface FormOptions {
  /** Called with the URL once the server is listening. Default opens the default browser. */
  opener?: (url: string) => void | Promise<void>;
  timeoutMs?: number;
}

export async function startUpdateForm(req: UpdateRequest, opts: FormOptions = {}): Promise<FormHandle> {
  const token = randomBytes(24).toString("base64url");
  let settled = false;
  const pin = String(randomInt(0, 1_000_000)).padStart(6, "0");
  let attempts = 0;
  let unlocked: string | undefined; // cookie nonce, issued only after the correct PIN
  let resolveResult!: (d: UpdateDecision) => void;
  const result = new Promise<UpdateDecision>((r) => (resolveResult = r));

  const server = createServer((rq: IncomingMessage, rs: ServerResponse) => {
    const port = (server.address() as AddressInfo).port;
    const deny = (code: number) => {
      rs.writeHead(code, { "content-type": "text/plain" });
      rs.end("forbidden");
    };
    // DNS-rebinding defence: only our exact loopback origin may talk to us.
    if (rq.headers.host !== `127.0.0.1:${port}`) return deny(403);
    const origin = rq.headers.origin;
    if (origin !== undefined && origin !== `http://127.0.0.1:${port}`) return deny(403);
    const base = `/${token}`;
    const headers = {
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'",
    };

    if (rq.method === "GET" && rq.url === base) {
      // The page itself holds nothing secret (no old value), so it can be fetched freely. Secrets only flow after /unlock.
      rs.writeHead(200, { ...headers, "content-type": "text/html; charset=utf-8" });
      rs.end(PAGE(safeJson({ name: req.name, storeLabel: req.storeLabel, command: req.command, exitCode: req.exitCode, snippet: req.snippet, reason: req.reason })));
      return;
    }
    const readJsonBody = (cb: (j: Record<string, unknown> | undefined) => void) => {
      let body = "";
      rq.on("data", (c) => {
        body += c;
        if (body.length > 64_000) rq.destroy();
      });
      rq.on("end", () => {
        try {
          cb(JSON.parse(body));
        } catch {
          cb(undefined);
        }
      });
    };
    const json = (code: number, o: unknown) => {
      rs.writeHead(code, { ...headers, "content-type": "application/json" });
      rs.end(JSON.stringify(o));
    };
    if (rq.method === "POST" && rq.url === `${base}/unlock` && !settled) {
      readJsonBody((j) => {
        const given = typeof j?.pin === "string" ? j.pin : "";
        const a = Buffer.from(given.padEnd(6, " ").slice(0, 6));
        const b = Buffer.from(pin);
        if (given.length === 6 && timingSafeEqual(a, b)) {
          unlocked = randomBytes(24).toString("base64url");
          rs.writeHead(200, { ...headers, "content-type": "application/json", "set-cookie": `av=${unlocked}; HttpOnly; SameSite=Strict; Path=/` });
          rs.end(JSON.stringify({ oldValue: req.oldValue }));
          return;
        }
        attempts += 1;
        if (attempts >= 3) {
          // Someone is guessing. Cancel loudly rather than let them keep trying.
          settled = true;
          json(429, { locked: true });
          resolveResult({ action: "cancel" });
          close();
          return;
        }
        json(403, { left: 3 - attempts });
      });
      return;
    }
    if (rq.method === "POST" && rq.url === `${base}/decide` && !settled) {
      const hasCookie = unlocked !== undefined && (rq.headers.cookie ?? "").split(/;\s*/).includes(`av=${unlocked}`);
      readJsonBody((j) => {
        let d: UpdateDecision | undefined;
        if (j?.action === "update" && typeof j.newValue === "string" && j.newValue.length > 0) {
          if (!hasCookie) return deny(403); // replacing a secret requires the PIN step
          d = { action: "update", newValue: j.newValue };
        } else if (j?.action === "keep") d = { action: "keep" };
        else if (j?.action === "cancel") d = { action: "cancel" };
        if (!d) return deny(400);
        settled = true; // single use
        rs.writeHead(200, headers).end("ok");
        resolveResult(d);
        close();
      });
      return;
    }
    deny(404);
  });

  const timer = setTimeout(() => {
    if (!settled) {
      settled = true;
      resolveResult({ action: "cancel" });
      close();
    }
  }, opts.timeoutMs ?? 10 * 60_000);
  function close() {
    clearTimeout(timer);
    server.close();
    server.closeAllConnections();
  }

  await new Promise<void>((res) => server.listen(0, "127.0.0.1", res));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/${token}`;
  await (opts.opener ?? defaultOpen)(url);
  return { url, pin, result, close };
}

async function defaultOpen(url: string): Promise<void> {
  const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  await run(cmd, args, { timeoutMs: 10_000 }).catch(() => undefined);
}
