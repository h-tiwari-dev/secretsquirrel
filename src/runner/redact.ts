const MIN_REDACT = 4; // shorter secrets would mangle ordinary output
const MIN_TRANSFORM_CHECK = 8; // transformed-form detection needs enough entropy to avoid false positives
const MIN_FRAGMENT = 6;

/** Base64 of `secret` as it would appear embedded in other data at each of the 3 byte alignments, keeping only the chars that do not depend on neighbouring bytes. */
function base64Fragments(secret: string, urlSafe: boolean): string[] {
  const out: string[] = [];
  const bytes = Buffer.from(secret);
  for (const k of [0, 1, 2]) {
    let b64 = Buffer.concat([Buffer.alloc(k), bytes]).toString(urlSafe ? "base64url" : "base64").replace(/=+$/, "");
    b64 = b64.slice([0, 2, 3][k]); // leading chars mixed with unknown preceding bytes
    if ((k + bytes.length) % 3 !== 0) b64 = b64.slice(0, -1); // last char mixed with unknown following byte
    if (b64.length >= MIN_FRAGMENT) out.push(b64);
  }
  return out;
}

/** Every encoding of a secret we scrub from command output before the agent sees it. */
export function variants(secret: string): string[] {
  if (secret.length < MIN_REDACT) return [];
  const hex = Buffer.from(secret).toString("hex");
  const all = new Set<string>([
    secret,
    JSON.stringify(secret).slice(1, -1),
    encodeURIComponent(secret),
    hex,
    hex.toUpperCase(),
    ...base64Fragments(secret, false),
    ...base64Fragments(secret, true),
  ]);
  return [...all].filter((v) => v.length >= MIN_REDACT).sort((a, b) => b.length - a.length);
}

export function redact(text: string, secrets: string[]): string {
  let out = text;
  for (const s of secrets) {
    for (const v of variants(s)) out = out.split(v).join("[REDACTED]");
  }
  return out;
}

const ANSI = /\x1b\[[0-9;?]*[ -/]*[@-~]/g;
/** Drop ANSI codes and every non-alphanumeric (spaces, newlines, commas, dots, dashes), lowercase: defeats `sed 's/./&,/g'`, `fold`, `xxd -p -c2`, wrapped base64. */
const squash = (s: string) => s.replace(ANSI, "").replace(/[^A-Za-z0-9]/g, "").toLowerCase();
const reverse = (s: string) => [...s].reverse().join("");

/**
 * Catches secrets that were spaced out, split, separated, wrapped, case-swapped, reversed or hex/base64-encoded
 * and then reformatted. Best-effort: it cannot see arbitrary transforms (rot13, base32, ciphers, one-bit oracles).
 */
export function leaksTransformed(text: string, secrets: string[]): boolean {
  const flat = squash(text);
  if (flat.length === 0) return false;
  return secrets.some((s) => {
    const forms = [s, ...variants(s)].map(squash).filter((n) => n.length >= MIN_TRANSFORM_CHECK);
    return forms.some((n) => flat.includes(n) || flat.includes(reverse(n)));
  });
}
