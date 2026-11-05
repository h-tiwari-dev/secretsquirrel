/**
 * Anything an agent supplies and a human reads (command text, hints, notes) goes through here first,
 * so control, bidi, zero-width and tag characters cannot hide or reorder what the human is approving.
 */
// Built from an escaped string (not a regex literal) so no raw line-separator characters ever appear in compiled output.
const HIDDEN = new RegExp(
  "[\\u0000-\\u0008\\u000b-\\u001f\\u007f-\\u009f\\u00ad\\u061c\\u180e\\u200b-\\u200f\\u2028-\\u202e\\u034f\\u115f\\u1160\\u17b4\\u17b5\\u2060-\\u2069\\u2800\\u3164\\ufe00-\\ufe0f\\ufeff\\uffa0\\ufff9-\\ufffb\\u{e0000}-\\u{e007f}\\u{e0100}-\\u{e01ef}]",
  "gu",
);

export function visible(s: string): string {
  return s
    .replace(/\r\n|\n|\r/g, " ⏎ ")
    .replace(/\t/g, " ⇥ ")
    .replace(HIDDEN, (c) => `\\u{${c.codePointAt(0)!.toString(16)}}`);
}

/** Clip by code point (never splits a surrogate pair). */
export function clip(s: string, max: number): string {
  const cps = [...s];
  return cps.length <= max ? s : cps.slice(0, max).join("") + "…";
}

export const codePoints = (s: string) => [...s].length;

/** Plain, short, single-line text from the agent for display. */
export function agentText(s: string | undefined, max: number): string | undefined {
  if (!s) return undefined;
  return clip(visible(s), max);
}

/** Distinct non-ASCII characters in `s` as "U+0430 (а)". Homoglyphs (Cyrillic "а" in a hostname) look identical on screen. */
export function nonAscii(s: string): string[] {
  const seen = new Set<string>();
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (cp > 0x7e) seen.add(`U+${cp.toString(16).toUpperCase().padStart(4, "0")}`);
  }
  return [...seen];
}
