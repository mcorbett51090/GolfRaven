/**
 * Minimal HTML→text extraction for X2/X4 evidence (decision 0001 Addendum
 * G: "HTML → text with tags stripped and whitespace collapsed"). This is a
 * conservative tag-strip, not a DOM-accurate render — X2 confirmation
 * quotes are expected to be short prose fragments that survive it
 * unchanged, matching how a person would copy the same text out of a
 * browser (gate finding S4: an inline element like `<span>` or `<a>` must
 * NOT insert a space at its boundary — `<a>Bear Trace</a>, <a>Fall
 * Creek</a>` must read as "Bear Trace, Fall Creek", exactly as a browser's
 * own copy-paste would produce; a block element like `<p>`/`<li>`/`<br>`
 * DOES break text, the same as a browser's copy-paste). Also extracts a
 * DRAFT candidate-name list (heading and link text) for `x2-fetch` to print
 * — explicitly never a confirmation; only `x2-verdict`, checking a
 * human-written confirmation file against this same extracted text,
 * confirms anything.
 */
import { decodeHTML } from "entities";

const SCRIPT_STYLE_TAG_NAMES = "script|style|noscript|template";
const SCRIPT_STYLE_CLOSED_RE = new RegExp(
  `<(${SCRIPT_STYLE_TAG_NAMES})\\b[^>]*>[\\s\\S]*?<\\/\\1\\s*>`,
  "gi",
);
// Gate finding N3: an UNCLOSED <script>/<style>/... has no matching close
// tag for SCRIPT_STYLE_CLOSED_RE to remove, so its JS/CSS source leaked into
// "visible" text. Once every properly-closed block is gone, any leftover
// opening tag for one of these names is, by construction, unclosed — drop
// everything from there to the end of the document rather than guess where
// it might have ended.
const UNCLOSED_SCRIPT_STYLE_OPEN_RE = new RegExp(
  `<(?:${SCRIPT_STYLE_TAG_NAMES})\\b[^>]*>`,
  "i",
);
const COMMENT_RE = /<!--[\s\S]*?-->/g;

/** Removes fully-closed `<script>`/`<style>`/`<noscript>`/`<template>`
 * blocks and HTML comments, then drops the tail of any leftover UNCLOSED
 * one of those tags (gate finding N3). Shared by `stripHtmlToText` and
 * `extractDraftCandidateNames` so both see the same "noise-free" input. */
function stripScriptStyleAndComments(html: string): string {
  const withoutClosedBlocks = html
    .replace(SCRIPT_STYLE_CLOSED_RE, " ")
    .replace(COMMENT_RE, " ");
  const unclosed = UNCLOSED_SCRIPT_STYLE_OPEN_RE.exec(withoutClosedBlocks);
  return unclosed ? withoutClosedBlocks.slice(0, unclosed.index) : withoutClosedBlocks;
}

/** Decision 0001 Addendum G's X2 quote-check and `x4-verify`'s name-check
 * both compare "after whitespace collapsing" — every run of whitespace
 * (including newlines/tabs) becomes one space, and the result is trimmed. */
export function collapseWhitespace(input: string): string {
  return input.replace(/\s+/g, " ").trim();
}

/** Decodes HTML entities using the full HTML5 named-entity table (gate
 * finding N4 — the previous hand-rolled table left e.g. `&eacute;`/`&shy;`
 * as literal text, which breaks any accented course name) plus numeric
 * (`&#NNN;`/`&#xHH;`) character references, via the pinned `entities`
 * package. */
export function decodeEntities(input: string): string {
  return decodeHTML(input);
}

/** Gate finding S4: elements that render with NO surrounding whitespace in
 * a browser's own text/copy-paste — their boundary must not become a space,
 * or a verbatim quote copied from the rendered page (e.g. "Bear Trace, Fall
 * Creek" from `<a>Bear Trace</a>, <a>Fall Creek</a>`) fails to match text
 * that has a spurious space inserted at every tag boundary. Everything not
 * in this list (block elements like `p`/`div`/`li`/`br`/headings/table
 * cells, and any unrecognized/custom tag) is treated as a break, the
 * conservative default. */
const INLINE_TAG_NAMES = new Set([
  "a",
  "b",
  "i",
  "em",
  "strong",
  "span",
  "small",
  "sup",
  "sub",
  "abbr",
  "code",
  "mark",
  "u",
  "cite",
  "q",
  "time",
  "kbd",
  "samp",
  "var",
  "bdi",
  "bdo",
  "wbr",
  "ins",
  "del",
  "label",
  "strike",
  "tt",
  "font",
  "data",
  "dfn",
  "acronym",
  "big",
  "nobr",
  "output",
  "ruby",
  "rt",
  "rp",
]);

const TAG_NAME_RE = /^\/?\s*([a-zA-Z][a-zA-Z0-9]*)/;

/** Strips every tag from `html`, replacing an inline element's boundary
 * with nothing and every other element's boundary (block elements, and any
 * unrecognized tag) with a single space. Hand-rolled instead of a single
 * "match a tag" regex so a `>` inside a QUOTED ATTRIBUTE VALUE (gate finding
 * N3, e.g. `alt="a > b"`) is not mistaken for the tag's own end. */
function stripTags(html: string): string {
  let out = "";
  let i = 0;
  const n = html.length;
  while (i < n) {
    const ch = html[i];
    if (ch !== "<") {
      out += ch;
      i += 1;
      continue;
    }
    let j = i + 1;
    let quote: '"' | "'" | null = null;
    while (j < n) {
      const c = html[j];
      if (quote) {
        if (c === quote) quote = null;
      } else if (c === '"' || c === "'") {
        quote = c as '"' | "'";
      } else if (c === ">") {
        break;
      }
      j += 1;
    }
    if (j >= n) {
      // No closing '>' found at all — not a real tag; emit the '<' as text
      // rather than silently discarding the rest of the document.
      out += ch;
      i += 1;
      continue;
    }
    const tagName = TAG_NAME_RE.exec(html.slice(i + 1, j))?.[1]?.toLowerCase() ?? "";
    out += INLINE_TAG_NAMES.has(tagName) ? "" : " ";
    i = j + 1;
  }
  return out;
}

/** HTML → text: strips noise blocks/comments (see above), strips every
 * remaining tag per the inline/block rule (gate S4), decodes entities, and
 * collapses whitespace. */
export function stripHtmlToText(html: string): string {
  const withoutNoise = stripScriptStyleAndComments(html);
  return collapseWhitespace(decodeEntities(stripTags(withoutNoise)));
}

const HEADING_RE = /<h[1-6]\b[^>]*>([\s\S]*?)<\/h[1-6]\s*>/gi;
const LINK_RE = /<a\b[^>]*>([\s\S]*?)<\/a\s*>/gi;
/** A link/heading whose collapsed text is longer than this is almost
 * certainly a whole nested block (e.g. a card with the entire course
 * description inside one `<a>`), not a course name — excluded from the
 * draft candidate list so it doesn't drown out genuine short names. */
const MAX_CANDIDATE_LENGTH = 120;

/**
 * Extracts a DRAFT candidate-name list from heading (`h1`-`h6`) and link
 * (`a`) text — `x2-fetch` prints this clearly labelled DRAFT, never as a
 * confirmation (Addendum G: only a human-written confirmation file, checked
 * by `x2-verdict`, confirms a roster). Deduplicated, order of first
 * appearance preserved.
 */
export function extractDraftCandidateNames(html: string): string[] {
  const withoutNoise = stripScriptStyleAndComments(html);
  const names: string[] = [];
  const seen = new Set<string>();
  const add = (raw: string): void => {
    const text = collapseWhitespace(decodeEntities(stripTags(raw)));
    if (!text || text.length > MAX_CANDIDATE_LENGTH) return;
    if (seen.has(text)) return;
    seen.add(text);
    names.push(text);
  };
  for (const m of withoutNoise.matchAll(HEADING_RE)) add(m[1] ?? "");
  for (const m of withoutNoise.matchAll(LINK_RE)) add(m[1] ?? "");
  return names;
}
