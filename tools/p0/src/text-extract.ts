/**
 * Minimal, dependency-free HTML→text extraction for X2 evidence (decision
 * 0001 Addendum G: "HTML → text with tags stripped and whitespace
 * collapsed"). No HTML-parsing library is added as a dependency — the same
 * "do not pretend" spirit that governs `x2-fetch`'s PDF handling (store the
 * bytes, mark extraction "manual" rather than fake a parse) applies here:
 * this is a conservative tag-strip, not a DOM-accurate render, and X2
 * confirmation quotes are expected to be short prose fragments that survive
 * it untouched. Also extracts a DRAFT candidate-name list (heading and link
 * text) for `x2-fetch` to print — explicitly never a confirmation; only
 * `x2-verdict`, checking a human-written confirmation file against this
 * same extracted text, confirms anything.
 */

const SCRIPT_STYLE_RE =
  /<(script|style|noscript|template)\b[^>]*>[\s\S]*?<\/\1\s*>/gi;
const COMMENT_RE = /<!--[\s\S]*?-->/g;
const TAG_RE = /<[^>]*>/g;

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: " ",
  mdash: "—",
  ndash: "–",
  rsquo: "’",
  lsquo: "‘",
  rdquo: "”",
  ldquo: "“",
  hellip: "…",
};

const ENTITY_RE = /&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z][a-zA-Z0-9]*);/g;

/** Decodes the small, common set of HTML entities above plus numeric
 * (`&#NNN;`) and hex (`&#xHH;`) character references. An unrecognized named
 * entity is left as-is (e.g. `&somethingobscure;`) rather than guessed at —
 * consistent with this module's "conservative, not DOM-accurate" scope. */
export function decodeEntities(input: string): string {
  return input.replace(ENTITY_RE, (whole, body: string) => {
    if (body.startsWith("#x") || body.startsWith("#X")) {
      const codePoint = parseInt(body.slice(2), 16);
      if (Number.isNaN(codePoint)) return whole;
      try {
        return String.fromCodePoint(codePoint);
      } catch {
        return whole;
      }
    }
    if (body.startsWith("#")) {
      const codePoint = parseInt(body.slice(1), 10);
      if (Number.isNaN(codePoint)) return whole;
      try {
        return String.fromCodePoint(codePoint);
      } catch {
        return whole;
      }
    }
    return NAMED_ENTITIES[body] ?? whole;
  });
}

/** Decision 0001 Addendum G's X2 quote-check and `x4-verify`'s name-check
 * both compare "after whitespace collapsing" — every run of whitespace
 * (including newlines/tabs) becomes one space, and the result is trimmed. */
export function collapseWhitespace(input: string): string {
  return input.replace(/\s+/g, " ").trim();
}

/** HTML → text: strips `<script>`/`<style>`/`<noscript>`/`<template>`
 * blocks and HTML comments entirely (their content is never prose), strips
 * every remaining tag, decodes entities, and collapses whitespace. */
export function stripHtmlToText(html: string): string {
  const withoutNoise = html
    .replace(SCRIPT_STYLE_RE, " ")
    .replace(COMMENT_RE, " ");
  const withoutTags = withoutNoise.replace(TAG_RE, " ");
  return collapseWhitespace(decodeEntities(withoutTags));
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
  const withoutNoise = html
    .replace(SCRIPT_STYLE_RE, " ")
    .replace(COMMENT_RE, " ");
  const names: string[] = [];
  const seen = new Set<string>();
  const add = (raw: string): void => {
    const text = collapseWhitespace(decodeEntities(raw.replace(TAG_RE, " ")));
    if (!text || text.length > MAX_CANDIDATE_LENGTH) return;
    if (seen.has(text)) return;
    seen.add(text);
    names.push(text);
  };
  for (const m of withoutNoise.matchAll(HEADING_RE)) add(m[1] ?? "");
  for (const m of withoutNoise.matchAll(LINK_RE)) add(m[1] ?? "");
  return names;
}
