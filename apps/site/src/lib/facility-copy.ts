/**
 * facility-copy.ts — meta composer for `/courses/[slug]`. Rewritten from
 * southern-wine-country's `src/lib/winery-copy.ts` @ 572ff7e (build plan
 * §5.1: "Rewrite | facility-copy.ts | Meta composer ≤ 158 chars; a
 * separate FR composer; no machine translation").
 *
 * Meta is ALWAYS composed from structured signals (trail placement,
 * access, holes) — never a verbatim blurb (SWC's own S1 rule, kept) — so
 * meta stays short, apostrophe-safe and differentiated from on-page prose.
 */
import type { Facility, Trail } from "@golfraven/catalog";

const META_MAX = 158;
const META_MIN = 40;

/** Truncate plain text on a word boundary at ≤ maxLen (default ~158). */
export function truncateAtWord(text: string, maxLen = META_MAX): string {
  const clean = text.replace(/\s+/g, " ").trim();
  if (clean.length <= maxLen) return clean;
  const slice = clean.slice(0, maxLen);
  const sp = slice.lastIndexOf(" ");
  const cut = sp > Math.floor(maxLen * 0.6) ? slice.slice(0, sp) : slice;
  return cut.replace(/[.,;:]\s*$/, "").trimEnd() + "…";
}

/**
 * Compose an EN meta description from available structured signals. Does
 * NOT copy any editorial blurb — on-page prose stays on-page only.
 */
export function facilityMetaDescription(
  facility: Facility,
  opts: { trail?: Trail; holes?: number } = {},
): string {
  const name = facility.name ?? facility.slug;
  const parts: string[] = [];

  parts.push(
    facility.town ? `${name} is a golf facility in ${facility.town}` : `${name} is a golf facility`,
  );

  if (opts.trail) {
    parts.push(`on the ${opts.trail.name}`);
  }

  if (facility.access === "private") {
    parts.push("(private — playable as a member's guest)");
  }

  if (opts.holes) {
    parts.push(`— ${opts.holes} holes`);
  }

  const close =
    facility.access === "private"
      ? "Listed on GolfRaven."
      : facility.url
        ? "See details and book on GolfRaven."
        : "Listed in the GolfRaven directory.";

  const raw = `${parts.join(" ")}. ${close}`;
  return truncateAtWord(raw, META_MAX);
}

/**
 * FR meta description — a SEPARATE composer, never a machine translation of
 * the EN string (build plan §5.5: "there is no machine-translated
 * filler"). Used only where real FR editorial content exists for the
 * facility; the caller decides that (this function does not read a
 * `blurbFr`/`nameFr` presence check itself — see §5.5's "Entity content is
 * FR only when real FR editorial exists").
 */
export function facilityMetaDescriptionFr(
  facility: Facility,
  opts: { trail?: Trail; holes?: number } = {},
): string {
  const name = facility.nameFr ?? facility.name ?? facility.slug;
  const parts: string[] = [];

  parts.push(
    facility.town
      ? `${name} est un parcours de golf à ${facility.town}`
      : `${name} est un parcours de golf`,
  );

  if (opts.trail) {
    const trailName = opts.trail.nameFr ?? opts.trail.name;
    parts.push(`sur le ${trailName}`);
  }

  if (facility.access === "private") {
    parts.push("(privé — accessible en tant qu'invité d'un membre)");
  }

  const close = facility.access === "private" ? "Répertorié sur GolfRaven." : "Voir sur GolfRaven.";

  const raw = `${parts.join(" ")}. ${close}`;
  return truncateAtWord(raw, META_MAX);
}

export { META_MAX, META_MIN };
