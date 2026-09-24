/**
 * og-card.ts — per-course Open Graph share image (1200×630 PNG), adapted
 * from southern-wine-country's `src/lib/og-card.ts` @ 572ff7e (build plan
 * §5.1: "Adapt | same | New tokens; chips for access · holes · par;
 * accent from the primary trail. OG images for verified pages only.").
 *
 * Same stack SWC used, satori (layout → SVG, text as vector paths, no
 * fonts needed at raster time) + sharp (SVG → PNG) — pinned to the SAME
 * resolved versions SWC's own lockfile carries (`satori@0.28.0`,
 * `sharp@0.33.5`), per this repo's pinning rule.
 *
 * **Honest by design, same as SWC's own rule**: a directory of REAL golf
 * courses never ships a fabricated AI "photo" of one — every card is a
 * branded TYPE card (name · place · trail accent · access/holes/par
 * chips), never imagery of the business itself.
 *
 * **OG images for VERIFIED pages only** (§5.1) — enforced by the caller
 * (`src/pages/og/courses/[slug].png.ts`'s `getStaticPaths`, which builds
 * its path list from `verifiedFacilities()`, the exact same set
 * `courses/[slug].astro` itself builds from), not by this module, which
 * only renders whatever `Facility` it is given.
 *
 * **OSM attribution** (stage-2 scope item 2's third bullet) — every card
 * this module renders, course or template, carries a small
 * "© OpenStreetMap contributors" line: the base map data behind the
 * facility's location (even where this flat card draws no map graphic)
 * is ODbL-licensed, and the ODbL layer-split rule (build plan §4.1) is
 * "Attribution ... appears on ... OG cards".
 */
import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import satori from "satori";
import sharp from "sharp";
import type { Facility, Trail } from "@golfraven/catalog";

const require = createRequire(import.meta.url);
const fontDir = (pkg: string) => join(dirname(require.resolve(`${pkg}/package.json`)), "files");
const PT = fontDir("@fontsource/pt-serif");
const CIN = fontDir("@fontsource/cinzel");
const read = (dir: string, file: string) => readFileSync(join(dir, file));

const fonts = [
  { name: "PT Serif", data: read(PT, "pt-serif-latin-400-normal.woff"), weight: 400 as const, style: "normal" as const },
  { name: "PT Serif", data: read(PT, "pt-serif-latin-700-normal.woff"), weight: 700 as const, style: "normal" as const },
  { name: "Cinzel", data: read(CIN, "cinzel-latin-700-normal.woff"), weight: 700 as const, style: "normal" as const },
];

// New GolfRaven tokens (§5.1: "New tokens") — distinct from SWC's
// wine-country cream/gold/wine palette. A deep fairway green replaces the
// wine tone; gold stays as the accent metal, matching BaseLayout's
// `theme-color` (`#1f4d3a`).
const GREEN = "#1f4d3a";
const GOLD = "#c9a227";
const INK = "#182420";
const INK_SOFT = "#4b5b52";
const CREAM = "#f4f1e6";

const ACCESS_LABEL: Record<string, string> = {
  public: "Public",
  "semi-private": "Semi-private",
  resort: "Resort",
  municipal: "Municipal",
  private: "Private",
};

// A simple golf-flag mark (own geometry, not the wine cluster mark it
// replaces) — no imagery of any real course, matching the "honest by
// design" rule above.
const markSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64"><circle cx="32" cy="54" r="4" fill="${GOLD}"/><rect x="30.5" y="10" width="3" height="44" rx="1.2" fill="${GOLD}"/><path d="M33.5 12 L54 20 L33.5 28 Z" fill="${GREEN}" stroke="${GOLD}" stroke-width="1.4" stroke-linejoin="round"/></svg>`;
const MARK = `data:image/svg+xml;utf8,${encodeURIComponent(markSvg)}`;

type El = { type: string; props: Record<string, unknown> };
const h = (type: string, style: Record<string, unknown>, ...children: unknown[]): El => ({
  type,
  props: { style, children: children.length <= 1 ? children[0] : children },
});

/**
 * A deterministic accent colour derived from the trail's id (§5.1: "accent
 * from the primary trail"). GolfRaven has no per-trail colour REGISTRY yet
 * (unlike SWC's `geo.ts` `trailColors`, which is a hand-curated map over
 * ~30 named wine trails) — that is out of stage-2 scope. A stable hash → hue
 * gives every trail its own fixed, reproducible accent today without one,
 * and can be swapped for a curated registry later without changing this
 * function's signature.
 */
export function accentForTrail(trailId: string): string {
  const hash = createHash("sha256").update(trailId).digest();
  const hue = hash.readUInt16BE(0) % 360;
  return `hsl(${hue}, 42%, 32%)`;
}

function nameSize(name: string): number {
  const n = name.length;
  if (n <= 18) return 84;
  if (n <= 30) return 74;
  if (n <= 44) return 62;
  return 52;
}

function courseCardTree(facility: Facility, opts: { trail?: Trail; holes?: number; par?: number }): El {
  const name = facility.name ?? facility.slug;
  const accent = opts.trail ? accentForTrail(opts.trail.id) : GREEN;
  const chips: El[] = [];
  if (facility.access) {
    chips.push(
      h(
        "div",
        { display: "flex", alignItems: "center", padding: "7px 18px", borderRadius: 999, border: `1px solid ${GOLD}`, color: INK_SOFT, fontSize: 25 },
        ACCESS_LABEL[facility.access] ?? facility.access,
      ),
    );
  }
  if (opts.holes) {
    chips.push(
      h(
        "div",
        { display: "flex", alignItems: "center", padding: "7px 18px", borderRadius: 999, background: "rgba(31,77,58,0.08)", color: GREEN, fontSize: 25 },
        `${opts.holes} holes`,
      ),
    );
  }
  if (opts.par) {
    chips.push(
      h(
        "div",
        { display: "flex", alignItems: "center", padding: "7px 18px", borderRadius: 999, background: "rgba(31,77,58,0.08)", color: GREEN, fontSize: 25 },
        `Par ${opts.par}`,
      ),
    );
  }

  return h(
    "div",
    { display: "flex", width: "100%", height: "100%", background: `linear-gradient(155deg, ${CREAM}, #e9e3d2)`, fontFamily: "PT Serif", position: "relative" },
    h("div", { position: "absolute", top: 40, left: 40, right: 40, bottom: 40, border: `2px solid ${GOLD}`, borderRadius: 18 }),
    h("div", { position: "absolute", top: 40, left: 40, bottom: 40, width: 12, background: accent, borderTopLeftRadius: 18, borderBottomLeftRadius: 18 }),
    h(
      "div",
      { display: "flex", flexDirection: "column", justifyContent: "space-between", width: "100%", height: "100%", padding: "82px 92px" },
      h(
        "div",
        { display: "flex", alignItems: "center", gap: 18 },
        { type: "img", props: { src: MARK, width: 46, height: 46, style: { width: 46, height: 46 } } },
        h("div", { fontFamily: "Cinzel", fontWeight: 700, fontSize: 26, letterSpacing: 6, color: GREEN }, "GOLFRAVEN"),
      ),
      h(
        "div",
        { display: "flex", flexDirection: "column" },
        opts.trail
          ? h("div", { display: "flex", fontStyle: "italic", fontSize: 27, color: accent, marginBottom: 14 }, `On the ${opts.trail.name}`)
          : h("div", { display: "flex" }),
        h("div", { display: "flex", fontWeight: 700, fontSize: nameSize(name), lineHeight: 1.04, color: INK, maxWidth: 940 }, name),
        facility.town
          ? h("div", { display: "flex", fontSize: 32, color: INK_SOFT, marginTop: 20 }, `${facility.town}, ${facility.region}`)
          : h("div", { display: "flex", fontSize: 32, color: INK_SOFT, marginTop: 20 }, facility.region),
      ),
      h(
        "div",
        { display: "flex", flexDirection: "column", gap: 10 },
        h("div", { display: "flex", gap: 14 }, ...chips),
        h("div", { display: "flex", fontSize: 16, color: INK_SOFT, opacity: 0.8 }, "Map data © OpenStreetMap contributors"),
      ),
    ),
  );
}

/**
 * The template (per-trail, generic) card — §5.2's automatic fallback:
 * "cards beyond the budget ship with the per-trail template card". Also
 * what `og/courses/[slug].png.ts` renders whenever the OG store is
 * unreachable (AT9: "a simulated empty OG store completes by falling back
 * to template cards instead of failing").
 */
function templateCardTree(trail?: Trail): El {
  const accent = trail ? accentForTrail(trail.id) : GREEN;
  return h(
    "div",
    { display: "flex", width: "100%", height: "100%", background: `linear-gradient(155deg, ${CREAM}, #e9e3d2)`, fontFamily: "PT Serif", position: "relative" },
    h("div", { position: "absolute", top: 40, left: 40, right: 40, bottom: 40, border: `2px solid ${GOLD}`, borderRadius: 18 }),
    h("div", { position: "absolute", top: 40, left: 40, bottom: 40, width: 12, background: accent, borderTopLeftRadius: 18, borderBottomLeftRadius: 18 }),
    h(
      "div",
      { display: "flex", flexDirection: "column", justifyContent: "space-between", width: "100%", height: "100%", padding: "82px 92px" },
      h(
        "div",
        { display: "flex", alignItems: "center", gap: 18 },
        { type: "img", props: { src: MARK, width: 46, height: 46, style: { width: 46, height: 46 } } },
        h("div", { fontFamily: "Cinzel", fontWeight: 700, fontSize: 26, letterSpacing: 6, color: GREEN }, "GOLFRAVEN"),
      ),
      h(
        "div",
        { display: "flex", flexDirection: "column" },
        h(
          "div",
          { display: "flex", fontWeight: 700, fontSize: nameSize(trail?.name ?? "GolfRaven"), lineHeight: 1.1, color: INK, maxWidth: 940 },
          trail?.name ?? "Golf trails, course by course",
        ),
        h("div", { display: "flex", fontSize: 32, color: INK_SOFT, marginTop: 20 }, "See this course on GolfRaven"),
      ),
      h("div", { display: "flex", fontSize: 16, color: INK_SOFT, opacity: 0.8 }, "Map data © OpenStreetMap contributors"),
    ),
  );
}

async function rasterize(tree: El): Promise<Buffer> {
  const svg = await satori(tree as unknown as Parameters<typeof satori>[0], { width: 1200, height: 630, fonts });
  return sharp(Buffer.from(svg)).png({ palette: true, compressionLevel: 9 }).toBuffer();
}

/** Render a facility's full OG card to a PNG buffer (1200×630). */
export async function renderCourseCard(
  facility: Facility,
  opts: { trail?: Trail; holes?: number; par?: number } = {},
): Promise<Buffer> {
  return rasterize(courseCardTree(facility, opts));
}

/** Render the generic per-trail fallback card (§5.2, AT9). */
export async function renderTemplateCard(trail?: Trail): Promise<Buffer> {
  return rasterize(templateCardTree(trail));
}

/**
 * The R2 object-store key (§5.2: "OG PNGs are stored in an object store
 * ... keyed by content hash ... A build fetches existing cards and renders
 * only cards whose hash is missing"). Every rendered field is folded into
 * the hash so a content edit (new blurb, new trail placement, a holes
 * count correction) naturally mints a NEW key rather than silently
 * serving a stale cached PNG under the old one.
 */
export function ogContentHash(facility: Facility, opts: { trail?: Trail; holes?: number; par?: number } = {}): string {
  const basis = JSON.stringify({
    slug: facility.slug,
    name: facility.name,
    town: facility.town,
    region: facility.region,
    access: facility.access,
    trailId: opts.trail?.id ?? null,
    trailName: opts.trail?.name ?? null,
    holes: opts.holes ?? null,
    par: opts.par ?? null,
  });
  return createHash("sha256").update(basis).digest("hex").slice(0, 24);
}
