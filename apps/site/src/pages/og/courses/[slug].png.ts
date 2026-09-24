/**
 * og/courses/[slug].png.ts — per-facility OG card endpoint. Adapted from
 * southern-wine-country's `src/pages/og/wineries/[slug].png.ts` @ 572ff7e
 * (build plan §5.1 `wineries/[slug].astro` + OG route → `courses/[slug].astro`,
 * `og/courses/[slug].png.ts`).
 *
 * **Verified pages only** (§5.1) — `getStaticPaths` builds from
 * `verifiedFacilities()`, the exact same set `courses/[slug].astro` itself
 * builds from (S4), so an OG card exists for every course page that
 * exists and for no others.
 *
 * **Demo builds generate NO OG cards at all** (Opus gate should-fix, OG
 * cards) — `getStaticPaths` returns an empty list when `usedDemoData` is
 * true, so nothing is rendered, nothing is written to `.og-store`, and
 * (matching `courses/[slug].astro`'s own `ogImage` guard) no page ever
 * links to a `/og/courses/*.png` URL that wouldn't exist in a demo build
 * anyway.
 */
import type { APIRoute } from "astro";
import { primaryTrailOf } from "@golfraven/catalog";
import type { Facility } from "@golfraven/catalog";
import {
  loadPrimaryTrailOverrides,
  loadSiteCatalog,
  verifiedFacilities,
} from "../../../lib/derive";
import {
  ogContentHash,
  renderCourseCard,
  renderTemplateCard,
} from "../../../lib/og-card";
import {
  readCachedCard,
  storeAvailable,
  writeCachedCard,
} from "../../../lib/og-store";
import { recordRenderTime, shouldRenderFresh } from "../../../lib/og-budget";

export async function getStaticPaths() {
  const { catalog, usedDemoData } = await loadSiteCatalog();
  if (usedDemoData) return [];
  return verifiedFacilities(catalog).map((facility) => ({
    params: { slug: facility.slug },
    props: { facility },
  }));
}

export const GET: APIRoute = async ({ props }) => {
  const facility = (props as { facility: Facility }).facility;
  const { catalog } = await loadSiteCatalog();
  const overrides = await loadPrimaryTrailOverrides();
  const primaryTrail = primaryTrailOf(catalog, facility.id, overrides);
  const holes = facility.courses[0]?.holes;
  const par = facility.courses[0]?.par;

  let buffer: Buffer;
  if (!storeAvailable()) {
    // AT9 (§5.2 "the build never fails on OG volume"): the OG store is
    // unreachable this build (a genuine outage, not just a cold/empty
    // cache) — fall back to the generic per-trail template card rather
    // than failing the build.
    buffer = await renderTemplateCard(primaryTrail);
  } else {
    const hash = ogContentHash(facility, { trail: primaryTrail, holes, par });
    const cached = await readCachedCard(hash);
    if (cached) {
      buffer = cached;
    } else if (!shouldRenderFresh()) {
      // §5.2's REAL automatic fallback: the projected time to render this
      // (and every card queued before it this build) would exceed the
      // remaining budget — ship the template card now; this facility
      // stays un-cached, so the next build with budget left renders and
      // caches it for real ("queued for the next release").
      buffer = await renderTemplateCard(primaryTrail);
    } else {
      const startedAt = performance.now();
      buffer = await renderCourseCard(facility, {
        trail: primaryTrail,
        holes,
        par,
      });
      recordRenderTime(performance.now() - startedAt);
      await writeCachedCard(hash, buffer);
    }
  }

  return new Response(new Uint8Array(buffer), {
    headers: {
      "Content-Type": "image/png",
      "Cache-Control": "public, max-age=31536000, immutable",
    },
  });
};
