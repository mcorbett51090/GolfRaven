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
 */
import type { APIRoute } from "astro";
import { primaryTrailOf } from "@golfraven/catalog";
import type { Facility } from "@golfraven/catalog";
import { loadPrimaryTrailOverrides, loadSiteCatalog, verifiedFacilities } from "../../../lib/derive";
import { ogContentHash, renderCourseCard, renderTemplateCard } from "../../../lib/og-card";
import { readCachedCard, storeAvailable, writeCachedCard } from "../../../lib/og-store";

export async function getStaticPaths() {
  const { catalog } = await loadSiteCatalog();
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
    // unreachable this build — fall back to the generic per-trail
    // template card rather than failing the build.
    buffer = await renderTemplateCard(primaryTrail);
  } else {
    const hash = ogContentHash(facility, { trail: primaryTrail, holes, par });
    const cached = await readCachedCard(hash);
    if (cached) {
      buffer = cached;
    } else {
      buffer = await renderCourseCard(facility, { trail: primaryTrail, holes, par });
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
