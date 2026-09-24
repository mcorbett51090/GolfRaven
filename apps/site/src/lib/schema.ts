/**
 * schema.ts — JSON-LD builders. Adapted from southern-wine-country's
 * `src/lib/schema.ts` @ 572ff7e (build plan §5.1: "Adapt | same | `@type`
 * `GolfCourse` [unverified — training knowledge; check on schema.org in
 * P2]; `addressCountry` from `Region.country` (removes the hard-coded
 * 'US', `swc-analysis.md §9.1`); `GeoCoordinates` only when `approx ===
 * false`").
 *
 * Each PAGE passes its own `@graph` nodes to `BaseLayout`; a page that
 * passes none emits no schema at all. `jsonLdScript()` escapes `<` so a
 * literal `</script>` in any value can't close the tag early, and it is
 * the ONLY place in this app that uses `set:html` (AT(7)).
 */
import type { Facility } from "@golfraven/catalog";

/** Deployment origin+base as a stable IRI root (no trailing slash). */
export function siteOrigin(astroSite: URL | undefined, base: string): string {
  const root = new URL(base, astroSite ?? "https://www.golfraven.example").href;
  return root.replace(/\/$/, "");
}

export const coursePageUrl = (origin: string, slug: string): string =>
  `${origin}/courses/${slug}/`;
export const trailUrl = (origin: string, slug: string): string =>
  `${origin}/trails/${slug}/`;
export const regionUrl = (origin: string, country: string, regionSlug: string): string =>
  `${origin}/${country.toLowerCase()}/${regionSlug}/`;

/** C2-equivalent gate: precise `GeoCoordinates` ONLY for verified
 * (non-approx) coordinates (§5.1: "`GeoCoordinates` only when `approx ===
 * false`"). */
function geoOf(f: Facility) {
  return f.approx === false && f.lat !== undefined && f.lng !== undefined
    ? { geo: { "@type": "GeoCoordinates", latitude: f.lat, longitude: f.lng } }
    : {};
}

/** `[unverified — training knowledge; check on schema.org in P2]` (§5.1).
 * `GolfCourse` is a schema.org type (a subtype of `SportsActivityLocation`
 * / `LocalBusiness`); until that is confirmed against schema.org directly,
 * `LocalBusiness` is always included alongside it so a consumer that
 * doesn't recognise `GolfCourse` still gets a valid, useful type. */
export function facilitySchemaTypes(): string[] {
  return ["GolfCourse", "LocalBusiness"];
}

/**
 * PostalAddress with locality + region always (when known).
 * `addressCountry` comes from the facility's region code, never
 * hard-coded (§5.1: "removes the hard-coded 'US'", `swc-analysis.md
 * §9.1`) — a `RegionCode` is always `<country>-<subdivision>`
 * (`packages/catalog`'s `RegionCodeSchema`), so the country is its prefix.
 */
export function postalAddressOf(f: Facility) {
  const country = f.region.split("-")[0];
  return {
    "@type": "PostalAddress",
    ...(f.town ? { addressLocality: f.town } : {}),
    addressRegion: f.region,
    addressCountry: country,
  };
}

/** BreadcrumbList from an ordered [{name,url}] trail. */
export function breadcrumbNode(crumbs: { name: string; url: string }[]) {
  return {
    "@type": "BreadcrumbList",
    itemListElement: crumbs.map((c, i) => ({
      "@type": "ListItem",
      position: i + 1,
      name: c.name,
      item: c.url,
    })),
  };
}

/** A facility as a ListItem→node, for a region/trail directory's `ItemList`. */
function facilityItem(origin: string, f: Facility, position: number) {
  return {
    "@type": "ListItem",
    position,
    item: {
      "@type": facilitySchemaTypes(),
      "@id": `${coursePageUrl(origin, f.slug)}#facility`,
      name: f.name ?? f.slug,
      url: coursePageUrl(origin, f.slug),
      address: postalAddressOf(f),
      ...geoOf(f),
    },
  };
}

/** `CollectionPage` + `ItemList` of a facility list (a trail or region
 * directory page). */
export function collectionNode(
  origin: string,
  name: string,
  description: string,
  list: Facility[],
  url: string,
) {
  return {
    "@type": "CollectionPage",
    "@id": url,
    name,
    description,
    url,
    mainEntity: {
      "@type": "ItemList",
      numberOfItems: list.length,
      itemListElement: list.map((f, i) => facilityItem(origin, f, i + 1)),
    },
  };
}

/** The course detail page's main entity (`GolfCourse`/`LocalBusiness`). */
export function facilityPageNode(origin: string, f: Facility) {
  const page = coursePageUrl(origin, f.slug);
  return {
    "@type": facilitySchemaTypes(),
    "@id": `${page}#facility`,
    name: f.name ?? f.slug,
    url: f.url ?? page,
    mainEntityOfPage: page,
    address: postalAddressOf(f),
    ...geoOf(f),
  };
}

/**
 * Serialize nodes to one `<script type="application/ld+json">` string.
 * Escapes `<` so a literal `</script>` in any value can't close the tag
 * early. AT(7): the ONLY `set:html` use in this app is `BaseLayout`
 * rendering this function's output.
 */
export function jsonLdScript(nodes: object[]): string {
  const graph = { "@context": "https://schema.org", "@graph": nodes };
  const json = JSON.stringify(graph).split("<").join("\\u003c");
  return `<script type="application/ld+json">${json}</script>`;
}
