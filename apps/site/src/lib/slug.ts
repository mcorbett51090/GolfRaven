/**
 * slug.ts — the ONE canonical slug function (ported from
 * southern-wine-country's `src/lib/slug.ts` @ 572ff7e, build plan §5.1:
 * "Copy | same | One slug function"), used by BOTH `getStaticPaths`
 * generation AND URL-param / link lookup, so a generated route and every
 * link to it can never disagree.
 *
 * `packages/catalog`'s facility/trail/course slugs are authored (or minted
 * by `mintSlug`, `packages/catalog/src/ledger.ts`) — this helper is for the
 * one thing the catalog layer does NOT slugify: a `Region`'s URL segment
 * (`/us/<region-slug>/`), derived here the same way SWC derived a state
 * slug.
 */
export function slugify(input: string): string {
  return input
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "") // strip diacritics
    .toLowerCase()
    .replace(/&/g, " and ") // ampersand -> 'and' (never silently dropped)
    .replace(/['’`]/g, "") // apostrophes removed, no hyphen
    .replace(/[^a-z0-9]+/g, "-") // any run of non-alphanumerics -> single hyphen
    .replace(/^-+|-+$/g, ""); // trim leading/trailing hyphens
}
