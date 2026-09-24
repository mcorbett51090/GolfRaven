/**
 * map-config.mjs — build-time configuration for `CourseMap.astro` (build
 * plan §10 P2 stage-2 scope item 1: "do not hard-code a third-party tile
 * host. Make the tile style URL a build-time config value, and allow-list
 * its host in the CSP through config. With no tile host configured, the
 * map shows the JS-free list and an 'OSM data © OpenStreetMap
 * contributors' attribution.").
 *
 * Plain `.mjs` (not `.ts`) deliberately — same reason as `env.mjs`: it is
 * imported both by Astro/Vite (`CourseMap.astro`) AND by a plain `node`
 * prebuild script (`scripts/gen-headers.mjs`, which cannot load a `.ts`
 * file without a loader). One implementation, read by both, so the CSP's
 * allow-listed host and the map component's own config can never drift
 * apart — see `gen-headers.mjs`'s module doc for the CSP side of this.
 *
 * SWC hard-coded `TILE_STYLE = 'https://tiles.openfreemap.org/styles/positron'`
 * directly in `WineryMap.astro`. GolfRaven reads it from
 * `GOLFRAVEN_TILE_STYLE_URL` instead, so a build with no tile provider
 * configured degrades honestly (list + attribution, no broken/absent map)
 * rather than shipping a third party's URL nobody chose.
 *
 * `GOLFRAVEN_TILE_ATTRIBUTION` optionally overrides the attribution text;
 * it always defaults to the ODbL-required OSM notice, shown even with NO
 * tile host configured — an unverified/unknown facility's map pin (once
 * the OSM join lands) and the base map both draw on OSM data (G-P0-12),
 * so the attribution is owed independent of whether a tile *style* is
 * configured.
 *
 * **`hosts[]` (Opus gate B2/should-fix "CSP" — "an explicit host list from
 * config (style, tiles, glyphs, sprites)")**: a style JSON commonly points
 * its `tiles`/`glyphs`/`sprite` entries at a DIFFERENT host than the style
 * document itself (this build never fetches/parses the style JSON, so it
 * cannot discover those hosts on its own). `GOLFRAVEN_TILE_HOSTS` is an
 * explicit, comma-separated allow-list for exactly those — the style URL's
 * own host is always included automatically; `GOLFRAVEN_TILE_HOSTS` adds
 * any others the chosen style actually references. `gen-headers.mjs`
 * allow-lists this exact set, nothing broader.
 *
 * @typedef {{
 *   configured: boolean,
 *   styleUrl?: string,
 *   hosts: string[],
 *   attribution: string,
 * }} TileConfig
 */

const DEFAULT_ATTRIBUTION = "© OpenStreetMap contributors";

/**
 * Reads and validates `GOLFRAVEN_TILE_STYLE_URL` (+ `GOLFRAVEN_TILE_HOSTS`).
 * An unset/empty `GOLFRAVEN_TILE_STYLE_URL` is the supported "no tile
 * provider yet" state (`configured: false`) — never an error. A SET value
 * that isn't a valid `https:` URL IS an error (a config typo silently
 * degrading to "no map" would be worse than failing the build loudly).
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {TileConfig}
 */
export function tileConfig(env = process.env) {
  const attribution =
    env.GOLFRAVEN_TILE_ATTRIBUTION?.trim() || DEFAULT_ATTRIBUTION;
  const raw = env.GOLFRAVEN_TILE_STYLE_URL?.trim();
  if (!raw) {
    return { configured: false, attribution, hosts: [] };
  }
  /** @type {URL} */
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(
      `GOLFRAVEN_TILE_STYLE_URL is set to "${raw}", which is not a valid URL. ` +
        `Unset it to build with no tile provider (the JS-free list + OSM attribution), ` +
        `or fix the URL.`,
    );
  }
  if (parsed.protocol !== "https:") {
    throw new Error(
      `GOLFRAVEN_TILE_STYLE_URL must be an https: URL (got "${parsed.protocol}"). ` +
        `A map tile style is always fetched cross-origin, so http: is never acceptable.`,
    );
  }

  const extraHosts = (env.GOLFRAVEN_TILE_HOSTS ?? "")
    .split(",")
    .map((h) => h.trim())
    .filter(Boolean);
  for (const h of extraHosts) {
    if (!/^[a-z0-9.-]+(:\d+)?$/i.test(h)) {
      throw new Error(
        `GOLFRAVEN_TILE_HOSTS contains "${h}", which is not a bare host (host[:port] only — ` +
          `no scheme, no path). Example: "tiles.example.com,glyphs.example.com".`,
      );
    }
  }
  const hosts = [...new Set([parsed.host, ...extraHosts])];

  return { configured: true, styleUrl: raw, hosts, attribution };
}

export { DEFAULT_ATTRIBUTION };
