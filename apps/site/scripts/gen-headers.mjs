#!/usr/bin/env node
/**
 * gen-headers.mjs — generates `<dist>/_headers` (the Cloudflare Pages
 * CSP/headers file) from build-time config, so the CSP can allow-list a
 * tile host WITHOUT hand-editing a static file every time
 * `GOLFRAVEN_TILE_STYLE_URL`/`GOLFRAVEN_TILE_HOSTS` change (stage-2 scope
 * item 1: "allow-list its host in the CSP through config").
 * `src/lib/map-config.mjs` derives the SAME host set from the SAME env
 * vars, so the map component and the CSP can never disagree.
 *
 * **Runs POSTBUILD, writes directly into `<dist>/_headers`** (Opus gate
 * nit: "Stop the scripts rewriting tracked `public/_headers`... write to
 * the build output instead"). This is a deliberate move from stage 2's
 * original prebuild-into-`public/` design: Cloudflare Pages reads
 * `_headers`/`_redirects` from the DEPLOYED output (`dist/`, per
 * `wrangler pages deploy dist`, §3.1 row C) — writing there directly means
 * nothing in this repo's own working tree (`public/`) is a build
 * artifact that keeps changing shape run to run. Same position as
 * `verify-sitemap.mjs` in `package.json`'s `build` script — after `astro
 * build`, before `pagefind-index.mjs` (the CSP those rules govern does not
 * depend on Pagefind's own generated files existing yet).
 *
 * **Every directive here, and why:**
 *
 * - `default-src 'self'` — stage-1's baseline, unchanged.
 * - `base-uri 'self'` / `frame-ancestors 'none'` / `object-src 'none'` /
 *   `form-action 'self'` (Opus gate should-fix "CSP") — a static site has
 *   no legitimate use for a `<base>` tag pointing elsewhere, being framed
 *   by another origin, a plugin/object embed, or a form posting off-site;
 *   each is a narrow, standard hardening directive with zero functional
 *   cost here.
 * - `script-src 'self'` (the site-wide default block) — Pagefind's own
 *   WASM search index needs `'wasm-unsafe-eval'` (below), but nothing else
 *   on the site does, so the BLANKET grant from the previous design is
 *   replaced with a path-scoped one.
 * - **`/pagefind/*` gets its OWN `_headers` block, AFTER `/*`, and
 *   DETACHES `Content-Security-Policy` before re-setting it** — corrected
 *   this round (confirmed against Cloudflare's own docs,
 *   https://developers.cloudflare.com/pages/configuration/headers/, and
 *   cloudflare-docs PR #32995): Pages does NOT let a later, more specific
 *   block override an earlier header value. Every MATCHING block's
 *   headers apply, in file order, and a header name repeated across
 *   blocks is JOINED WITH A COMMA rather than replaced — so without the
 *   `! Content-Security-Policy` line below, `/pagefind/*` would have
 *   received BOTH the `/*` block's CSP and its own, comma-joined into one
 *   invalid, doubly-restrictive header (the browser intersects the two
 *   policies, and the `/*` block's policy has no `'wasm-unsafe-eval'`, so
 *   Pagefind's WASM would still be blocked even though this file *looks*
 *   like it grants the keyword). `! Content-Security-Policy` clears
 *   whatever `/*` already contributed for a `/pagefind/*` request BEFORE
 *   this block's own `Content-Security-Policy:` line sets the real,
 *   final value — the "detach" only removes what earlier rules added, so
 *   the file order here (`/*` first, `/pagefind/*` second) is load-
 *   bearing, not cosmetic.
 * - `connect-src 'self'[, <tile hosts>]` / `img-src 'self'[, <tile
 *   hosts>]` — added ONLY when `GOLFRAVEN_TILE_STYLE_URL` is configured,
 *   for the EXACT host set `map-config.mjs`'s `tileConfig()` derives
 *   (the style URL's own host, plus any `GOLFRAVEN_TILE_HOSTS` entries for
 *   a style whose tiles/glyphs/sprites live elsewhere) — MapLibre fetches
 *   all of those via `fetch()` (connect-src) and may load raster tiles as
 *   `Image` (img-src). With no tile host configured, neither directive is
 *   added.
 * - `worker-src` — deliberately NOT added. See `CourseMap.astro`'s module
 *   doc: MapLibre's worker is booted via `setWorkerUrl()` pointing at its
 *   CSP-safe, same-origin worker bundle, which needs nothing beyond
 *   `default-src 'self'` (CSP3: `worker-src` falls back to `default-src`).
 * - `img-src data:` — NOT added. See `src/styles/maplibre-overrides.css`'s
 *   doc: every control icon this site's map actually renders is
 *   self-hosted as a real file instead.
 * - `connect-src <worker host>` / `script-src <turnstile host>` /
 *   `frame-src <turnstile host>` — added ONLY when
 *   `src/config/forms-config.mjs`'s `isFormsConfigured()` is true (build
 *   plan §5.1 "SecureFormScript → the shared Worker with
 *   siteId: 'golfraven'"; this task's scope: "the Worker origin and
 *   Turnstile hosts are allowed only when configured"). With the
 *   `workerUrl`/`turnstileSiteKey` `TODO(owner)` placeholders still in
 *   place (the real, committed default today), NEITHER host is added —
 *   the CSP stays exactly as strict as stage 2's. `SecureFormScript.astro`
 *   itself never renders the Turnstile widget or `fetch()`s the Worker
 *   while unconfigured, so a page can never be ABLE to need a host this
 *   generator didn't allow-list — same defense-in-depth reasoning as
 *   `booking-hosts.ts`'s render-time gate.
 *
 * `X-Content-Type-Options` / `Referrer-Policy` / the `/catalog/v1/*`
 * `X-Robots-Tag` rule are carried over from stage 1 unchanged.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tileConfig } from "../src/lib/map-config.mjs";
import { FORMS_CONFIG, formsWorkerHost, isFormsConfigured, TURNSTILE_HOSTS } from "../src/config/forms-config.mjs";

const here = dirname(fileURLToPath(import.meta.url));

/**
 * `formsConfig` is a parameter (not read from `env`, unlike `tileConfig`)
 * because `FORMS_CONFIG` is a static per-site config module, not an env
 * var — see `forms-config.mjs`'s doc. Defaulting to the real module keeps
 * `buildHeaders(env)` callable exactly as before everywhere it already
 * is; a test can pass a second, override config to exercise the
 * "configured" branch without needing real Worker/Turnstile values.
 */
export function buildHeaders(env = process.env, formsConfig = FORMS_CONFIG) {
  const tiles = tileConfig(env);
  const formsConfigured = isFormsConfigured(formsConfig);
  const workerHost = formsConfigured ? formsWorkerHost(formsConfig) : null;

  const tileHostSrcs = tiles.configured ? tiles.hosts.map((h) => `https://${h}`) : [];
  const turnstileHostSrcs = formsConfigured ? TURNSTILE_HOSTS.map((h) => `https://${h}`) : [];
  const workerHostSrc = workerHost ? `https://${workerHost}` : null;

  const connectSrcHosts = [...tileHostSrcs, ...(workerHostSrc ? [workerHostSrc] : []), ...turnstileHostSrcs];
  const connectSrc = connectSrcHosts.length ? `connect-src 'self' ${connectSrcHosts.join(" ")}` : null;
  const imgSrc = tiles.configured ? `img-src 'self' ${tileHostSrcs.join(" ")}` : null;
  const scriptSrc = turnstileHostSrcs.length
    ? `script-src 'self' ${turnstileHostSrcs.join(" ")}`
    : `script-src 'self'`;
  const frameSrc = turnstileHostSrcs.length ? `frame-src ${turnstileHostSrcs.join(" ")}` : null;

  const baseCsp = [
    `default-src 'self'`,
    scriptSrc,
    `base-uri 'self'`,
    `frame-ancestors 'none'`,
    `object-src 'none'`,
    `form-action 'self'`,
    connectSrc,
    imgSrc,
    frameSrc,
  ]
    .filter(Boolean)
    .join("; ");

  const pagefindCsp = [
    `default-src 'self'`,
    `script-src 'self' 'wasm-unsafe-eval'`,
    `base-uri 'self'`,
    `frame-ancestors 'none'`,
    `object-src 'none'`,
    `form-action 'self'`,
  ].join("; ");

  return (
    `# GENERATED by scripts/gen-headers.mjs — do not hand-edit. Config:\n` +
    `# GOLFRAVEN_TILE_STYLE_URL=${tiles.configured ? tiles.styleUrl : "(unset)"}\n` +
    `# GOLFRAVEN_TILE_HOSTS=${tiles.configured ? tiles.hosts.join(",") : "(unset)"}\n` +
    // Non-secret boolean only — never the Worker URL/Turnstile key
    // themselves, whether real or placeholder.
    `# forms-config.mjs isFormsConfigured()=${formsConfigured}\n` +
    `/*\n` +
    `  Content-Security-Policy: ${baseCsp}\n` +
    `  X-Content-Type-Options: nosniff\n` +
    `  Referrer-Policy: strict-origin-when-cross-origin\n` +
    `\n` +
    `# Pagefind's WASM search index needs 'wasm-unsafe-eval' — scoped to\n` +
    `# ONLY this path, not the site-wide block above (see module doc). The\n` +
    `# "! Content-Security-Policy" line DETACHES the /* block's CSP for a\n` +
    `# /pagefind/* request before this block sets its own — Cloudflare Pages\n` +
    `# joins a repeated header's values across matching blocks with a comma\n` +
    `# rather than overriding, so omitting this line would silently ship\n` +
    `# BOTH policies joined (and Pagefind's WASM blocked either way).\n` +
    `/pagefind/*\n` +
    `  ! Content-Security-Policy\n` +
    `  Content-Security-Policy: ${pagefindCsp}\n` +
    `\n` +
    `/catalog/v1/*\n` +
    `  X-Robots-Tag: noindex\n`
  );
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const distDir = process.env.DIST_DIR ?? process.argv[2] ?? join(here, "..", "dist");
  const outPath = join(distDir, "_headers");
  await mkdir(distDir, { recursive: true });
  const content = buildHeaders();
  await writeFile(outPath, content);
  console.log(`gen-headers: wrote ${outPath}`);
}
