// @ts-check
/**
 * The Content Security Policy of `apps/partners` and the `_headers` file that carries it (docs/security/partner-auth-design.md 4.6).
 *
 * Emitted TWICE from one function: as the `Content-Security-Policy` response header (`dist/_headers`, the way apps/site does it) and as a
 * `<meta http-equiv>` in `index.html`, so a static host that ignores `_headers` still serves the page under the policy. `frame-ancestors` is
 * ignored in a meta element (and logs a console error), so the meta form leaves it out; the header form has it.
 *
 *   default-src 'none'            nothing is allowed unless a directive below names it
 *   script-src 'self'             our own bundle only: no inline script, no eval, no third-party origin
 *   style-src 'self'              an external stylesheet only: no `<style>`, no `style=""` attribute
 *   img-src 'self' <storage>      the favicon, plus short-lived Supabase Storage signed URLs for receipt review previews (§51):
 *                                 `${origin}/storage/v1/` derived from the same API host as connect-src (path-scoped prefix; no `data:` / `blob:`).
 *   connect-src <fn URL prefixes> one source PER PARTNER FUNCTION, scoped by path: `https://<host>/functions/v1/partner-session/` (a source whose path
 *                                 ends in `/` matches every URL under that prefix; CSP3 "path-part match"). Not the whole API origin: the same
 *                                 host serves /rest/v1 (PostgREST) and every other edge function, and this page may reach none of them (design 4.6).
 *                                 Not even 'self': the page fetches nothing from its own origin. The list is src/api/partner-functions.json, the
 *                                 same one the client's `call()` allow-list uses.
 *   manifest-src 'self'           the web app manifest
 *   worker-src 'none'             S7a ships no service worker (README: why)
 *   object-src 'none', base-uri 'none', form-action 'none', frame-ancestors 'none'
 *   require-trusted-types-for 'script' + trusted-types 'none'
 *                                 every DOM string sink (innerHTML, script.src, eval, ...) must receive a TrustedType, and no policy may be created,
 *                                 so none can: the code uses `textContent` only. Chromium enforces this today; Safari's support is [unverified]
 *                                 and an unsupporting browser simply ignores both directives.
 *
 * Departures from the design's section 4.6 list, all STRICTER: `connect-src` drops 'self'; `img-src` drops `data:` (Storage host added for §51); `worker-src` is 'none', not 'self'.
 */

import { readFileSync } from "node:fs";

/** The partner functions the page may call: one `connect-src` entry each, and the client's bearer allow-list. @type {readonly string[]} */
export const PARTNER_FUNCTIONS = JSON.parse(readFileSync(new URL("../../src/api/partner-functions.json", import.meta.url), "utf8"));

/**
 * The `connect-src` sources: `<origin><functions-root path>/<function>/` for each partner function (the trailing slash makes it a prefix match).
 *
 * @param {string} apiBase the functions root, e.g. `https://<host>/functions/v1`
 * @param {readonly string[]} [functions]
 * @returns {string[]}
 */
export function connectSources(apiBase, functions = PARTNER_FUNCTIONS) {
  const url = new URL(apiBase);
  const root = url.pathname.replace(/\/+$/, "");
  return functions.map((fn) => `${url.origin}${root}/${fn}/`);
}

/**
 * Path-scoped Storage host for receipt preview `<img>` (signed URLs under `/storage/v1/...` on the same origin as the functions root).
 *
 * @param {string} apiBase
 * @returns {string}
 */
export function storageImgSource(apiBase) {
  return `${new URL(apiBase).origin}/storage/v1/`;
}

/**
 * @param {string} apiBase the functions root the page may connect to (`https://<host>/functions/v1`); only the partner functions under it are allowed
 * @param {{ meta?: boolean, functions?: readonly string[] }} [opts]
 */
export function buildCsp(apiBase, opts = {}) {
  const directives = [
    `default-src 'none'`,
    `script-src 'self'`,
    `style-src 'self'`,
    `img-src 'self' ${storageImgSource(apiBase)}`,
    `connect-src ${connectSources(apiBase, opts.functions).join(" ")}`,
    `manifest-src 'self'`,
    `worker-src 'none'`,
    `object-src 'none'`,
    `base-uri 'none'`,
    `form-action 'none'`,
    ...(opts.meta ? [] : [`frame-ancestors 'none'`]),
    `require-trusted-types-for 'script'`,
    `trusted-types 'none'`,
  ];
  return directives.join("; ");
}

/**
 * The generated `_headers` file (Cloudflare Pages syntax, as apps/site). One `/*` block carries the security headers; the hashed assets add a long cache
 * lifetime in their own block (no header name is repeated across blocks: Pages joins repeated names with a comma instead of replacing them).
 *
 * `/`, `/index.html` and `/invite` (the page itself; `/invite#<token>` is the link an invite carries, served the same page by the host's single-page fallback) are `no-store`, so a back/forward navigation never serves the signed-in page from the HTTP cache or, in
 * Chromium, from the back/forward cache (a page whose main resource is no-store is not bfcache-eligible there). The hashed `/assets/*` stay immutable.
 * They are separate blocks from `/assets/*` and match disjoint paths, so no request gets two `Cache-Control` values.
 *
 * Permissions-Policy: `camera=(self)` from S7b (the attest / course-QR / redeem screens). The shop-floor scan field calls `getUserMedia` on the
 * same origin; paste remains the fallback when BarcodeDetector or the camera is unavailable.
 *
 * @param {string} apiBase the functions root (see buildCsp)
 */
export function buildHeadersFile(apiBase) {
  return (
    `# GENERATED by scripts/build.mjs - do not hand-edit.\n` +
    `/*\n` +
    `  Content-Security-Policy: ${buildCsp(apiBase)}\n` +
    `  Strict-Transport-Security: max-age=31536000; includeSubDomains\n` +
    `  X-Content-Type-Options: nosniff\n` +
    `  Referrer-Policy: no-referrer\n` +
    `  Permissions-Policy: publickey-credentials-get=(self), publickey-credentials-create=(self), camera=(self), microphone=(), geolocation=(), payment=(), usb=()\n` +
    `  Cross-Origin-Opener-Policy: same-origin\n` +
    `  Cross-Origin-Resource-Policy: same-origin\n` +
    `  X-Robots-Tag: noindex, nofollow\n` +
    `\n` +
    `/\n` +
    `  Cache-Control: no-store\n` +
    `\n` +
    `/index.html\n` +
    `  Cache-Control: no-store\n` +
    `\n` +
    `/invite\n` +
    `  Cache-Control: no-store\n` +
    `\n` +
    `/assets/*\n` +
    `  Cache-Control: public, max-age=31536000, immutable\n`
  );
}
