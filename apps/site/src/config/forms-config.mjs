/**
 * forms-config.mjs — per-site config for the claim/feedback forms' shared
 * secure-upload Worker (build plan §5.1: "`SecureFormScript` → the shared
 * Worker with `siteId: 'golfraven'`"; §10 P2 scope item "Claim/feedback
 * forms (the verification funnel)").
 *
 * Plain `.mjs` (not `.ts`) deliberately — same reasoning as
 * `map-config.mjs`/`env.mjs`: read by BOTH Astro/Vite
 * (`SecureFormScript.astro`, via the pages that mount it) AND a plain
 * `node` prebuild script (`scripts/gen-headers.mjs`, which cannot load a
 * `.ts` file without a loader), so the CSP's allow-listed Worker/Turnstile
 * hosts and the form's own client config can never drift apart.
 *
 * **Fixed vs. owner-provisioned, per this task's scope:**
 *   - `siteId: "golfraven"` is FIXED — this site's identity in the shared
 *     Worker's `SITES_CONFIG_JSON` was already decided (build plan §5.1).
 *   - `workerUrl` and `turnstileSiteKey` are NOT decidable here.
 *     Provisioning `golfraven` into the shared Worker — adding its entry
 *     to `SITES_CONFIG_JSON`, creating its own Turnstile widget — is an
 *     action against a shared, owner-controlled production resource
 *     (`raven-site-kit/secure-upload`) that this build cannot and must
 *     not take on its own. Both stay grep-able `TODO(owner)` placeholders
 *     until the owner completes the "Per-site adoption runbook" in
 *     `raven-site-kit/secure-upload/README.md`.
 *
 * **While either placeholder remains**, `isFormsConfigured()` returns
 * `false` and:
 *   - `SecureFormScript.astro` renders no Turnstile widget, loads no
 *     Turnstile script, and its submit handler shows a "forms aren't live
 *     yet" message with NO network call (never a broken `fetch()` against
 *     a literal `"TODO(owner)…"` string);
 *   - `scripts/gen-headers.mjs` allow-lists neither the Worker origin nor
 *     the Turnstile hosts in the CSP — the strict default
 *     (`default-src 'self'`, no third-party `connect-src`/`script-src`/
 *     `frame-src`) is unchanged until forms are actually provisioned.
 */

/** Cloudflare Turnstile's own hosts — the widget loader script and its
 * challenge iframe both come from here.
 * `[docs-verified this session via WebSearch against
 * developers.cloudflare.com/turnstile/reference/content-security-policy/
 * and the Cloudflare community threads it links to — the live page itself
 * was unreachable through this session's egress proxy, so this is
 * corroborated via the search snippet + community reports, not a direct
 * fetch of Cloudflare's own doc text]`: Turnstile needs `script-src` (to
 * load `challenges.cloudflare.com/turnstile/v0/api.js`), `frame-src` (the
 * challenge widget itself renders in an iframe from the same host), and
 * `connect-src` (the widget's own network calls, made from inside that
 * iframe's origin, not this page's).
 */
export const TURNSTILE_HOSTS = ["challenges.cloudflare.com"];

/**
 * TODO(owner): complete `raven-site-kit/secure-upload`'s "Per-site
 * adoption runbook" (its README.md) for `golfraven`, then replace the two
 * `TODO(owner)` values below with the real ones. Nothing else in this
 * file, or in any form page, needs to change once these three values are
 * real.
 */
export const FORMS_CONFIG = {
  // TODO(owner): the shared secure-upload Worker's deployed URL, no
  // trailing slash — e.g. "https://raven-secure-upload.matt-769.workers.dev"
  // (the SAME Worker southern-wine-country and corbett-claims already use;
  // see raven-site-kit/secure-upload/README.md). Add golfraven's entry to
  // that Worker's SITES_CONFIG_JSON first (README.md step 1 of the
  // "Per-site adoption runbook").
  workerUrl: "TODO(owner): raven-site-kit secure-upload Worker URL",
  // Fixed — golfraven's siteId in the shared Worker's SITES_CONFIG_JSON
  // (build plan §5.1).
  siteId: "golfraven",
  // TODO(owner): golfraven's PUBLIC Turnstile site key — safe to ship to
  // the browser (the SECRET half goes only in the Worker's
  // SITE_SECRETS_JSON, never here, never in this repo). Create
  // golfraven's own Turnstile widget per the runbook's step 2.
  turnstileSiteKey: "TODO(owner): golfraven Turnstile site key",
};

/** True for an empty value or one still carrying the literal
 * `TODO(owner)` marker — fails closed: anything that isn't obviously a
 * real value is treated as unset, never the reverse. */
export function isPlaceholderValue(value) {
  return !value || /^TODO\(owner\)/i.test(String(value));
}

/** True only once every one of `workerUrl` / `siteId` / `turnstileSiteKey`
 * is a real (non-placeholder) value. */
export function isFormsConfigured(config = FORMS_CONFIG) {
  return (
    !isPlaceholderValue(config?.workerUrl) &&
    !isPlaceholderValue(config?.siteId) &&
    !isPlaceholderValue(config?.turnstileSiteKey)
  );
}

/** The Worker's own host, for the CSP `connect-src` allow-list. `null`
 * while unconfigured (never derives a host from a placeholder string) or
 * when `workerUrl` isn't a valid absolute URL. */
export function formsWorkerHost(config = FORMS_CONFIG) {
  if (!isFormsConfigured(config)) return null;
  try {
    return new URL(config.workerUrl).host;
  } catch {
    return null;
  }
}
