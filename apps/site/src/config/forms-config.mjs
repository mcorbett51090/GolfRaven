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
 *   - `workerUrl` / `turnstileSiteKey` / `contactEmail` are NOT decidable
 *     here. Provisioning `golfraven` into the shared Worker — adding its
 *     entry to `SITES_CONFIG_JSON`, creating its own Turnstile widget —
 *     is an action against a shared, owner-controlled production
 *     resource (`raven-site-kit/secure-upload`) that this build cannot
 *     and must not take on its own.
 *
 * **Two ways the owner can set the two real values (`workerUrl`,
 * `turnstileSiteKey`) — both land in the SAME `FORMS_CONFIG`, read by
 * everything below:**
 *   1. **Env vars at build time** — `GOLFRAVEN_FORMS_WORKER_URL` /
 *      `GOLFRAVEN_FORMS_TURNSTILE_SITE_KEY` (+ optional
 *      `GOLFRAVEN_FORMS_CONTACT_EMAIL`), e.g. set in the Cloudflare Pages
 *      build's environment variables. This is the path a REAL deployment
 *      is expected to use — no source edit, no redeploy of this repo
 *      needed to rotate a key. It's also how this repo's OWN test suite
 *      exercises the "configured" state end-to-end
 *      (`test/paths.mjs`'s `configured` build) without ever hand-editing
 *      this file.
 *   2. **Hand-editing the two `TODO(owner)` literals below** — replacing
 *      them permanently. Either path is fine; env vars simply win when
 *      both are present (see `readEnvOr` below), so a placeholder literal
 *      never has to be touched for a build/preview that just wants to set
 *      env vars temporarily.
 *
 * **While `workerUrl`/`siteId`/`turnstileSiteKey` isn't a complete, VALID
 * set** (S1, gate review: `isFormsConfigured()` now also requires
 * `isValidWorkerUrl(workerUrl)` — real `https:`, no userinfo, no
 * non-default port, a plain `[a-z0-9.-]+` hostname, no wildcard),
 * `isFormsConfigured()` returns `false` and:
 *   - `SecureFormScript.astro` renders no Turnstile widget, loads no
 *     Turnstile script, keeps its fieldset `disabled` (B1, gate review),
 *     and its submit handler shows a "forms aren't live yet" message with
 *     NO network call (never a broken/misdirected `fetch()`);
 *   - `scripts/gen-headers.mjs` allow-lists neither the Worker origin nor
 *     the Turnstile hosts in the CSP — the strict default
 *     (`default-src 'self'`, no third-party `connect-src`/`script-src`/
 *     `frame-src`) is unchanged until forms are actually provisioned.
 *
 * **`assertValidFormsConfig()` runs eagerly at the bottom of this file**
 * (S1: "If a value is non-placeholder but invalid, throw at build time"):
 * a `workerUrl` that is SET (not a placeholder) but doesn't parse as a
 * valid Worker URL fails the build immediately, the first time anything
 * imports this module — never silently reaching a page, a `fetch()`
 * call, or the CSP generator with a malformed value.
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

/** Reads `env[key]`, trims it, and returns it if non-empty — otherwise
 * `fallback`. Centralises the "env var wins over the literal default"
 * rule so every field below applies it identically. */
function readEnvOr(env, key, fallback) {
  const raw = env?.[key];
  const trimmed = typeof raw === "string" ? raw.trim() : "";
  return trimmed || fallback;
}

/**
 * `typeof process !== "undefined"` — NOT a bare `process.env` reference —
 * because this module is also bundled into the BROWSER (the client
 * script below imports `isPlaceholderValue`/`isValidWorkerUrl` from it,
 * pulling in the whole module including this top-level default). `typeof`
 * on an undeclared identifier never throws; a direct `process.env` access
 * would throw `ReferenceError: process is not defined` in that bundle and
 * break every page's client-side JS. In the browser this resolves to
 * `{}`, which is harmless: the client script never reads `FORMS_CONFIG`
 * itself, only the pure functions below, applied to values already read
 * from the DOM (`form.dataset.*`) — see SecureFormScript.astro.
 */
const DEFAULT_ENV = typeof process !== "undefined" && process.env ? process.env : {};

/**
 * Builds `FORMS_CONFIG` from `env` (defaults to `process.env`). A named
 * function (not just the top-level `FORMS_CONFIG` object) so tests can
 * construct an independent config from arbitrary env vars without any
 * process-global mutation or module-cache trickery.
 *
 * TODO(owner): set `GOLFRAVEN_FORMS_WORKER_URL` and
 * `GOLFRAVEN_FORMS_TURNSTILE_SITE_KEY` (e.g. in the Cloudflare Pages
 * build's environment variables), OR hand-edit the two `TODO(owner)`
 * string literals below permanently — either is fine, see this file's
 * module doc. Complete `raven-site-kit/secure-upload`'s "Per-site
 * adoption runbook" (its README.md) for `golfraven` first. Nothing else
 * in this file, or in any form page, needs to change once those two
 * values are real.
 */
export function buildFormsConfig(env = DEFAULT_ENV) {
  return {
    workerUrl: readEnvOr(
      env,
      "GOLFRAVEN_FORMS_WORKER_URL",
      // TODO(owner): the shared secure-upload Worker's deployed URL, no
      // trailing slash — e.g. "https://raven-secure-upload.example.workers.dev"
      // (the SAME Worker southern-wine-country and example-site already
      // use; see raven-site-kit/secure-upload/README.md — do not copy
      // their real URLs here, ask the owner for golfraven's own). Add
      // golfraven's entry to that Worker's SITES_CONFIG_JSON first
      // (README.md step 1 of the "Per-site adoption runbook").
      "TODO(owner): raven-site-kit secure-upload Worker URL",
    ),
    // Fixed — golfraven's siteId in the shared Worker's SITES_CONFIG_JSON
    // (build plan §5.1). Not env-overridable: this is an identity, not a
    // secret or a per-environment value.
    siteId: "golfraven",
    turnstileSiteKey: readEnvOr(
      env,
      "GOLFRAVEN_FORMS_TURNSTILE_SITE_KEY",
      // TODO(owner): golfraven's PUBLIC Turnstile site key — safe to ship
      // to the browser (the SECRET half goes only in the Worker's
      // SITE_SECRETS_JSON, never here, never in this repo). Create
      // golfraven's own Turnstile widget per the runbook's step 2.
      "TODO(owner): golfraven Turnstile site key",
    ),
    // TODO(owner): a PUBLIC contact address for GolfRaven, if/when you
    // want one published on the site (the claim/feedback forms' "email
    // us instead" fallback text and mailto link). Deliberately left EMPTY
    // rather than defaulting to anyone's personal address — publishing a
    // personal email on a public site/repo is the owner's call, never
    // this build's default. While empty, every form page renders NO
    // mailto link and NO email text anywhere; the fallback copy reads
    // "please check back soon" / "please try again later" instead
    // (English and French). This is READ INDEPENDENTLY of
    // isFormsConfigured() below — the forms can go live
    // (workerUrl/turnstileSiteKey provisioned) with this still empty, and
    // vice versa.
    contactEmail: readEnvOr(env, "GOLFRAVEN_FORMS_CONTACT_EMAIL", ""),
  };
}

export const FORMS_CONFIG = buildFormsConfig();

/** True for an empty value or one still carrying the literal
 * `TODO(owner)` marker — fails closed: anything that isn't obviously a
 * real value is treated as unset, never the reverse. */
export function isPlaceholderValue(value) {
  return !value || /^TODO\(owner\)/i.test(String(value));
}

/**
 * S1 (gate review): "Configured" only if `url` parses as protocol
 * `https:`, with no username or password, no (non-default) port, and a
 * hostname matching `^[a-z0-9.-]+$` (no wildcard, no injected
 * characters). Never throws — returns `false` for anything unparseable,
 * including a scheme-less value like `"raven-secure-upload.workers.dev"`
 * (which `new URL()` rejects outright rather than silently treating as
 * relative — the exact case this check exists to catch before it ever
 * reaches a `fetch()` call, where a scheme-less string WOULD resolve
 * relative to the current page's own origin instead of failing loudly).
 */
export function isValidWorkerUrl(url) {
  if (typeof url !== "string" || !url) return false;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:") return false;
  if (parsed.username || parsed.password) return false;
  // A URL's own `.port` is empty for the scheme's default port (443 for
  // https:) — WHATWG URL parsing normalises that away — so this only
  // rejects an EXPLICIT non-default port, exactly as intended.
  if (parsed.port) return false;
  if (!/^[a-z0-9.-]+$/.test(parsed.hostname)) return false;
  return true;
}

/**
 * S1 (gate review): "If a value is non-placeholder but invalid, throw at
 * build time." A placeholder `workerUrl` (still unset) is fine — that's
 * the ordinary "not provisioned yet" state. A `workerUrl` that is SET but
 * fails `isValidWorkerUrl()` is a config MISTAKE, not an unset value, and
 * fails the build loudly rather than silently shipping a broken/
 * dangerous fetch target.
 */
export function assertValidFormsConfig(config = FORMS_CONFIG) {
  if (!isPlaceholderValue(config?.workerUrl) && !isValidWorkerUrl(config.workerUrl)) {
    throw new Error(
      `forms-config.mjs: workerUrl "${config.workerUrl}" is not a valid Worker URL — it must be an ` +
        "https: URL with no username/password, no non-default port, and a hostname matching " +
        '/^[a-z0-9.-]+$/ (no wildcard, no injected characters). Fix GOLFRAVEN_FORMS_WORKER_URL (or ' +
        "the literal in forms-config.mjs), or leave it as the TODO(owner) placeholder until it's ready.",
    );
  }
}

/** True only once every one of `workerUrl` / `siteId` / `turnstileSiteKey`
 * is a real (non-placeholder) value AND `workerUrl` is a genuinely valid
 * Worker URL (S1) — never `contactEmail`, which is independent (see this
 * file's module doc). */
export function isFormsConfigured(config = FORMS_CONFIG) {
  return (
    !isPlaceholderValue(config?.workerUrl) &&
    isValidWorkerUrl(config?.workerUrl) &&
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

// Eager, build-time check against the REAL, committed/env-derived config
// — a build/test run that ever imports this module with an invalid
// non-placeholder workerUrl fails immediately, not silently later inside
// a fetch() call or a generated CSP.
assertValidFormsConfig(FORMS_CONFIG);
