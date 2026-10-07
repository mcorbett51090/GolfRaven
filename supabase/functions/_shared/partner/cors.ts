// supabase/functions/_shared/partner/cors.ts
//
// The partner lane's CORS and Origin policy (docs/security/partner-auth-design.md 4.6, PA-10). Pure: no environment, no database, no clock, no logging.
//
// ONE allowed origin, an exact string (no wildcard, no list, no suffix match), supplied by the caller. Where it comes from is decided in `privileged.ts#loadPartnerCorsOrigin` (the environment
// variable GR_PARTNER_ORIGIN): `OPTIONS` must never open a database connection (PA-10), so the origin cannot be read from `app.partner_rp_config` for a preflight. The sign-in handler
// compares the environment value with `partner_rp_config.origin` on every database path and refuses with a 503 when they differ, so the two cannot drift apart silently (S1.2 departure D2).
//
//   * a request with NO `Origin` header (a non-browser client) is let through: no ambient credential exists for a cross-site page to abuse, and no CORS header is added;
//   * a request whose `Origin` is anything but the allowed one is refused 403 by THE SERVER, for every method, before routing, whatever the browser does with CORS: this is what stops a
//     "simple" cross-site request (a form POST, a `text/plain` fetch) that never preflights;
//   * the allowed origin gets `Access-Control-Allow-Origin: <that origin>`, `Vary: Origin`, no credentials mode (the token is a header, never a cookie), and `Access-Control-Allow-Methods`
//     for GET, POST, PATCH and DELETE (plus OPTIONS). Any other origin gets NO CORS header;
//   * the allowed origin's responses also carry `Access-Control-Expose-Headers: Retry-After` and nothing else: a cross-origin page can read only the CORS-safelisted response headers unless
//     the server names more, and `Retry-After` (a 429) is the one non-safelisted header the partner lane sends that the page needs (S7a finding, design doc 20.6).

/** The methods a preflight advertises (4.6: "GET, POST, PATCH, DELETE, OPTIONS"). */
export const PARTNER_ALLOWED_METHODS = "GET, POST, PATCH, DELETE, OPTIONS";
/** `x-gr-pop` is the reserved proof-of-possession header (N7): advertised so a future client can send it, ignored by every server today. */
export const PARTNER_ALLOWED_HEADERS = "authorization, content-type, x-gr-pop";
/** A short preflight cache (seconds): a changed origin or method list is picked up within ten minutes. */
export const PARTNER_PREFLIGHT_MAX_AGE_SECONDS = 600;
/** The ONE response header a cross-origin page may read beyond the CORS-safelisted ones: `Retry-After` on a 429. Exposing more would hand the page headers it has no use for. */
export const PARTNER_EXPOSED_HEADERS = "Retry-After";

export type OriginDecision =
  /** No `Origin` header at all. */
  | { kind: "none" }
  /** The one allowed origin. */
  | { kind: "allowed"; origin: string }
  /** Any other `Origin`, or no origin is configured: the server refuses (403). */
  | { kind: "refused" };

/**
 * Decides what to do about a request's `Origin`. `allowedOrigin` is the one exact origin (or null when none is configured, which fails closed: every request that CARRIES an Origin is refused).
 * Comparison is exact string equality: `https://partners.example.test/` (trailing slash), a different case, a port, another scheme, `null` and a comma-joined list (two Origin headers) all differ.
 */
export function decideOrigin(headers: Headers, allowedOrigin: string | null): OriginDecision {
  const origin = headers.get("origin");
  if (origin === null) return { kind: "none" };
  if (allowedOrigin !== null && origin === allowedOrigin) return { kind: "allowed", origin };
  return { kind: "refused" };
}

/** The headers every partner response carries: never cacheable, varying by Origin, no sniffing; plus the CORS headers when the origin was the allowed one. Never a credentials header. */
export function baseHeaders(decision: OriginDecision): Headers {
  const h = new Headers();
  h.set("cache-control", "no-store");
  h.set("vary", "Origin");
  h.set("x-content-type-options", "nosniff");
  if (decision.kind === "allowed") {
    h.set("access-control-allow-origin", decision.origin);
    h.set("access-control-expose-headers", PARTNER_EXPOSED_HEADERS);
  }
  return h;
}

/** The answer to an `OPTIONS` preflight from the allowed origin (or from no origin): 204, the method and header lists, a short max-age. It is built without touching any other module. */
export function preflightResponse(decision: OriginDecision): Response {
  const h = baseHeaders(decision);
  if (decision.kind === "allowed") {
    h.set("access-control-allow-methods", PARTNER_ALLOWED_METHODS);
    h.set("access-control-allow-headers", PARTNER_ALLOWED_HEADERS);
    h.set("access-control-max-age", String(PARTNER_PREFLIGHT_MAX_AGE_SECONDS));
  }
  return new Response(null, { status: 204, headers: h });
}

/**
 * Validates the configured origin: an exact `https` origin (scheme, host, optional port; no path, no query, no trailing slash, no credentials) whose serialisation is itself. Returns the
 * origin, or throws: a malformed configuration must stop the function at boot rather than run with an origin nobody meant.
 */
export function parseAllowedOrigin(value: string | null | undefined): string | null {
  if (value === null || value === undefined || value === "") return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("the partner origin is not a URL");
  }
  if (url.protocol !== "https:" || url.origin !== value) throw new Error("the partner origin must be an exact https origin (no path, no trailing slash)");
  return value;
}
