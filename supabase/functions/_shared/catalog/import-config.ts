// supabase/functions/_shared/catalog/import-config.ts
//
// Pure config validation — the "explicit https: allow-list check" task
// instruction: "The catalog fetch URL comes from config (env) with a
// strict https: allow-list check. No hard-coded personal or account
// identifiers." The actual env read (`Deno.env.get(...)`) happens ONLY in
// privileged.ts (tools/service-role-lint's own rule — a non-public key
// may only be read there); this module takes the already-read strings as
// plain arguments so it needs no env access itself and is unit-testable
// with literal fixtures.

export interface ArtifactUrlCheckResult {
  ok: boolean;
  reason?: "not_https" | "host_not_allowed" | "malformed_url" | "url_has_userinfo_port_query_or_fragment";
}

/** `baseUrl` must be `https:` and its hostname must be an EXACT match (no
 * suffix/subdomain wildcarding — a wildcard here would be exactly the
 * kind of "make code work" grant-broadening this repo's own house rules
 * warn against, applied to a URL allow-list instead of a DB grant) for
 * one of `allowedHosts`. Never throws — a malformed URL is reported the
 * same structured way as a scheme/host mismatch, so the caller can log
 * and 500/503 uniformly rather than crash on a bad env value. */
export function checkArtifactBaseUrl(baseUrl: string, allowedHosts: readonly string[]): ArtifactUrlCheckResult {
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch {
    return { ok: false, reason: "malformed_url" };
  }
  if (parsed.protocol !== "https:") return { ok: false, reason: "not_https" };
  // P3e round 2 gate, LOW: reject userinfo, port, query and fragment —
  // a base URL is scheme + exact host + path only. (`https://good@evil`
  // style userinfo tricks, non-default ports and `?`/`#` suffixes that
  // would corrupt the `${base}/manifest.json` join are all refused.)
  if (parsed.username !== "" || parsed.password !== "" || parsed.port !== "" || parsed.search !== "" || parsed.hash !== "" || /[?#]/.test(baseUrl)) {
    return { ok: false, reason: "url_has_userinfo_port_query_or_fragment" };
  }
  if (!allowedHosts.includes(parsed.hostname)) return { ok: false, reason: "host_not_allowed" };
  return { ok: true };
}
