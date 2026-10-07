// @ts-check
/**
 * Build-time configuration of `apps/partners`: where the partners API lives.
 *
 * `GOLFRAVEN_PARTNERS_API_BASE` is the FUNCTIONS ROOT, e.g. `https://<project>.supabase.co/functions/v1`: the client calls
 * `<base>/partner-session/<route>` (and, in later slices, `<base>/partner-attest/...`). The origin of that URL is what the page's CSP
 * `connect-src` allows, and it must be exactly the origin the server's `GR_PARTNER_ORIGIN` does NOT name: `GR_PARTNER_ORIGIN` is the origin of THIS
 * PAGE (the one origin the API's CORS answers), while the API origin here is where the page sends requests.
 *
 * The default is a placeholder on the reserved `.example` TLD. The real host is the owner's open question Q1 (the partners domain and the API host
 * are not decided), so a default that resolves to a real host would be a decision nobody made. A production build (`GOLFRAVEN_ENV=production`)
 * REFUSES the placeholder (in any spelling: case, a trailing dot), and refuses a loopback, `localhost` or bare-IP host (a bundle that can only
 * reach the build machine). It also refuses the e2e loopback allowance outright: the e2e switch must never reach a production build.
 */

/** The host without a trailing dot (`golfraven.example.` is the same name as `golfraven.example`), lower-case. */
function normalHost(/** @type {string} */ hostname) {
  return hostname.toLowerCase().replace(/\.+$/, "");
}

/** `.example` (and `example` itself) are reserved: a placeholder, whatever the spelling. @param {string} hostname */
export function isPlaceholderHost(hostname) {
  const h = normalHost(hostname);
  return h === "example" || h.endsWith(".example");
}

/** A host that only means something on the build machine: `localhost`, `*.localhost`, loopback, or any IP literal (`URL` already normalises 0x7f.1 and 2130706433 to dotted form). @param {string} hostname */
export function isLocalOrIpHost(hostname) {
  const h = normalHost(hostname);
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h.startsWith("[")) return true; // an IPv6 literal
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h);
}

export const DEFAULT_API_BASE = "https://partners-api.golfraven.example/functions/v1";

/**
 * @param {string | undefined} raw
 * @param {{ allowLoopback?: boolean, production?: boolean }} [opts] `allowLoopback`: accept `http://localhost` (the Playwright suite only).
 * @returns {{ base: string, origin: string, isPlaceholder: boolean }}
 */
export function resolveApiBase(raw, opts = {}) {
  const value = raw === undefined || raw === "" ? DEFAULT_API_BASE : raw;
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`GOLFRAVEN_PARTNERS_API_BASE is not a URL: ${JSON.stringify(value)}`);
  }
  if (opts.production && opts.allowLoopback) throw new Error("the e2e loopback allowance (GOLFRAVEN_PARTNERS_E2E) cannot be combined with a production build");
  const loopback = url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1");
  if (url.protocol !== "https:" && !(opts.allowLoopback && loopback)) {
    throw new Error("GOLFRAVEN_PARTNERS_API_BASE must be an https URL (a loopback http URL is accepted only for the e2e build)");
  }
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    throw new Error("GOLFRAVEN_PARTNERS_API_BASE must carry no credentials, query or fragment");
  }
  const path = url.pathname.replace(/\/+$/, "");
  // the path becomes part of CSP `connect-src` sources, so it is a closed shape: nothing that could end a source or a directive
  if (!/^(?:\/[A-Za-z0-9._~-]+)*$/.test(path)) throw new Error("GOLFRAVEN_PARTNERS_API_BASE has a path with characters outside [A-Za-z0-9._~-] (it becomes part of the CSP)");
  const base = `${url.origin}${path}`;
  const isPlaceholder = isPlaceholderHost(url.hostname);
  if (opts.production && isPlaceholder) {
    throw new Error("a production build refuses the placeholder API host: set GOLFRAVEN_PARTNERS_API_BASE (owner question Q1)");
  }
  if (opts.production && isLocalOrIpHost(url.hostname)) {
    throw new Error("a production build refuses a localhost, loopback or bare-IP API host: set GOLFRAVEN_PARTNERS_API_BASE to the real functions root");
  }
  return { base, origin: url.origin, isPlaceholder };
}
