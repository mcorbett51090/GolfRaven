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
 * REFUSES the placeholder.
 */

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
  const loopback = url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1");
  if (url.protocol !== "https:" && !(opts.allowLoopback && loopback)) {
    throw new Error("GOLFRAVEN_PARTNERS_API_BASE must be an https URL (a loopback http URL is accepted only for the e2e build)");
  }
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    throw new Error("GOLFRAVEN_PARTNERS_API_BASE must carry no credentials, query or fragment");
  }
  const base = `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
  const isPlaceholder = url.hostname.endsWith(".example");
  if (opts.production && isPlaceholder) {
    throw new Error("a production build refuses the placeholder API host: set GOLFRAVEN_PARTNERS_API_BASE (owner question Q1)");
  }
  return { base, origin: url.origin, isPlaceholder };
}
