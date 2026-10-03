import { base64UrlToBytes, utf8DecodeStrict } from "./catalog/bytes";

/**
 * The pure half of the app configuration (no Expo imports, so it is
 * unit-testable under Node). `config.ts` adds the environment reads.
 */

/** `https://host[:port][/path]` only — a plain `http:` catalog is never
 * acceptable outside local development (and even then the signature, not the
 * transport, is what is trusted). `null` for anything else. */
export function parseCatalogBaseUrl(raw: string | undefined | null, opts: { allowLocalHttp?: boolean } = {}): string | null {
  if (!raw) return null;
  const v = raw.trim().replace(/\/+$/, "");
  const https = /^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?(\/[A-Za-z0-9._~/-]*)?$/;
  const localHttp = /^http:\/\/(localhost|127\.0\.0\.1|10\.0\.2\.2)(:\d{1,5})?(\/[A-Za-z0-9._~/-]*)?$/;
  if (https.test(v)) return v;
  if (opts.allowLocalHttp && localHttp.test(v)) return v;
  return null;
}

/** The contract MAJOR this build reads (`CONTRACT_VERSION` in
 * `@golfraven/catalog`; pinned equal by `test/wallet-config.test.ts`). The M-freeze
 * (build plan §10 P1) moves it to 1 — and moving it is a deliberate edit
 * here, which is the point. */
export const SUPPORTED_CONTRACT_MAJOR = 0;

/** `https:` only. */
export function parseStoreUrl(raw: string | undefined | null): string | null {
  return raw && /^https:\/\/[^\s]+$/.test(raw) ? raw : null;
}

/** Where the Edge Functions are served from: the project's Functions root, e.g. `https://<ref>.supabase.co/functions/v1`. The client appends
 * `/<function-name>` (`me-signin-methods`, `me-delete`, ...). Same rule as the catalog URL: `https://` only, `http://` only to a local host
 * in a development build. `null` for anything else (no network API; see `runtime/backend.ts`). */
export function parseApiBaseUrl(raw: string | undefined | null, opts: { allowLocalHttp?: boolean } = {}): string | null {
  return parseCatalogBaseUrl(raw, opts);
}

/** The Supabase project URL (Auth lives at `<url>/auth/v1`): an origin only, `https://` (local `http://` in development). */
export function parseSupabaseUrl(raw: string | undefined | null, opts: { allowLocalHttp?: boolean } = {}): string | null {
  const v = parseCatalogBaseUrl(raw, opts);
  return v !== null && /^https?:\/\/[^/]+$/.test(v) ? v : null;
}

function jwtRole(token: string): string | null {
  const parts = token.split(".");
  const payload = parts[1];
  if (parts.length !== 3 || !payload || !/^[A-Za-z0-9_-]+$/.test(payload)) return null;
  try {
    const role = (JSON.parse(utf8DecodeStrict(base64UrlToBytes(payload))) as { role?: unknown }).role;
    return typeof role === "string" ? role : null;
  } catch {
    return null;
  }
}

/** The PUBLIC Supabase key (the "anon" or "publishable" key; it is meant to ship in clients and RLS is what protects the data).
 * Defence in depth against pasting the wrong one into a public env var: a legacy JWT key must carry `role: "anon"` (a `service_role` JWT, or
 * any JWT whose role cannot be read, is refused), a `sb_publishable_…` key is accepted and an `sb_secret_…` key is refused. Whitespace, empty
 * and anything else is refused too. `null` = not usable. */
export function parseSupabaseAnonKey(raw: string | undefined | null): string | null {
  if (!raw) return null;
  const v = raw.trim();
  if (v.length < 20 || v.length > 2048 || /\s/.test(v)) return null;
  if (v.startsWith("sb_secret_")) return null;
  if (v.startsWith("sb_publishable_")) return /^sb_publishable_[A-Za-z0-9_-]+$/.test(v) ? v : null;
  return jwtRole(v) === "anon" ? v : null;
}
