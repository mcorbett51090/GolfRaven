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
