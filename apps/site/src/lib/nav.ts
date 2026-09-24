/**
 * nav.ts — base-aware link helper (copied from southern-wine-country's
 * `src/lib/nav.ts` @ 572ff7e, build plan §5.1: "Copy | same"). Every
 * internal href goes through withBase() so the site works identically
 * whatever BASE it is deployed at.
 */
const BASE = import.meta.env.BASE_URL; // e.g. '/'

/** Prefix an app-absolute path with the deployment base, collapsing double slashes. */
export function withBase(path: string): string {
  const p = path.startsWith("/") ? path.slice(1) : path;
  return `${BASE}${p}`.replace(/\/{2,}/g, "/");
}
