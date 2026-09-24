/**
 * booking-hosts-guard.mjs — should-fix (Opus gate, Booking): "A production
 * build refuses while `config/booking-hosts.json` carries the SYNTHETIC/
 * TEST marker."
 *
 * `config/booking-hosts.json`'s own `_comment` says plainly: "SYNTHETIC /
 * TEST ONLY (P1a). The real booking-host allow-list waits on X4/X6 ...
 * none should be treated as [a real booking provider's production host
 * list]." A `GOLFRAVEN_ENV=production` build trusting that file to decide
 * which booking links are safe to publish would be trusting a file that
 * says, in its own text, not to be trusted for that yet — this is the
 * same fail-closed shape as `derive.ts`'s demo-data guard (B3), applied
 * to a different file.
 *
 * Plain `.mjs` (not `.ts`) deliberately — read by BOTH
 * `src/lib/booking-hosts.ts` (Astro/Vite) and `scripts/verify-input.mjs`
 * (plain `node`, which cannot load a `.ts` file without a loader) — same
 * reasoning as `env.mjs`/`map-config.mjs`.
 */
import { isProductionEnv } from "./env.mjs";

const SYNTHETIC_MARKER_RE = /SYNTHETIC|TEST[\s-]ONLY/i;

/**
 * @param {unknown} raw the parsed contents of config/booking-hosts.json
 * @param {NodeJS.ProcessEnv} [env]
 */
export function assertBookingHostsNotSynthetic(raw, env = process.env) {
  if (!isProductionEnv(env)) return;
  const comment = JSON.stringify(/** @type {{ _comment?: unknown }} */ (raw)?._comment ?? "");
  if (SYNTHETIC_MARKER_RE.test(comment)) {
    throw new Error(
      "GOLFRAVEN_ENV=production refuses to build against config/booking-hosts.json while its own " +
        "_comment still carries the SYNTHETIC/TEST-ONLY marker — the real allow-list waits on X4/X6 " +
        "(build plan §10 P1, decision 0003 S2's carve-out). Replace the file's real contents (and " +
        "that marker) before a production deploy ever ships a booking link built from it.",
    );
  }
}
