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
 * **Nit (re-gate): an explicit `"synthetic"` field, not `_comment`
 * sniffing.** Regex-matching free-text prose (`_comment`) for a marker
 * word is fragile — a rewritten comment that no longer happens to say
 * "SYNTHETIC" or "TEST-ONLY" (deliberately or by accident) would silently
 * defeat this guard with no change to the data the guard actually cares
 * about. `config/booking-hosts.json` now carries a real, structural
 * `"synthetic": true | false` field instead, and this function is
 * FAIL-CLOSED on it: production refuses unless the field is present AND
 * is the literal boolean `false` — missing, `null`, a string `"false"`,
 * or any other shape all refuse, exactly as `true` does. (This is a
 * deliberately stricter contract than the old regex ever was: the old
 * code would have happily accepted a `_comment` that simply forgot to
 * mention "synthetic" at all.)
 *
 * Plain `.mjs` (not `.ts`) deliberately — read by BOTH
 * `src/lib/booking-hosts.ts` (Astro/Vite) and `scripts/verify-input.mjs`
 * (plain `node`, which cannot load a `.ts` file without a loader) — same
 * reasoning as `env.mjs`/`map-config.mjs`.
 */
import { isProductionEnv } from "./env.mjs";

/**
 * @param {unknown} raw the parsed contents of config/booking-hosts.json
 * @param {NodeJS.ProcessEnv} [env]
 */
export function assertBookingHostsNotSynthetic(raw, env = process.env) {
  if (!isProductionEnv(env)) return;
  const synthetic = /** @type {{ synthetic?: unknown }} */ (raw)?.synthetic;
  if (synthetic !== false) {
    const shape =
      synthetic === undefined
        ? "the field is missing entirely"
        : `it is ${JSON.stringify(synthetic)}, not the boolean false`;
    throw new Error(
      `GOLFRAVEN_ENV=production refuses to build against config/booking-hosts.json: its ` +
        `"synthetic" field must be the literal boolean \`false\` before a production build will ` +
        `trust it, and ${shape}. The real allow-list waits on X4/X6 (build plan §10 P1, decision ` +
        "0003 S2's carve-out) — set \"synthetic\": false only once the file's hosts[] is the real, " +
        "verified allow-list, never as a way to silence this check early.",
    );
  }
}
