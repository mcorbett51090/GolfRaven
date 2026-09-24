/**
 * `GOLFRAVEN_ENV` normalisation — shared by `derive.ts` (via Vite/Astro)
 * AND the plain-`node` prebuild scripts (`scripts/verify-input.mjs`,
 * `scripts/emit-indexability.mjs`), which is why this is plain `.mjs`
 * rather than `.ts`: a script run directly by `node` cannot load a `.ts`
 * file without a loader, but any of them can import a `.mjs` module
 * (including one that lives under `src/lib/`) with no extra tooling.
 *
 * Case-normalised and validated against a closed set — an unrecognised
 * value (a typo, `Production` vs `production`, …) is a build-time error,
 * never silently treated as "not production" (which would be the
 * dangerous direction to fail in for the demo-data guard, B3).
 */
export const GOLFRAVEN_ENV_VALUES = ["development", "staging", "production"];

/** Normalises `raw` (typically `process.env.GOLFRAVEN_ENV`) to lowercase
 * and validates it against `GOLFRAVEN_ENV_VALUES`. Unset/empty stays
 * `undefined` (no environment declared — never an error by itself).
 * Throws on anything else that doesn't match, case-insensitively. */
export function normalizeGolfravenEnv(raw) {
  if (raw === undefined || raw === null || raw === "") return undefined;
  const normalized = String(raw).trim().toLowerCase();
  if (!GOLFRAVEN_ENV_VALUES.includes(normalized)) {
    throw new Error(
      `Unknown GOLFRAVEN_ENV value "${raw}" — must be one of: ${GOLFRAVEN_ENV_VALUES.join(", ")} (case-insensitive).`,
    );
  }
  return normalized;
}

/** True when `env.GOLFRAVEN_ENV` normalises to `"production"`. Throws (via
 * `normalizeGolfravenEnv`) on an unrecognised value rather than treating
 * it as non-production. */
export function isProductionEnv(env) {
  return normalizeGolfravenEnv(env.GOLFRAVEN_ENV) === "production";
}
