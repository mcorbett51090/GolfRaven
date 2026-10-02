/**
 * Minimal semver comparison for `minAppVersion` (build plan §3.5). Accepts
 * exactly the shape the manifest schema allows (`SemverSchema` in
 * `tools/catalog/src/manifest-core.ts`): MAJOR.MINOR.PATCH, optional
 * `-prerelease`, optional `+build`. Build metadata is ignored, a
 * pre-release sorts below its release, and pre-release identifiers compare
 * per semver 2.0.0 §11.
 */
const RE =
  /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

interface Parsed {
  core: [number, number, number];
  pre: string[];
}

export function parseSemver(v: string): Parsed | null {
  const m = RE.exec(v);
  if (!m) return null;
  return {
    core: [Number(m[1]), Number(m[2]), Number(m[3])],
    pre: m[4] ? m[4].split(".") : [],
  };
}

function cmpIdent(a: string, b: string): number {
  const an = /^\d+$/.test(a);
  const bn = /^\d+$/.test(b);
  if (an && bn) return Math.sign(Number(a) - Number(b));
  if (an) return -1; // numeric identifiers sort below alphanumeric
  if (bn) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

/** -1 / 0 / 1. Returns `null` if either input is not a valid semver. */
export function compareSemver(a: string, b: string): -1 | 0 | 1 | null {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) return null;
  for (let i = 0; i < 3; i += 1) {
    const d = pa.core[i]! - pb.core[i]!;
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  if (pa.pre.length === 0 && pb.pre.length === 0) return 0;
  if (pa.pre.length === 0) return 1;
  if (pb.pre.length === 0) return -1;
  const n = Math.max(pa.pre.length, pb.pre.length);
  for (let i = 0; i < n; i += 1) {
    const x = pa.pre[i];
    const y = pb.pre[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const c = cmpIdent(x, y);
    if (c !== 0) return c < 0 ? -1 : 1;
  }
  return 0;
}

/** True when `appVersion` is BELOW `minAppVersion` — the force-update
 * condition. An unparseable app version is treated as below (fail closed). */
export function isBelowMinAppVersion(appVersion: string, minAppVersion: string): boolean {
  const c = compareSemver(appVersion, minAppVersion);
  return c === null ? true : c < 0;
}
