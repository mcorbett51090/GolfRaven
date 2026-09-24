/**
 * Adapts an `ImportedRound` into `@golfraven/matching`'s `matchRoute()`
 * input (build plan §7.4). This package never calls `matchRoute` itself —
 * candidate courses come from the device's catalog cache, which this
 * package has no access to (same boundary `@golfraven/matching` itself
 * draws around `@golfraven/catalog` — see that package's `types.ts`).
 */
import type { CandidateCourse, MatchRouteInput, RouteFix } from "@golfraven/matching";
import type { ImportedRound } from "./types.js";

export interface ToMatcherInputOptions {
  /** Candidates within the search radius, already projected into
   * `@golfraven/matching`'s `CandidateCourse` shape. */
  candidates: CandidateCourse[];
  catalogVersion?: string;
  candidateRadiusMeters?: number;
  insideRatioBufferMeters?: number;
  maxSimplifiedPoints?: number;
  tieThreshold?: number;
  acceptInsideRatio?: number;
}

/**
 * Builds `matchRoute`'s input from an imported round. Returns `undefined`
 * when the round has no fixes (`round.fixes.length === 0`) — there is no
 * route to match (`matchRoute` itself throws on an empty fix list), and a
 * routeless import scores as `file_import` 0.10 / `local_date` only
 * (build plan §4.5, A2-17), never as a `matchRoute()` candidate.
 *
 * A file-imported fix's `simulated` flag is left **unset**, deliberately
 * — it is never asserted `false`. `@golfraven/matching`'s `RouteFix.
 * simulated` models a live-location mock-provider signal (iOS
 * `isSimulatedBySoftware` / Android's mock-location flag); a file
 * someone chose to import isn't a live capture at all, so this package
 * genuinely doesn't know whether the *original* device's GPS was
 * mocked at capture time, and asserting `false` would overclaim that it
 * checked. `matchRoute` still treats an omitted `simulated` as `false`
 * for its own scoring math (this doesn't change matching's *behavior*),
 * but the *contract* this package hands off never claims to have
 * verified non-simulation — matching's foreground check-in path
 * (`matchCheckIn`) specifically requires `simulated === false` to ever
 * accept a fix as a co-signal, and a file-imported fix should never be
 * mistakable for that kind of live-verified evidence downstream. It
 * carries no attestation either, so it's never a co-signal regardless —
 * `@golfraven/rules` (out of scope here) is what actually withholds
 * money scoring from `file_import` (build plan §4.5: "Files are
 * editable; badge-only").
 */
export function toMatcherInput(round: ImportedRound, options: ToMatcherInputOptions): MatchRouteInput | undefined {
  if (round.fixes.length === 0) return undefined;

  const fixes: RouteFix[] = round.fixes.map((f) => ({
    point: { lat: f.lat, lon: f.lon },
    timestamp: f.timestamp,
    ...(f.accuracyMeters !== undefined ? { accuracyMeters: f.accuracyMeters } : {}),
  }));

  return {
    fixes,
    candidates: options.candidates,
    ...(options.catalogVersion !== undefined ? { catalogVersion: options.catalogVersion } : {}),
    ...(options.candidateRadiusMeters !== undefined
      ? { candidateRadiusMeters: options.candidateRadiusMeters }
      : {}),
    ...(options.insideRatioBufferMeters !== undefined
      ? { insideRatioBufferMeters: options.insideRatioBufferMeters }
      : {}),
    ...(options.maxSimplifiedPoints !== undefined ? { maxSimplifiedPoints: options.maxSimplifiedPoints } : {}),
    ...(options.tieThreshold !== undefined ? { tieThreshold: options.tieThreshold } : {}),
    ...(options.acceptInsideRatio !== undefined ? { acceptInsideRatio: options.acceptInsideRatio } : {}),
  };
}
