/**
 * Bumped whenever the matching algorithm changes in a way that could change
 * a past decision (build plan §3.1 row D: `matcherVersion`). The same code
 * — and therefore the same version number — runs on device, in tests, and
 * in server replay for disputes (build plan §3.1 row D).
 *
 * v1 is the first real implementation (build plan §7.4 steps 1–5): route
 * simplification, candidate search, `insideRatio`, the acceptance rules
 * (including radius fallback and shared-geometry disambiguation), and the
 * foreground check-in match. v0 was the P0 placeholder.
 *
 * **Cross-engine determinism caveat.** This package runs on device (JSC on
 * older iOS / Hermes on RN's default engine) as well as in tests and
 * server replay (V8/Node). `Math.sin`, `Math.cos`, `Math.atan2`,
 * `Math.asin`, `Math.sqrt`, and friends are specified by ECMA-262 to be
 * "implementation-approximated" — the spec gives no exact bit-for-bit
 * algorithm, only an accuracy expectation, so Hermes and V8 can (and do)
 * return results that differ in the last one or two ULPs for the same
 * input. Every boundary comparison in this package (an `insideRatio`
 * threshold, a buffer distance, the 0.15 tie gap, the duration window)
 * therefore rounds both sides to a fixed precision before comparing
 * (`geo.ts`'s `roundTo`: distances to 0.01 m, ratios and hours to 1e-9) —
 * see `geo.ts` and the modules that call it — so a genuine boundary case
 * cannot flip between engines. This does NOT change `MATCHER_VERSION`:
 * it is a robustness fix, not a change to what counts as a match.
 *
 * **Matcher parameters (gate fix: cap the gaps in the time-weighting).**
 * Two constants govern how a route's `insideRatio` handles large gaps
 * between fixes — both defined and documented in `inside-ratio.ts`, and
 * restated here because they materially change what counts as a match
 * and belong beside the other tunables this file documents:
 *  - `MAX_GAP_SECONDS = 300` (5 min) — the most any single inter-fix
 *    interval can contribute to the time-weighted total. Without this
 *    cap, one inside fix, a multi-hour gap, then one more inside fix
 *    could make that gap's whole span count as "inside" time, even
 *    though nothing was actually observed during it.
 *  - `MIN_OBSERVED_COVERAGE = 0.5` — the minimum fraction of a route's
 *    wall-clock span that must be covered by fixes (after the cap above)
 *    for a polygon candidate to ever be `matched`; below it, the route
 *    goes to `typeahead` regardless of how clean the ratio looks over
 *    what little was observed. Reported as `MatchSummaryFields.
 *    observedCoverage` on every outcome. Scoped to polygon matching only
 *    — a radius-fallback match is still decided purely by start/end
 *    containment (build plan §4.2), unaffected by either parameter.
 */
export const MATCHER_VERSION = 1;
