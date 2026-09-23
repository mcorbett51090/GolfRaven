/**
 * P0 placeholder.
 *
 * `@golfraven/matching` is pure TS course-matching logic run on device, in
 * tests, and in server replay for disputes (build plan §3.1 row D, §7.4):
 * simplify a route, collect nearby candidates, compute `insideRatio`
 * against course polygons, and pick a match. None of that exists yet — P1
 * onward builds it against real catalog geometry. This module only proves
 * the package builds and typechecks so that work has a workspace to land
 * in.
 */

/** Bumped whenever the matching algorithm changes in a way that could
 * change a past decision (build plan §3.1 row D: `matcherVersion`). */
export const MATCHER_VERSION = 0;
