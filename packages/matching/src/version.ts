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
 */
export const MATCHER_VERSION = 1;
