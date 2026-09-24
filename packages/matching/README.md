# @golfraven/matching

On-device course matching (build plan §3.1 row D, §7.4): simplify a route,
collect nearby candidates (including unverified directory stubs), compute a
time-weighted `insideRatio` (or the radius-fallback start/end containment
test), apply the acceptance / `ask_user` / `typeahead` rules, and match a
single foreground check-in fix.

Pure TypeScript, no dependencies. The same code runs on device, in tests,
and in server replay for disputes (build plan §3.1 row D). It deliberately
does **not** import `@golfraven/catalog` — that schema is being revised in
a parallel workstream — so it defines its own minimal `CandidateCourse`
shape (`src/types.ts`) instead. Whoever wires this package up projects
catalog rows into that shape.

Deciding rewards (`packages/rules` `scorePlay`) is out of scope. This
package only produces the fields build plan §4.5 says the scorer consumes
from matching.

## Modules

| File | What it does |
|---|---|
| `types.ts` | The public input/output shapes. |
| `geo.ts` | Single-ring geometry primitives: haversine distance, the local equirectangular projector, point-in-ring, ring-boundary distance, `roundTo`. Kept stable (a flat `LatLng[]` ring in, a number out) because tests and diagnostic probes call these directly. |
| `polygon.ts` | Multipolygon-with-holes geometry, built on `geo.ts`'s primitives: normalizing the three accepted polygon shapes, preparing a candidate's geometry once (projected + bounding box), the buffered inside test, and the bbox-prefiltered distance test used for the candidate search. |
| `inside-ratio.ts` | The time-weighted `insideRatio` computation over raw, sorted fixes. |
| `simplify.ts` | Deterministic route simplification to a point-count cap, for the transmitted summary only. |
| `duration.ts` | The 1.5–6 h / 9-hole ≥ 0.75 h acceptance window. |
| `fixes.ts` | Fix validation (`RangeError` on non-finite fields) and stable time-sorting. |
| `candidates.ts` | The 3 km candidate search. |
| `route-match.ts` | `matchRoute` (the whole pipeline) and `resolveAskUser`. |
| `checkin.ts` | `matchCheckIn`, the foreground check-in match — fails closed on malformed input. |
| `version.ts` | `MATCHER_VERSION`. |

## Ambiguities and design decisions

This section records every place the build plan (`RavenGolf/docs/golf-trails/02-build-plan.md`)
underspecified something this package had to decide, with the plan line
it leaned on. Two rounds: the original implementation, and the fixes made
after an Opus-tier review found real bugs in it.

**Round 1 (original implementation):**

1. Added an optional `holes` field to `CandidateCourse`, beyond the design
   constraint's literal field list (id, verification tier, polygon/circle,
   facility id, shared flag) — the §7.4 step 4 duration window depends on
   whether a candidate is a 9-hole course, so the matcher needs *some*
   signal for that. Defaults to 18 when omitted.
2. Generalized "shared polygon" into a single `sharedGeometry` flag that
   also covers identical radius-fallback circles (§4.2: "every course at
   a multi-course site has the same circle"; §4.3: "identical radius
   circles … at a site"), rather than a polygon-only boolean.
3. Radius-fallback matching applies no buffer to the start/end containment
   test, per §4.2's literal wording ("start and end both fall inside the
   circle").
4. The 0.15 tie threshold (§7.4 step 4) is compared only within the set of
   candidates that already qualify geometrically and on duration — not
   across every nearby candidate.
5. The one-pick-per-facility-per-date guard (§4.3) is applied to every
   `ask_user` resolution via `resolveAskUser`, not only the
   `shared_geometry` reason — the spirit of the guard (one visit can't
   tick two courses) plausibly extends to a close-scores ambiguity too.
6. `course_disambiguated_by: 'staff'` is never produced by this package —
   that's a partner-portal decision made entirely outside its boundary
   (§3.1 rows D/H).
7. Composite-course roster aggregation (a play on a composite also
   satisfies its constituent nines as roster members, but counts once in
   `uniqueCourses`, §4.3), co-signal/allow-list classification, and
   velocity/spoof-detection fraud heuristics (§4.5) are all explicitly out
   of scope — they belong to `packages/rules` and the server.

**Round 2 (gate fixes, after review):**

8. **`insideRatio` is time-weighted over the raw, time-sorted fixes**
   (`inside-ratio.ts`), never computed by counting vertices after
   Douglas-Peucker simplification. The original implementation did the
   latter, which is biased: a long straight stretch collapses to ~2
   points under simplification regardless of how long it actually took,
   while a winding stretch of the same real duration keeps many points —
   so a post-simplification vertex count is not a duration fraction at
   all. Each fix's weight is half of each of its adjacent time intervals
   (a standard trapezoidal scheme), so weights sum exactly to the route's
   duration. Simplification (`simplify.ts`) is kept, but only for the
   transmitted summary/geometry.
9. **A radius match is never ranked on the polygon `insideRatio` scale.**
   A qualifying polygon candidate always outranks every radius candidate
   outright; radius candidates are only even considered when no polygon
   candidate qualifies. `MatchedCourse.insideRatio` is `null` for a
   `'radius'` match (with a separate `radiusStartEndInside: true`
   instead), so the §4.5 scorer's 0.6/0.8 `insideRatio` bands can never
   accidentally read a radius-derived number.
10. **A solo candidate still routes to `ask_user` if it's flagged
    `sharedGeometry`**, even when no sibling appears in that particular
    call (e.g. a sibling was filtered out by the duration window).
    Geometry that is *inherently* shared can't vouch for uniqueness just
    because this call happens not to include the sibling.
11. **Holes and multipolygons.** `CandidateCourse.polygon` accepts a flat
    `LatLng[]` ring (unchanged), a single polygon's rings (`Ring[]`, outer
    + holes), or a `MultiPolygon` (several such polygons — e.g. a
    composite course whose lobes don't touch). A point inside a hole is
    outside the polygon. The buffer is applied symmetrically to hole
    boundaries too (a point just inside a hole, near its edge, is treated
    the same as a point just outside the course boundary near its edge) —
    GPS noise doesn't know which side of a boundary is "the excluded
    part", so there's no principled reason to buffer one direction and
    not the other.
12. **Determinism.** `roundTo` (`geo.ts`) rounds every boundary comparison
    (distances to 0.01 m, ratios and durations to 1e-9) before comparing,
    because `Math.sin`/`cos`/`atan2`/etc. are only
    "implementation-approximated" per ECMA-262 and can differ in the last
    ULP or two between JS engines (V8 in Node/tests/server replay vs.
    Hermes on device) — see `version.ts`. Tied candidates are sorted by
    score, then by plain ordinal `courseId` comparison (never
    locale-aware `localeCompare`, which could itself vary by ICU version)
    — output ordering never depends on the order candidates were passed
    in.
13. **Known, deliberately unaddressed limitation: the antimeridian.** The
    local equirectangular projection (`geo.ts`) does no longitude
    normalization across the ±180° seam, so a polygon whose ring crosses
    it would project incorrectly (confirmed via a diagnostic probe during
    the gate-fix pass). No golf course spans the international date line,
    this was never in the build plan's scope, and a correct fix is a
    non-trivial geodesy undertaking — so it's recorded here rather than
    silently left for someone to rediscover.
