# `@golfraven/p0-tools`

Three check tools for build plan §10 P0's kill experiments **X1** (=K4a, Health real-device test)
and **X5** (Overpass OSM coverage). See `docs/p0/X1.md`, `docs/p0/X5.md`,
`docs/owner/x1-k4b-device-protocol.md`, `docs/p0/K4.md`, and decision
`docs/decisions/0001-owner-decisions-and-p0-thresholds.md` Addendum D R6 for the
checks these implement — this README only covers running the tools.

## Build

```shell
pnpm --filter @golfraven/p0-tools build
```

Produces `dist/x1-ios-export.js`, `dist/x1-verdict.js`, `dist/x5-overpass.js` (plus `dist/index.js`,
the library entry point re-exporting all three tools' pure functions/types).

## 1. `x1-ios-export` — iOS Health export reader

Reads Matt's unzipped `apple_health_export/` directory (from **Settings → Health → profile icon →
Export All Health Data** on the iPhone, then unzipping `export.zip`
`[unverified — training knowledge, per plan G-P0-06 and `docs/owner/x1-k4b-device-protocol.md` §2d]`)
and reports every `HKWorkoutActivityTypeGolf` workout it finds, per source, with route evidence.

```shell
node dist/x1-ios-export.js /path/to/apple_health_export --since 2026-09-15 --out x1-ios-export-result
```

- `<path>` — the directory that directly contains `export.xml` and `workout-routes/`.
- `--since YYYY-MM-DD` (optional) — an extra, coarser pre-filter on top of the round window below.
- `--out <prefix>` (optional, default `x1-ios-export-result`) — writes `<prefix>.json` and
  `<prefix>.md`.

**Round windows (decision 0001 Addendum F, gate finding B-7) — REQUIRED, no override flag.** Before
running, the CLI always reads the repo's own `docs/p0/X1.md` "## Round windows" section for the
logged UTC start/end time of each test round, and **refuses to run if it's still blank** — never
silently treats every workout on the device as in-round. Only a workout whose start time falls
inside a logged window, with 60 minutes of slack either side, counts; older workouts on the device
are excluded (with a warning naming how many). Log the window(s) in `docs/p0/X1.md` before reading
the export.

**Feeds:** the JSON is one of `x1-verdict`'s two inputs. The markdown table's columns match
`docs/owner/x1-k4b-device-protocol.md` §4's results table (Source / OS / Workout written? / Route
present? / CONSENT_REQUIRED column (always "N/A (iOS)" here) / Source id / Verdict) — copy rows
straight into that table, then into `docs/p0/X1.md` MEASURED VALUE once the round is run.

**Loud-failure contract:** if `export.xml`'s root element isn't `<HealthData>`, `<Workout>`
elements exist but none carry a `workoutActivityType` attribute, or a `<WorkoutRoute>` appears as a
**sibling** of `<Workout>` rather than nested inside one (gate finding B-8 — the least-certain part
of the assumed shape), the tool **throws and exits 1** — it never silently reports zero golf
workouts, or zero routes, for a shape it doesn't recognize. Genuinely zero golf workouts in a
well-shaped file is not an error (see `--since`/wrong-directory sanity-check it yourself if that's
surprising). See `src/health-export-xml.ts`'s module doc for the full list of
`[unverified — training knowledge]` assumptions about Apple's export.xml shape this relies on, and
"Known risk" below.

## 2. `x1-verdict` — X1 pass/kill from recorded results

Pure function (`computeX1Verdict`, importable from `dist/index.js`) plus a CLI wrapper.

```shell
node dist/x1-verdict.js \
  --ios x1-ios-export-result.json \
  --android health-connect-reader-result.json \
  --source-map source-map.json \
  --follow-ups android-route-follow-ups.json \
  --out x1-verdict-result
```

- `--ios` — `x1-ios-export`'s JSON output.
- `--android` — the Android Health Connect reader's JSON output
  (`apps/mobile/src/health-connect/` — a `GolfSessionReadResult`; run it on the Android round).
- `--source-map` — a small JSON file you write once per round, mapping each of the 3 sources to the
  `sourceName` values (iOS) / `dataOrigin` package names (Android) that identify it, e.g.:

  ```json
  {
    "garmin": {
      "iosSourceNames": ["Garmin Connect"],
      "androidDataOrigins": ["com.garmin.android.apps.connectmobile"]
    },
    "appleWatch": { "iosSourceNames": ["Matt's Apple Watch"] },
    "phoneApp": {
      "iosSourceNames": ["18Birdies"],
      "androidDataOrigins": ["com.eighteenbirdies.android"],
      "appUsed": "18Birdies"
    }
  }
  ```

  If `phoneApp.appUsed` is `"Hole19"`, you must also set `"hole19SwapLoggedBeforeRound": true` —
  the tool **throws** otherwise (decision 0001 Addendum D R6: Hole19 replaces 18Birdies as the
  source verdict only when the swap was logged in `docs/p0/X1.md`'s Log _before_ the round; this
  is a literal validation, not a suggestion). Any source not listed here (TheGrint, Golfshot,
  SwingU, ...) is ignored for verdict purposes even if it appears in the iOS/Android data —
  "supplementary, never the source verdict" per R6.

- `--follow-ups` (optional) — a JSON object `{ "<Health Connect recordId>": { "routePresent": bool,
"routePointCount": n } }` for any Android session Health Connect reported as `CONSENT_REQUIRED`,
  from a follow-up `requestExerciseRoute(recordId)` call (R6). A `CONSENT_REQUIRED` session with no
  entry here defaults to "not present," per R6.

**Round windows — REQUIRED (same as `x1-ios-export` above).** The CLI also always reads
`docs/p0/X1.md`'s logged round window(s) and refuses to run if none is logged. It re-applies the
window filter to both the `--ios` and `--android` inputs itself (gate finding B-7) — independent of
whatever filtering already happened upstream — so a stale or hand-edited JSON file can't silently
widen the verdict.

**The "≥ 1 OS" bar, made exact (decision 0001 Addendum F, gate finding B-6).** X1 passes only if
there is **one** operating system on which **≥ 2 of the 3 sources** pass. Sources that pass on
_different_ OSes (e.g. Apple Watch only on iOS, Garmin only on Android) do **not** combine — that
reading predicts what a user actually gets, since a user syncs from one phone. The result's
`sourcesPassingByOs: { ios, android }` shows both counts explicitly, alongside `overallVerdict`.

**Feeds:** `overallVerdict` → `docs/p0/X1.md` VERDICT; `perSource` → the per-source column of
`docs/owner/x1-k4b-device-protocol.md` §4 and `docs/p0/X1.md`'s A2-14 requirement;
`garminWrittenStatementTriggeredByX1` → the first half of `docs/p0/K4.md`'s "written statement"
requirement (K4b failing independently also triggers it — this tool has no K4b data and does not
assess that half).

## 3. `x5-overpass` — Overpass OSM coverage

```shell
# N_osm (pace measurement, not pass/fail)
node dist/x5-overpass.js n-osm
node dist/x5-overpass.js n-osm --endpoint https://overpass-api.de/api/interpreter --timeout-ms 190000

# Coverage (the pass/fail measurement), live
node dist/x5-overpass.js coverage --courses pilot-candidate-courses.json

# Coverage, offline against saved Overpass responses (how the test suite runs it)
node dist/x5-overpass.js coverage --courses pilot-candidate-courses.json \
  --responses saved-overpass-responses.json
```

- `--courses <file>` — a JSON array of pilot-candidate courses (X2 fills this once its roster
  fetch runs):

  ```json
  [
    {
      "name": "Pilot Ridge Golf Course",
      "lat": 36.0,
      "lon": -87.0,
      "trail": "TN",
      "unit": "course"
    },
    {
      "name": "RTJ Course A",
      "lat": 34.0,
      "lon": -86.0,
      "trail": "RTJ",
      "unit": "course",
      "facilityId": "rtj-site-1"
    }
  ]
  ```

  `unit` is X2's `completionUnit` for that trail (`course` | `facility` | `hole`). `facilityId` is
  used to group `unit: "facility"` courses that share one polygon (X5.md's `course`-unit rule is
  implemented verbatim: one denominator entry per course even when several share a facility
  polygon; `facility`-unit trails count one entry per `facilityId`, covered if any of its courses
  matched, and `hole`-unit trails count one entry per course — both pinned in decision 0001 Addendum E
  before any X5 data). `knownPoint: {lat, lon}` is optional — when present, the match rule tries point
  containment, and _also_ uses it as the distance origin for the 500 m name-match (both branches are
  always evaluated; a known point outside every polygon does not skip the name-match branch — gate
  finding F-S1). With no known point, the name-match branch uses the approximate `lat`/`lon` instead.
  `id` is optional (gate finding B-12):
  a stable id from X2, used to key saved responses/denominator entries instead of `name` — set it
  when two pilot-candidate courses can share a name (e.g. across RTJ sites); the bbox query is
  also centered on `knownPoint` when given, not the approximate `lat`/`lon` (gate finding B-11).

- `--endpoint` (default `https://overpass-api.de/api/interpreter`), `--timeout-ms` (default
  190000), `--bbox-radius-meters` (default 2000 — a query-fetch window size, **not** part of the
  pre-registered match rule; see `overpass-geo.ts`).
- `--responses <file>` — a JSON object keyed by each course's `id` (or `name` if it has none), each
  value a saved Overpass response for that course's coverage query (from a prior live run, or
  hand-built for a test). When given, no network call is made, and a course missing from this file
  is a hard **refusal** (gate finding B-4), never a silent "treat as unmatched".
- `--from-file <file>` (the `n-osm` subcommand only) — same idea, one saved response for the
  N_osm query.

**Match rule, made exact (decision 0001 Addendum F, gate findings B-1/B-2/B-3/F-S1) — supersedes this
README's and X5.md's own looser wording wherever they differ.** A `leisure=golf_course` way **or
relation** matches when **either** (a) the course's known point lies inside the polygon — a relation's
outer ring(s) are assembled from its `outer`-role `way` members (Overpass `out geom` puts a
relation's geometry under `members[]`, never a top-level `geometry` — a way-only reading silently
skipped every relation-mapped course) — **or** (b) the names match **and** the shortest distance
from the course's point to the polygon is ≤ 500 m (0 if inside — never a centroid distance, which
was skewed by vertex density and could put an inside point outside its own polygon). **Both branches
are always evaluated when a known point exists** — a known point that lies outside every candidate
polygon does not skip the name-match branch; it just supplies that branch's distance origin instead
of the approximate `lat`/`lon` (gate finding F-S1). Names match after normalisation (Unicode NFKD,
diacritics stripped, lower-cased, non-letter/digit → space, whitespace collapsed) on equality or
whole-word containment — **no abbreviation list or fuzzy matching** ("St." and "Saint" do NOT unify;
"Golf Club" and "Golf Course" do NOT unify).

**Run integrity (decision 0001 Addendum F).** An Overpass `remark` (its way of reporting a runtime
error, e.g. a timeout, as HTTP 200 with partial/empty `elements`), a missing or unparseable response
for any course, or an empty `--courses` list all **stop the run with a non-zero exit** — none of
them is ever silently counted as "unmatched" or a vacuous 0/0 (gate finding B-4). In **live** mode
(no `--responses`), every raw Overpass response is also saved to `<out>-responses.json`, keyed the
same way `--responses` expects, with the query text and a fetch timestamp — so the verdict can be
replayed offline / re-audited later (gate finding B-5). The contact string in the Overpass
`User-Agent` is read from the `X5_CONTACT` env var (gate finding B-10), not hard-coded — set it to
a real contact before a live run; it defaults to a generic project URL when unset.

**Feeds:** `n-osm`'s printed total → `docs/p0/X5.md` MEASURED VALUE's `N_osm`. `coverage`'s
combined/per-trail percentages and PASS/KILL line → `docs/p0/X5.md` MEASURED VALUE and VERDICT
(bar: ≥ 60%, applied literally — see `computeCoverage`/`buildDenominatorEntries` in
`src/x5-overpass.ts`).

### Known risk

The exact Overpass POST protocol (`data=<urlencoded query>` form body to `/api/interpreter`) this
tool uses is `[unverified — training knowledge]` — it has not been confirmed against a live
response in this environment (see below). If it turns out wrong once network access is unblocked,
the fix is localized to `runOverpassQuery` in `src/x5-overpass.ts`; the query builders, match rule,
and coverage math are all tested independently of it via `--from-file`/`--responses`.

### This session's live run against the default endpoint

Per `docs/p0/X5.md` STATUS ("BLOCKED — network policy... proxy 403 on CONNECT as of 2026-09-23"),
running `node dist/x5-overpass.js n-osm` against the real default endpoint was expected to fail on
this environment's proxy. See the task report for the exact error text this session got — it was
not worked around, per the task's own instruction.

## Tests

```shell
pnpm --filter @golfraven/p0-tools test
```

All fixtures are synthetic (`test/fixtures/`) — a small hand-written `export.xml` + GPX files, and
saved Overpass JSON responses. **No test makes a network call.** Coverage includes: golf vs.
non-golf workout filtering; a workout with no route; a missing GPX file; an empty (0-trackpoint)
GPX file; a wrong root element and a wrong Workout shape both failing loudly; the `--since` filter;
R6's `CONSENT_REQUIRED` + follow-up cases (present / absent / no follow-up run); the Hole19 swap
with and without a logged pre-round swap; the X1 2-of-3 boundary (exactly 2 passes, exactly 1
fails); X5's match-rule boundaries (500 m name-match just inside/outside, point-containment not
falling back to name-match); facility-sharing (`unit: "course"` denominator counts per course even
when several share one polygon; `unit: "facility"` groups by `facilityId`); and the 60% coverage
boundary (exactly 60% passes, just under fails).
