# `@golfraven/p0-tools`

Check tools for build plan §10 P0's kill experiments **X1** (=K4a, Health real-device test), **X2**
(pilot-slate roster/rules direct-fetch), **X4** (GolfNow facility-page coverage) and **X5** (Overpass
OSM coverage), plus **`p0-desk`**, a one-command runner for the checks that don't need a human
confirmation file first, and the **K1** (operator + sponsor signal) and **K3** (SEO signal) verdict
tools. See `docs/p0/X1.md`, `docs/p0/X2.md`, `docs/p0/X4.md`, `docs/p0/X5.md`, `docs/p0/K1.md`,
`docs/p0/K3.md`, `docs/partners/k1-outreach.md`, `docs/owner/x1-k4b-device-protocol.md`,
`docs/p0/K4.md`, and decision `docs/decisions/0001-owner-decisions-and-p0-thresholds.md` Addenda A, B,
C, D (R1, R2, R4, R5, R6), E, F, G and H for the checks these implement — this README only covers
running the tools.

## Build

```shell
pnpm --filter @golfraven/p0-tools build
```

Produces `dist/x1-ios-export.js`, `dist/x1-verdict.js`, `dist/x2-fetch.js`, `dist/x2-verdict.js`,
`dist/x4-verify.js`, `dist/x5-overpass.js`, `dist/p0-desk.js`, `dist/k1-verdict.js`,
`dist/k3-verdict.js` (plus `dist/index.js`, the library entry point re-exporting every tool's pure
functions/types).

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

## 3. `x2-fetch` — pilot-slate roster/rules direct-fetch, evidence gathering

```shell
node dist/x2-fetch.js
node dist/x2-fetch.js --config config/x2-sources.json --out-dir x2-evidence
```

- `--config <file>` (default: this package's own `config/x2-sources.json`) — trail name → list of
  official URLs to fetch (seeded from the URL table in `docs/p0/X2.md`: TN tries
  `tnstateparks.com/golf`, `tngolftrail.net` and `tn.gov` candidates — the exact `tngolftrail.net`/
  `tn.gov` paths are `[unverified — X2.md only names the hosts, not a confirmed path]`, so their
  entries are each host's root URL; VI the two pages plus the Trail Pass terms PDF; RTJ
  `rtjgolf.com`). **Gate finding S9 — operator note:** these are HOMEPAGES, not confirmed trail
  rules/roster pages; the tool fetches exactly what's configured and never crawls or searches, so if
  a trail's `completionUnit`/season/roster facts actually live on a deeper rules page, **add that
  page's URL to `config/x2-sources.json` before writing the confirmation file** — a homepage-only
  config structurally biases that trail toward "unconfirmed," not because the trail's facts don't
  exist, but because this tool never went looking for them past the homepage.
- `--out-dir <dir>` (default: a fresh directory under the OS temp dir — gate finding S7; pass
  `--out-dir` explicitly to write anywhere else, including inside the repo) — where evidence is
  written: `<out-dir>/manifest.json` (the full per-URL record), `<out-dir>/raw/<sha256>.<ext>` (raw
  bytes) and `<out-dir>/text/<sha256>.txt` (extracted text).

**Evidence stored per URL, per decision 0001 Addendum G ("X2 'confirmed from a direct fetch'"):**
raw bytes, the final URL after redirects, the HTTP status, `fetchedAt` (UTC), a SHA-256 of the
bytes, and an extracted-text file. HTML → text with tags stripped and whitespace collapsed
(`text-extract.ts`; inline elements like `<a>`/`<span>`/`<b>` never insert a space at their
boundary, matching a browser's own copy-paste — gate finding S4). **PDF → text is derived with a
pinned, pure-JS extractor (`unpdf`, no native build step — `pdf-extract.ts`, gate finding S3)** and
recorded as `textExtraction: "auto-pdf"` plus the exact `extractor` id (e.g. `unpdf@1.8.1`); a PDF
is never left as bytes-only or typed by hand. The evidence bytes are classified by their **magic
bytes** first (`%PDF-`), not the HTTP content-type or URL suffix (gate N5), so a `.pdf` URL that
actually serves an HTML error page is stored as opaque binary, not mis-read as either. `x2-verdict`
re-derives this SAME text from the SAME raw bytes at verdict time — the stored `text/<sha>.txt` file
is a convenience copy only, never itself trusted (gate S1). A fetch that fails — including this
environment's own network-policy block, reported as `"BLOCKED — network policy (<host>)"` (see
`net.ts`) — is recorded in the manifest as `status: "failed"` with the exact error; it is never
silently skipped. Only `https:` URLs are ever fetched, and a response that downgrades to `http:` via
redirect is rejected too (gate N6). Every fetch has a real timeout covering the full body read (not
just the initial headers) and a 10 MB response-size cap enforced while streaming (gate S6).

**DRAFT candidate names.** For each successfully-fetched HTML page, headings (`h1`-`h6`) and link
text are extracted into a per-trail, deduplicated list, printed to stdout clearly labelled
**DRAFT** and written into the manifest's `draftCandidateNames`. This is a hint for whoever writes
the confirmation file below — **never itself a confirmation**; only `x2-verdict`, checking a
human-written confirmation file against the stored evidence text, confirms a roster.

**Feeds:** the evidence dir (raw + text + `manifest.json`) is `x2-verdict`'s first input.

## 4. `x2-verdict` — X2 pass/kill verdict from a human-written confirmation

```shell
node dist/x2-verdict.js --evidence-dir x2-evidence --confirmation x2-confirmation.json --out x2-verdict-result
```

- `--evidence-dir <dir>` — an `x2-fetch` output dir (reads its `manifest.json`).
- `--confirmation <file>` — a JSON object, **per trail** (`"TN"`/`"VI"`/`"RTJ"`):

  ```json
  {
    "TN": {
      "roster": [
        {
          "name": "Bear Trace at Harrison Bay",
          "quote": "Bear Trace at Harrison Bay is a member of the Tennessee Golf Trail.",
          "evidenceSha": "<sha256 of the evidence file this quote/name came from>"
        }
      ],
      "completionUnit": {
        "value": "course",
        "quote": "the exact sentence, from the fetched page, that settles the completion unit",
        "evidenceSha": "<sha256>"
      },
      "season": {
        "value": "year-round",
        "quote": "the exact sentence that settles the season window",
        "evidenceSha": "<sha256>"
      }
    }
  }
  ```

**Implements decision 0001 Addendum G literally.** A trail is confirmed only if:

- **all three facts are present** (a non-empty `roster`, a `completionUnit`, and a `season`), and
- **every quote appears verbatim, after whitespace collapsing,** in the extracted text of the
  evidence file its `evidenceSha` cites (`collapseWhitespace`, same rule for both sides of the
  comparison — a quote copy-pasted with different line-wrapping still matches), and
- **every roster entry's name** also appears (same whitespace-collapsing rule) in the evidence text
  its own `evidenceSha` cites, and the quote/value are non-empty and at least 12 characters (gate N8).

X2 passes when **≥ 2 of the 3 slate trails are confirmed** (X2.md's pass bar, unchanged). Each
trail's `reasons` array explains exactly which fact failed and why, and also lists every source
that FAILED or was BLOCKED for that trail — even one that contributed no evidence at all (gate S5),
so an unconfirmed trail is never indistinguishable from one whose only rules page never loaded.
`perTrail[trail].facts` echoes every fact actually checked (value/quote/evidenceSha) and
`rosterSize`, so a reviewer can see why a trail confirmed without re-opening the confirmation file
(gate S8).

**Evidence is never trusted from the manifest or the stored `text/<sha>.txt` file.** At verdict
time, `buildEvidenceByTrail` re-reads each entry's RAW bytes, **recomputes its SHA-256**, and
**re-derives its text with the identical extractor `x2-fetch` used** — refusing (throwing) if the
recomputed hash doesn't match the manifest's recorded one (gate S1). Evidence is scoped **strictly
per trail**: a fact may only cite evidence that trail's own `x2-fetch` run produced, whose final URL
(after redirects) is still on the same host that trail's own config asked for; citing another
trail's SHA, or a SHA that redirected to a foreign host, is a hard refusal — never silently treated
as a confirmation (gate S2).

**Refuses (non-zero exit) if a cited `evidenceSha` doesn't match evidence belonging to that trail**
— whether because the SHA doesn't exist anywhere, belongs to a different trail, or was excluded as a
foreign-host redirect. This is a hard integrity check, never silently treated as "quote not found"
(which would make a fabricated/borrowed SHA indistinguishable from a real, failed verification). The
CLI also exits non-zero when a trail is unconfirmed while one of its sources failed/was blocked
(gate S5) — `--out` defaults outside the repo the same way `x2-fetch`'s `--out-dir` does (gate S7).

**Feeds:** `overallVerdict` → `docs/p0/X2.md` VERDICT; `perTrail` reasons → the log entry explaining
each trail's confirmed/unconfirmed status.

## 5. `x4-verify` — GolfNow facility-page coverage, per trail

```shell
# Live
node dist/x4-verify.js --courses x4-course-map.json --out-dir x4-verify-result

# Offline, against saved responses (how the test suite runs it)
node dist/x4-verify.js --courses x4-course-map.json --responses x4-verify-result/responses.json
```

- `--courses <file>` — a hand-built JSON map, **slate course name → `{trail, golfnowFacilityUrl}`**
  (X4.md METHOD: facility ids are looked up **by hand** on golfnow.com; this tool never searches or
  crawls GolfNow, it only fetches the exact URL it's given):

  ```json
  {
    "Grand National": { "trail": "RTJ", "golfnowFacilityUrl": "https://www.golfnow.com/tee-times/facility/2360-grand-national/search" },
    "Some TN Course": { "trail": "TN", "golfnowFacilityUrl": null }
  }
  ```

  `golfnowFacilityUrl: null` means no GolfNow page was found for that course — it counts as **not
  covered**, same as a fetched-but-not-live page (X4.md/Addendum G).

- `--responses <file>` — a saved-response file from a prior live run (`<out-dir>/responses.json`),
  keyed by course name. When given, no network call is made; a course with a non-null URL but no
  entry in this file is a hard **refusal**, never silently treated as not-live (same run-integrity
  style `x5-overpass.ts` uses for its own `--responses`). A saved entry whose `request.url` no
  longer matches the course map's CURRENT url for that course is also a hard refusal, rather than
  silently replaying a stale response (gate N1).
- `--out-dir <dir>` (default: a fresh directory under the OS temp dir — gate S7) — writes
  `result.json` always, and `responses.json` in live mode (every live response saved for replay,
  same `{request, fetchedAt, response}` envelope pattern as `x5-overpass.ts`'s own saved responses).
- `--slate TN,VI,RTJ` (default: the pilot slate) — every named trail must have at least one entry in
  `--courses`, or the run refuses (gate N7); pass a narrower/different list to evaluate a
  partial/reserve slate deliberately.

**Decision 0001 Addendum H's three-way per-course outcome, applied literally** (this supersedes the
old two-way live/not-live read):

- **live** — HTTP 200, the final URL's **host is exactly `www.golfnow.com`**, its **path** contains
  `/tee-times/facility/<id>-` for the **SAME `<id>`** parsed from the *configured* URL (gate B2 — a
  match in the query string, or for a different id, does NOT count), and the page text contains the
  course's name under Addendum F's normalisation (`namesMatch`, reused verbatim from
  `overpass-geo.ts`).
- **not covered (definitive)** — no URL configured, HTTP 404/410, or a resolved HTTP 200 page that
  fails the live test above (wrong id, generic search page, foreign host, name absent).
- **indeterminate** — a network-policy block, timeout, connection error, HTTP 403/429/any 5xx, or
  any other unlisted status. **Never** counted as "not covered" (gate B1).

A configured URL is parsed with `^https://www\.golfnow\.com/tee-times/facility/(\d+)-[^/]+/search$`
(gate B2); a course map entry that doesn't match is a hard refusal, not a silent skip. Every fetch's
timeout covers the full body read, with a 10 MB size cap enforced while streaming (gate S6).

**Coverage per trail = live ÷ that trail's roster size** (a `null` URL and a definitively-not-live
page both count as not covered — X4.md's own rule). **A trail's verdict is computed only when NONE
of its courses is indeterminate** (Addendum H); otherwise that trail reads as `"not run —
indeterminate (n)"` in `perTrail[trail]` (`verdict: "not-run"`, `pct: null`), and the CLI exits
non-zero (`result.anyIndeterminate`). Otherwise, **evaluated per trail, independently** (decision
0001 Addendum G: "no combined figure decides anything") — pass ≥ 80%, else kill with that trail's
consequence ("course-native link becomes primary for `<trail>`").

**Feeds:** `perTrail` → `docs/p0/X4.md` MEASURED VALUE and VERDICT (per trail; X4.md has no single
combined figure). A `"not-run"` trail is not a verdict at all — re-run once its indeterminate
course(s) resolve.

## 6. `p0-desk` — one-command desk check + status board

```shell
node dist/p0-desk.js
node dist/p0-desk.js --run-dir p0-desk-run-2026-10-05 --x2-config config/x2-sources.json --x4-courses x4-course-map.json
```

Runs, **in order**: `x5-overpass n-osm`, `x2-fetch`, and — **only if a course-map file exists** at
`--x4-courses` (default: `config/x4-course-map.json`, not seeded — X4.md's own precondition is that
X2's rosters are confirmed first) — `x4-verify` (evaluated over whichever trails are actually present
in that course map, not a hard-coded slate). All evidence is written under one timestamped run
directory OUTSIDE the source tree (`--run-dir`, default: a fresh directory under the OS temp dir —
gate S7; pass `--run-dir` explicitly to write anywhere else, including inside the repo):
`x5-n-osm/response.json`, `x2-evidence/` (the same shape `x2-fetch` writes on its own), and, when it
ran, `x4-verify/`.

Prints a status board, one row per check, with `state`:

| State | Meaning |
|---|---|
| `ran` | The check ran and produced its own measurement (only `x5-overpass n-osm`, a pace measurement — no pass/fail). |
| `needs-confirmation` | Evidence gathered (`x2-fetch`), ALL sources fetched cleanly; a human must still write a confirmation file and run `x2-verdict`. |
| `verdict` | The check computed its own clean pass/kill for every trail (`x4-verify`, per trail — never used when any trail is indeterminate). |
| `partial-blocked` | **Gate S5/B1: some, but not all, sources failed/were blocked** (`x2-fetch`), or **some trail is indeterminate under Addendum H** (`x4-verify`) — never reads as a clean `needs-confirmation`/`verdict`. |
| `skipped` | Nothing to run yet — e.g. no `x4` course-map file (X4's own precondition, not a failure). |
| `blocked` | **Every** attempted source for that check hit a network-policy block — surfaced as `"BLOCKED — network policy (<host>)"` (see `net.ts`'s detection of both observed shapes: a resolved 403 denial page, or a thrown CONNECT/tunnel 403 error). |
| `error` | Some other failure (a malformed config file, an unexpected non-200 that isn't a policy block, etc). |

**Exits non-zero if any check's state is `blocked`, `partial-blocked` or `error`** — a legitimately
`skipped` check (no course-map file yet) is not treated as a failure to run. `status.json` in the
run dir carries the same rows machine-readably.

## 7. `x5-overpass` — Overpass OSM coverage

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

## 8. `k1-verdict` — K1 operator + sponsor early-read and full-gate verdicts

```shell
node dist/k1-verdict.js
node dist/k1-verdict.js --as-of 2026-11-15 --out k1-verdict-result
```

The CLI always reads the repo's own `docs/partners/k1-outreach.md` §(g) tracking table — the single
K1 log (decision 0001, Addendum D, R2) — same no-override philosophy as `x1-ios-export`'s round
windows. `--as-of YYYY-MM-DD` (default: today's UTC date) is its only input flag (decision 0001,
Addendum I): it gates both verdicts' pending state and is the ceiling every logged date is checked
against. That table's columns were restructured 2026-09-24 (and got a "Sponsor conversation date"
column 2026-09-24, Addendum I), so every input `k1-verdict` needs is its own column — see the note
above the table in that file, and `src/k1-log.ts`'s strict parser. "Hammock Coast" is accepted as an
alias of the table's own "Hammock Coast Golf Trail" row.

**Two separate verdicts, never merged (decision 0001, Addendum I):**

- **Early read** (Addendum D, R1): count of the 5 named operators whose acceptance of an exploratory
  call is dated on or before **2026-10-19**. Pass ≥ 2. **Before 2026-10-20** this reads `pending (n so
  far)` regardless of the count — the window hasn't closed.
- **Full gate** (Addendum C, cutoff **2026-11-30**): count of the same 5 with a signed non-binding
  LOI (fee willingness recorded) dated on or before the cutoff — pass needs ≥ 2 — **and** ≥ 1 sponsor
  row with all three qualifiers recorded **and** a sponsor conversation date on or before the same
  cutoff — pass needs ≥ 1. **Before 2026-12-01** this reads `pending` regardless of counts. Once
  closed, **operator miss is evaluated before sponsor miss**: `operator-miss` if the operator bar
  isn't met, else `sponsor-miss` if the sponsor bar isn't met, else `pass`.
- A full-gate result is never hidden by an early-read miss, and the reverse is also true — both are
  always computed and reported.
- **Oklahoma Golf Trail** counts only when its "OK swap replaces" cell names one of the 3 slate trails
  (the X2 swap rule activated) — it then replaces that trail in the 5, never a 6th contact (K1.md
  METHOD step 1); a warning fires if the replaced trail's own row already had data logged.

**Date sanity (Addendum I):** every logged date must be on or after **2026-09-23** and on or before
`--as-of` — a later date is refused outright, not just excluded. An acceptance or LOI dated before its
own row's Contacted date is also refused. Dates are plain calendar dates, no timezone conversion.

**Parser strictness (`src/k1-log.ts`):** an unknown operator name, a sponsor row whose name matches a
known operator, a malformed date, an unexpected column layout, a malformed Y/N cell, or a table row
separated from the table by a blank line (rows are never silently dropped) all throw. A blank cell
means "not yet" and is never an error on its own.

**Output:** each verdict's own count/pass/pending state, which entries are late (listed, not counted),
which LOIs lack fee willingness, which sponsor rows are partially qualified, and each verdict's own
verbatim K1.md consequence quote (a pass or a still-pending read has no kill-consequence text to quote;
the tool says so rather than inventing any).

**Feeds:** `earlyRead`/`fullGate` → `docs/p0/K1.md` MEASURED VALUE and VERDICT (as two distinct reads).

## 9. `k3-verdict` — K3 SEO-signal verdict

```shell
node dist/k3-verdict.js
node dist/k3-verdict.js --out k3-verdict-result
```

No input flags: the CLI always reads the repo's own `docs/p0/K3.md`, whose "## Search Console read"
and "## Keyword Planner read" tables (added 2026-09-24, before any read) are its two inputs, alongside
the existing "## SWC Search Console property" memo.

- **Search Console:** the median of the three fixed months' (July/August/September 2026, decision
  0001 Addendum D R4) total organic clicks (Addendum A's method), compared to **M = 1,000**. Refuses
  to run if the property id is blank or doesn't look like a real property (decision 0001, Addendum I —
  must read `sc-domain:<host>` or an `https://` URL-prefix property; a placeholder like "TBD" is
  refused), if the Search Console table's "Read date" cell (Addendum I) is blank or earlier than
  **2026-10-01** (a read that early would lock in a partial September), or if any month's clicks total
  is blank — a blank cell is "not read yet," and the loud-failure contract forbids silently treating
  that as 0 clicks.
- **Keyword Planner:** the sum of the six closed-list terms' (decision 0001 Addendum B) lower bounds,
  compared to **≥ 5,000**, applying Addendum D R5's "identical range counted once" rule exactly: two
  terms that report the identical `(lower, upper)` range contribute that lower bound only once. There
  is no separate "Point value" column (Addendum I) — a point value is entered as `lower = upper`, so
  R5's dedup applies to a shared point exactly as it does to a shared range. Refuses to run if any term
  has no range recorded at all.

**Parser strictness (`src/k3-log.ts`):** an off-list or missing keyword term, an unexpected/missing/
duplicate month or term row, a malformed number, a half-filled range, a lower bound above the upper
bound, a "Read date" recorded on more than one row, or a table row separated from its table by a
blank line (rows are never silently dropped) all throw.

**Output:** both raw numbers, each individual pass/miss against its own bar, the combined branch
(`both-miss` / `disagree` / `both-pass`), and K3.md's Kill-consequence text quoted verbatim (plus the
"P1 proceeds in every case" line, which applies regardless of branch).

**Feeds:** `combinedBranch`/`consequenceText` → `docs/p0/K3.md` MEASURED VALUE and VERDICT.

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

**X2/X4/`p0-desk` coverage** (all fetches go through a stubbed `global.fetch` — `vi.stubGlobal`,
same technique the X5 tests already use — never the real network): HTML text extraction (tags
stripped, whitespace collapsed, script/style/comment blocks removed, inline vs. block element
boundaries per gate S4, quoted-attribute-safe tag matching and unclosed-`<script>` tail-dropping per
gate N3) and DRAFT candidate-name extraction; PDF evidence auto-extracted with the pinned `unpdf`
extractor against a real, deterministically-built PDF fixture (`test/fixtures/pdf/`), never left as
bytes-only or typed by hand (gate S3); magic-byte content classification (gate N5); charset
detection from the header or a `<meta>` tag (gate N4); a failed fetch recorded with the exact error
and never skipped, distinguishing a network-policy block from a genuine site-side failure (e.g.
404); a body that exceeds the size cap, or stalls past the timeout, failing instead of hanging or
silently truncating (gate S6); non-`https:` URLs refused before fetching (gate N6); X2 verdict
cases — quote present / absent / a whitespace-variant quote still matching / a cited SHA with no
matching evidence for that trail refusing outright / a cited SHA belonging to a DIFFERENT trail
refusing outright (gate S2) / an edited stored-text file NOT confirming because the raw bytes are
re-derived at verdict time (gate S1) / a roster name missing from its own cited evidence / a missing
season fact / a too-short quote (gate N8) / a failed source listed and flagged (gate S5) / the 2-of-3
trail boundary; X4's three-way live/not-live/indeterminate outcome (decision 0001 Addendum H) —
a redirect to a different facility id, a match only in the query string, a foreign host, a 200 page
missing the course name (all NOT live); a block/timeout/403/429/5xx (all indeterminate, never not
covered, gate B1); a stale replay refused (gate N1) — and its 80%-per-trail boundary (exactly 80%
passes, just under fails), never computed while any course is indeterminate; and `p0-desk`'s status
board, including the BLOCKED row for a fake fetch that throws a `"CONNECT tunnel failed, response
403"`-shaped error (`net.test.ts` also covers the other observed shape — a resolved 403 response
that IS the proxy's own denial page, vs. one that's the destination site's own 403) and the
PARTIAL-BLOCKED row for a partial failure/indeterminate result (gate S5).

**K1/K3 coverage:** `k1-verdict` — 0/1/2/5 acceptance counts, the early-read cutoff boundary (2026-10-19
counts, 2026-10-20 doesn't), a 6th contact (Oklahoma Golf Trail) NOT counting while its swap is
inactive, the Oklahoma swap correctly replacing its named slate trail in the 5 (with a warning when
that trail's own row had data), an LOI without recorded fee willingness not counting, a sponsor row
missing a qualifier or its conversation date not counting, the full-gate priority (operator miss
evaluated before sponsor miss), the `pending` state at both as-of boundaries (2026-10-19 and
2026-11-30), the probe case where a 0-acceptance early miss coexists with a passing full gate (both
visible, never merged), every consequence branch with its quoted text, date-sanity refusals (before
2026-09-23, after `--as-of`, an acceptance/LOI before its row's Contacted date), the "Hammock Coast"
alias, a sponsor row named after a known operator throwing, and a table row separated from the table
by a blank line throwing (never silently dropped). `k3-verdict` — a blank or malformed ("TBD") property
id refusing, a blank or too-early (2026-09-30) read date refusing, a blank month/term value refusing,
the median computed correctly regardless of input order, Addendum D R5's duplicate-range rule (as
restated by Addendum I) deduplicating an identical range OR an identical point value exactly once, the
5,000 keyword-sum boundary (4,999 misses, 5,000 passes), all three combined branches with quoted
consequence text, and the parser throwing on an off-list or missing keyword term, a
missing/duplicate/unexpected month or term row, a malformed number, a lower bound above the upper
bound, a half-filled range, a Read date recorded on more than one row, and a stray row after the table
ends.
