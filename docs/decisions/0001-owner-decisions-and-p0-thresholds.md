# 0001 — Owner decisions (2026-09-23) and P0 thresholds, fixed before any data is read

- **Status:** Accepted
- **Date:** 2026-09-23 (P0 start of work; the plan's calendar assumes P0 starts 2026-10-05 — work began early, which moves nothing)
- **Decider:** Matt (owner)
- **Source:** `docs/golf-trails/02-build-plan.md` v6 §14 (all rows DECIDED) and `docs/golf-trails/00-scope.md` A1–A23 in the RavenGolf repo

## Why this record exists before anything else

The plan requires the K1–K3 demand thresholds to be **fixed in writing before any of their data is opened**
(§10 P0, O7, G-P0-01). This file is committed before any K1 reply, K2 signup count, or K3 Search Console /
Keyword Planner number has been read. Its git commit timestamp is the evidence. Changing a threshold after
data is read requires a new decision record that says so and why.

## P0 thresholds (verbatim from plan v6 §10 P0; O7 DECIDED "keep as written")

| Gate | Early read | Full gate | Kill → consequence (summary; full text in the plan) |
|---|---|---|---|
| **K1** operator + sponsor | ≥ 2 of 5 operators accept an exploratory call within 2 weeks | ≥ 2 of 5 operators sign a non-binding LOI with willingness to pay the per-season programme fee within 8 weeks (verdict ≈ wk 10), **and** ≥ 1 qualified sponsor conversation (named decision-maker, stated season budget range, interest in special-marker attribution) | Early 0–1/5 → replan before P1. Operator miss → P5/P6 do not start; app launches as directory + tracking + badges. Sponsor miss only → programme proceeds operator-funded |
| **K2** player (organic, $0) | ≥ 100 confirmed double-opt-in signups by day 14 — **advisory only** | ≥ **N = 300** confirmed signups in 6 weeks (verdict ≈ wk 7) | Full miss → P4.2 held for an owner decision: one paid 2-week re-test at the same N (≈ $1,000), or replan |
| **K3** SEO (proxy) | — | southern-wine-country organic clicks ≥ **M = 1,000/month** (90-day median) **and** golf-trail keyword volume ≥ **5,000/month** combined (range lower bound) | Both miss → directory is a partner asset, not a growth engine. Disagree → growth engine on probation, re-read 6 months after M1 |
| **K4** sync | — | X1 passes **or** K4b passes | Both fail → written owner escalation before P1: "sync with Garmin" means file import + one-tap watch check-in + "Open in" links |

Technical checks X1–X7 keep the pass bars in plan §10 P0 unchanged; each memo in `docs/p0/` quotes its bar.

## Owner decisions in force (plan §14, all DECIDED 2026-09-23)

| # | Decision |
|---|---|
| O1 | Product name **GolfRaven**; primary domain registered in P0 (`.com` preferred; `.golf`, `.ca` held where cheap) |
| O2 | One pnpm-workspace monorepo `golfraven` |
| O3 | No anonymous web passport; the site shows a "track in the app" CTA |
| O4 | Pilot slate: Tennessee Golf Trail, Vancouver Island Golf Trail, Robert Trent Jones Golf Trail; Oklahoma reserve |
| O5 | Any pro-shop marker counts; each course has a QR the golfer scans (rotating signed token or printed QR + daily PIN), always with the app's presence fix |
| O6 | Solo / 1–2 people, no fixed season; event-driven milestones; 30 h/week, 1.0–1.5× agent uplift (A71) |
| O7 | K thresholds as above |
| O8 | Private clubs listed **and** counted toward completion |
| O9/O10 | No shipping; each trail's special marker is stocked at member pro shops and handed over in person |
| O11 | Payers: operator per-season programme fee **and** sponsor-funded prizes |
| O12 | Sign-in: email OTP + Sign in with Apple + Google |
| O13 | New GTM/GA4 container, same PII allow-list gate |
| O14 | Leaderboards later (P9), opt-in |
| O15 | Completion = all courses per the trail's published rule |
| O16 | Templated commercial "trails" listed as unverified checklists |
| O17 | App ships independently of partner signings |
| O18 | Minimum age 16+ (pending counsel L7) |
| O19 | Special marker requires purchase **and** play at every course |
| O20 | Matt's existing operating entity is applicant and merchant of record (US + CA) |
| O21/O25 | Verification trade-offs accepted as defaulted |
| O22 | Solo until the P3 pre-build gate names a second admin and external reviewer |
| O23/O24 | $0 promotion, borrowed devices; upgrade path ≈ $2,500 |

## Working rules adopted 2026-09-23 (not in the plan)

- **Model tiers for agent work:** Opus/Fable only for gates (critic, red-team, verdict and security reviews
  that hold a phase). Sonnet for everything else.
- **Monorepo staging:** the GitHub integration could not create the `golfraven` repository (`403 Resource not
  accessible by integration`). The monorepo is staged under `golfraven/` in the RavenGolf repo and moves to its
  own repository with history (`git subtree split --prefix=golfraven`) once the owner creates it.

## Addendum A (2026-09-23, before any K3 data is read) — K3 median method

The plan says "90-day median" without saying how to group the days. The method is fixed here so it cannot be
chosen after the numbers are visible: **take the three most recent complete calendar months before the read
date, total organic clicks for each, and use the median of those three monthly totals.** Partial months are
excluded. The keyword-volume check uses the lower bound of each Keyword Planner range, summed across the
keyword list in `docs/owner/k3-seo-reads.md`.

## Addendum B (2026-09-23, before any K3 data is read) — K3 keyword list and X7 measurement

### K3 keyword list (closed, fixed before any data is read)

The keyword list is **exactly these six terms**, and no others, in every K3 read:

1. `golf trail`
2. `golf trails`
3. `robert trent jones golf trail`
4. `tennessee golf trail`
5. `vancouver island golf trail`
6. `oklahoma golf trail`

Rules, fixed now and not revisitable once any volume has been read:

- **English only.** No French terms, regardless of Québec relevance.
- **Exact-match volume only**, via Google Keyword Planner's **"Get search volume and forecasts"** tool (not
  "Discover new keywords", which returns Google's own suggested/related terms rather than a volume for the
  fixed list above).
- **Each term's Avg. monthly searches uses the range's lower bound** (per Addendum A / O7), and the six lower
  bounds are **summed** to get the combined golf-keyword volume figure compared to the ≥ 5,000/month bar.
- **No additions after data is read.** The "Optionally any other trail names … worth checking" and "if
  material" French-terms language in the plan draft and in `docs/owner/k3-seo-reads.md` is superseded by this
  closed list — nothing may be added to reach the threshold once any number has been seen.
- **Search Console search type is pinned to Web** (not Image, Video, News or Discover) for the SWC Part A read
  in the same file, so that check is equally closed before data is read.

This closes B2 in the P0 gate review (2026-09-23): the keyword list was open-ended and would have let whoever
read the numbers add terms until the combined sum reached the bar.

### X7 measurement (in-database p95, mixed hit/miss point set)

Pre-registering, before any X7 run is treated as the recorded result:

- **p95 is measured in-database**, as server-side execution time, not client round trip and not end-to-end
  from the Edge Function region. Each of 1,000 point-in-polygon queries is timed with `clock_timestamp()`
  inside a PL/pgSQL loop (equivalently, per-query `EXPLAIN ANALYZE` execution time), and p95 is computed with
  `percentile_cont(0.95)` over the 1,000 timings.
- **The query points are generated so that roughly half fall inside a polygon and half do not**: for half the
  points, sample a random polygon and draw a point from its interior (e.g. `ST_PointOnSurface`, optionally
  combined with `ST_GeneratePoints(geom, 1)`); for the other half, draw uniformly random points across the
  overall bounds. This replaces the prior all-random-over-bbox generation, which produced a 0% hit rate and so
  measured only the empty-index-probe path.
- **The query point is bound once per iteration** (a parameter or a value materialised before the timed call),
  never `random()` evaluated inside the predicate — so the query plan actually exercises the GiST index
  (`course_polygon_gix`) the same way on every timed call, and the recorded `EXPLAIN` text matches what the
  benchmark script itself runs.
- **Pass bar stays p95 < 100 ms** (plan §10 P0, unchanged by this addendum).
- **Report the hit rate (points that matched a polygon ÷ 1,000) alongside p95** in `x7-postgis-benchmark.md`,
  so the recorded number is legible as "p95 over a realistic mixed workload", not "p95 over an empty probe".

This closes S1 in the P0 gate review (2026-09-23).

## Addendum C (2026-09-23, before any K1 reply is read) — K1 8-week anchor and denominator

The plan's Check text gives the full-gate window as "within 8 wk" without saying what it is measured from, and
K1's own working memo had informally anchored it to "first contact" (an addition not in the plan). Fixed here,
before any operator reply is read:

- **The 8-week window is anchored to the plan's P0 start date, 2026-10-05** (plan §10 conventions), so the
  full-gate window closes on **2026-11-30** and the verdict is read around week 10 (≈ 2026-12-14), matching the
  plan's schedule. It is **not** anchored to this record's date (work began early on 2026-09-23, before any
  outreach was sent, which must not shorten the window) and **not** to each operator's individual first-contact
  date (which would let a late contact extend the window).
- **The denominator is the 5 operators the Check text requires to be contacted**: the three pilot-slate trail
  operators (TN Golf Trail, Vancouver Island Golf Trail, Robert Trent Jones Golf Trail) plus the ≥ 2 co-op/DMO
  warm reserves contacted to satisfy "Contact ≥ 5 operators". If more than 5 are contacted, the denominator is
  the **first 5 contacted, in the order logged in the K1 tracking table** (`docs/partners/k1-outreach.md`),
  whether or not they reply. The same 5 are the early-read denominator. It is never "≥ 2 of however many
  operators are ultimately contacted".

This closes S2 in the P0 gate review (2026-09-23).

## Update (2026-09-23) — repository created and monorepo moved

The owner created the `golfraven` repository. The staged monorepo was moved here with history via
`git subtree split --prefix=golfraven` and merged onto the repository's initial commit; the staging copy and
its CI workflow were removed from RavenGolf. The "Monorepo staging" rule above is therefore closed.

## Addendum D (2026-09-23, before any K1 outreach, K2 launch, K3 read or X1 round) — remaining read rules

The P0 gate re-verification (`docs/p0/gate-reverify.md`, R1–R6) found six places where a reading rule could
still be chosen after its data is visible. Each is fixed here, before that data exists. None of the pass bars
changes.

**R1 — K1 early-read window.** The early read counts operators whose acceptance of an exploratory call is
**dated on or before 2026-10-19** (P0 start 2026-10-05 + 14 days), whenever the call itself takes place.

**R2 — K1 denominator, named now.** The five operators are: **Tennessee Golf Trail, Vancouver Island Golf
Trail, Robert Trent Jones Golf Trail, Hammock Coast, Canadian Rockies Golf Consortium.** Ties in contact order
do not matter because the five are named. The Oklahoma Golf Trail counts only if the plan's X2 swap rule
activates it as the slate reserve, and it then replaces the dropped slate trail, never a co-op. The single K1
log is the tracking table in `docs/partners/k1-outreach.md` §(g). Early read and full gate use the same five.

**R3 — K2 day 0 and counting.** Day 0 is the UTC date on which the landing page is publicly reachable **and**
its double-opt-in backend has delivered a confirmation email end to end. Matt logs that date in `docs/p0/K2.md`
before any promotion. The clock is never restarted. The count is distinct lower-cased email addresses whose
`confirmedAt` falls before day 0 + 14 days (advisory read) and before day 0 + 42 days (gate). Owner and test
addresses are excluded only if listed in `docs/p0/K2.md` before day 0.

**R4 — K3 Search Console months.** The months are fixed: **July, August and September 2026**. The property is
southern-wine-country's Search Console property (Matt records its exact property id in `docs/p0/K3.md` before
opening the report). Search type **Web**, all countries, all devices. The first read performed is the recorded
one. There are no re-reads.

**R5 — K3 Keyword Planner read.** Tool: Keyword Planner → "Get search volume and forecasts" → the historical
metrics view. Location: United States and Canada. Language: English. Date range: **September 2025 – August
2026**. Metric: "Avg. monthly searches", using the lower bound of each reported range. The tool reports
keyword-level volume and may fold close variants together, so Addendum B's "exact-match only" wording is
replaced by this: **if two of the six terms return the identical range, count that range once.** The rest of
Addendum B's list and rules stand.

**R6 — X1 route rule and the phone app.** On Android, a session reported as `CONSENT_REQUIRED` counts as
"route present" only if a follow-up `requestExerciseRoute` for that session returns at least one point.
Otherwise it counts as "not present". The phone golf app is **18Birdies**. If, before the round, 18Birdies
cannot be installed or offers no Apple Health / Health Connect write setting, **Hole19** replaces it, and the
reason is logged in `docs/p0/X1.md` before the round. Any other app tried is supplementary data, never the
source verdict.

## Addendum E (2026-09-23, before any X5 query is run) — X5 denominator for facility- and hole-unit trails

`docs/p0/X5.md` pre-registers the match rule and the `course`-unit denominator (one entry per course, even when
several courses share one facility polygon). It does not say how `facility`- and `hole`-unit trails enter the
denominator. Fixed here, before any Overpass data is read:

- **`completionUnit = facility`:** one denominator entry per facility (grouped by `facilityId` from X2). The entry
  is covered if at least one course at that facility matched a `leisure=golf_course` polygon under X5.md's match
  rule. A course with no `facilityId` is its own facility.
- **`completionUnit = hole`:** one denominator entry per course, exactly as for `course`. `golf=hole` coverage is
  recorded as a quality measurement only and never enters the pass/fail denominator.
- The 60% bar is computed over the combined denominator across the pilot slate. These rules are implemented in
  `tools/p0` (`x5-overpass`) and cited there.

## Addendum F (2026-09-23, before any X1 round, X5 query or K2 count) — read rules found open by the round-3 gate

`docs/p0/gate-round3.md` found reading rules that the tools had to choose on their own. Each is fixed here before
its data exists. No pass bar changes.

**X5 match rule, made exact.** A `leisure=golf_course` way **or relation** (outer-ring geometry) matches a
pilot-candidate course when either (a) the course's known point lies inside the polygon, or (b) the names match
**and** the shortest distance from the course's point to the polygon is ≤ 500 m, where a point inside the polygon
has distance 0. Names match when, after normalisation (Unicode NFKD, diacritics removed, lower-cased, every
character that is not a letter or digit replaced by a space, whitespace collapsed), the OSM name equals the course
name, or contains the course name as a whole-word sequence. No other normalisation, abbreviation list or fuzzy
matching is applied.

**X5 run integrity.** An Overpass `remark` error, a missing or unparseable response for any course, or an empty
course list stops the run with a non-zero exit. It never counts as "unmatched". Every live response is saved
alongside the result so the verdict can be replayed offline.

**X1 "on ≥ 1 OS".** X1 passes only if there is **one** operating system on which at least 2 of the 3 sources
write golf workouts with routes. Sources that pass on different operating systems do not combine. (A user syncs
from one phone, so this is the reading that predicts what a user gets.)

**X1 round window.** Before the export is read, Matt logs in `docs/p0/X1.md` the start and end time (UTC) of each
test round. Only workouts whose start time falls inside a logged round window, with 60 minutes of slack either
side, count. Older workouts on the device are ignored.

**K2 exclusion dating.** An address is excluded if it **first appeared** in `docs/p0/K2.md` in a commit whose
**committer** time is before day 0 00:00 UTC, found from the file's full history (`git log -S`), so later
reformatting or deletion does not change it. The count refuses to run in a shallow clone. Known limit: git
timestamps can be set by whoever makes the commit; the protection is that exclusions are pushed to GitHub before
day 0, which leaves a server-side record Matt can check.

## Addendum G (2026-09-23, before any X2 or X4 fetch) — X2 confirmation rule and X4 scope

**X2 "confirmed from a direct fetch".** Every page used is fetched directly and stored as evidence: the raw
bytes, the final URL after redirects, the HTTP status, the retrieval time (UTC) and a SHA-256 of the bytes. A
slate trail counts as confirmed only when all three of its facts — the roster, the `completionUnit` and the
season window — are backed by quotes that appear **verbatim** (after whitespace collapsing) in the text of that
stored evidence, and every roster entry's name appears in it. A fact supported only by a research-file snippet,
or by a quote not found in the stored evidence, leaves the trail unconfirmed. X2 passes when at least 2 of the
3 slate trails are confirmed (plan bar, unchanged).

**X4 scope and "live page".** X4 is evaluated **per trail**: each slate trail is its own pass (≥ 80% of its X2
roster courses have a live GolfNow facility page) or kill (course-native links become that trail's primary
booking link). The X4 row records every trail's result; no combined figure decides anything. A facility page is
**live** when a GET of `https://www.golfnow.com/tee-times/facility/<id>-<slug>/search` returns HTTP 200, the
final URL after redirects still contains `/tee-times/facility/<id>-`, and the page text contains the course's
name under Addendum F's name normalisation. Facility ids are looked up by hand on golfnow.com (the X4 memo's
method); no tool automates GolfNow search while the X6 terms read is outstanding.

## Addendum H (2026-09-24, before any X4 fetch) — X4 indeterminate results

A GolfNow facility-page check has three outcomes, not two:

- **Live** — as Addendum G defines it (HTTP 200; host `www.golfnow.com`; the final URL's path contains
  `/tee-times/facility/<id>-` for the **same** `<id>` that was requested; course name present under Addendum F).
- **Not covered (definitive)** — the course has no facility URL recorded, or the request returns HTTP 404 or
  410, or it resolves (HTTP 200) to a page that is not live: a different facility id, a generic search page, a
  foreign host, or the course name absent.
- **Indeterminate** — a network-policy block, a timeout, a connection error, HTTP 403, 429 or any 5xx, or any
  other status not listed above.

A trail's X4 verdict is computed only when **none** of its courses is indeterminate. Otherwise the trail's
result is "not run — indeterminate (n courses)" and the check is retried; an indeterminate course is never
counted as not covered. The runner exits non-zero whenever any trail is indeterminate.
