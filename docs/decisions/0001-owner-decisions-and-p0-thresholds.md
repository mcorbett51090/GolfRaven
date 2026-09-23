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
