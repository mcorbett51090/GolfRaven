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
