# P0 status board — GolfRaven

Source of truth for thresholds and rulings: `docs/golf-trails/02-build-plan.md` §10 P0 (v6) and
`docs/decisions/0001-owner-decisions-and-p0-thresholds.md`. This board is derived from those two files;
it never states a number they don't already state.

## The 11 gating verdicts (P0 *is* the gate — plan §10 P0)

| ID | Check | Owner (who runs it) | Status | Verdict |
|---|---|---|---|---|
| X1 (=K4a) | Health real-device test (3 iOS sources + Android pass) | Matt (physical rounds, borrowed devices) | OWNER — needs borrowed devices + real rounds | _(blank)_ |
| X2 | Direct-fetch pilot-slate rosters/rules (TN, VI, RTJ) | Agent, once unblocked | BLOCKED — network policy (`tnstateparks.com`, `tngolftrail.net`, `golfvancouverisland.ca`, `rtjgolf.com`, `tn.gov`); unblock in the environment's Network access settings, then an agent runs it | _(blank)_ |
| X3 | SWC source host | Agent | **CLOSED — PASS 2026-09-23** | **pass** |
| X4 | GolfNow facility-page coverage of pilot courses | Agent, once unblocked | BLOCKED — network policy (`golfnow.com`); unblock in the environment's Network access settings, then an agent runs it | _(blank)_ |
| X5 | Overpass OSM polygon / `golf=hole` coverage | Agent, once unblocked | BLOCKED — network policy (`overpass-api.de`); unblock in the environment's Network access settings, then an agent runs it | _(blank)_ |
| X6 | GolfNow ToS + partner-API docs | Agent, once unblocked | BLOCKED — network policy (`golfnow.com`, `affiliate.gnsvc.com`); unblock in the environment's Network access settings, then an agent runs it | _(blank)_ |
| X7 | PostGIS point-in-polygon benchmark | Agent, once the Supabase project exists | OWNER — needs the Supabase project (P0 account step); benchmark kit ready (`docs/owner/x7-postgis-benchmark.sql`) | _(blank)_ |
| K1 | Operator + sponsor signal | Matt (outreach/relationship calls) | OWNER — needs direct operator/sponsor outreach; an agent cannot run these calls. **Ready to send:** 9 unsent drafts (5 operators, 4 sponsors) are in Matt's Gmail, built from `docs/partners/k1-outreach.md`; each opens with a delete-before-sending note. The pre-registered dates (2026-10-05 window opens, 2026-10-19 early-read cutoff, 2026-11-30 LOI window closes, ≈ 2026-12-14 verdict) are on his Google Calendar as all-day holds | _(blank)_ |
| K2 | Player signal (organic landing page) | Matt (promotion through his own channels) | DEFERRED — decision 0002: deploy at the last responsible moment (day 0 no later than planned P4.2 start − 7 weeks); gates P4.2 only | _(blank)_ |
| K3 | SEO signal (SWC Search Console + Keyword Planner) | Matt (account access) | OWNER — needs Matt's SWC Search Console access and a Google Ads account, then Keyword Planner reads (`docs/owner/k3-seo-reads.md`) | _(blank)_ |
| K4 | Sync signal = X1 **or** K4b | Matt (physical devices) | OWNER — needs borrowed devices + real rounds (K4 = X1 OR K4b; see `X1.md` and `docs/owner/x1-k4b-device-protocol.md`) | _(blank)_ |

Each `docs/p0/<ID>.md` memo carries the check verbatim, its pre-registered pass bar and kill consequence
verbatim, the method, the owner split, and a dated log. **X3 is closed (PASS, 2026-09-23)** with a
measured value and verdict recorded. The other 10 of the 11 checks have not been run and their memos are
still blank.

## Non-gating P0 work (plan §10 P0, "Non-gating work, in parallel")

| Item | Owner | Status |
|---|---|---|
| X8 — marker vendor quotes (MOQ, unit cost, lead time) | Matt | PENDING — not started |
| Test devices, borrowed first (≥2 current Garmin golf watch models, Apple Watch + iPhone, Android + Health Connect), by day 5 | Matt | PENDING — see `docs/owner/x1-k4b-device-protocol.md` |
| Domain registration (`golfraven.com` preferred; `.golf`, `.ca` held where cheap) | Matt | PENDING — see `docs/owner/accounts-and-domain-checklist.md` |
| Legal entity / D-U-N-S number (O20: Matt's existing operating entity; D-U-N-S applied for if not already held) | Matt | PENDING |
| Apple Developer **organisation** account (under the operating entity) | Matt | PENDING |
| Google Play **organisation** developer account (under the operating entity) | Matt | PENDING |
| Sign in with Apple service id + key (under the organisation Apple account) | Matt | PENDING |
| Google OAuth client (under the organisation Google account) | Matt | PENDING |
| Custom SMTP (Postmark/SES) on the P0 domain with SPF/DKIM/DMARC | Matt | PENDING |
| Bundle IDs reserved (iOS + Android) | Matt | PENDING |
| Applications with dated receipts: GolfNow T1 + business form, Lightspeed, GHIN GPA, Arccos, Garmin waitlist + Golf API BD email, Supreme Golf (applicant = P0 legal entity) | Matt | PENDING — drafts ready in `docs/partners/applications.md`; none filed yet, no dated receipts |
| Counsel brief L1–L7 and L-OSM | Matt (retains counsel) | PENDING — see `docs/owner/counsel-brief.md` |
| SP10 — `passport_mark` event in SWC (~1 h build; needs owner approval before it ships) | Agent (build), Matt (approval) | PENDING — approval not yet given |
| K2 signup backend — prerequisite for K2 day 0 | Matt (deploy) | BUILT and gated (golfraven PR #2, `apps/signup-worker`); deploy deferred per decision 0002 — runbook in `apps/signup-worker/README.md` |

## P0 exit rule (plan §10 P0 acceptance tests + §15 P0 DoD)

1. **All gating verdicts are written**, each with its measured value quoted against its numeric threshold — **10 of 11**: K2 is deferred by decision 0002 and gates P4.2 only (its deploy deadline is tracked in `docs/p0/K2.md`).
2. Every application has a dated receipt.
3. `pnpm -r build` passes on the skeleton in CI.
4. **Any kill verdict has an owner-signed replan note** before P1 starts.
5. The organisation store accounts exist in the operating entity's name (or their pending status is dated).
   The domain-resolves and DMARC checks move with the K2 deploy (decision 0002) and are met before K2 day 0.
6. The P0 DoD carries a `/security-review` report and Matt's recorded self-attestation (O22).

A kill on any one of the 11 checks means: **replan before P1** (plan §10 P0 Scope: "A kill on any one → replan
before P1.").
