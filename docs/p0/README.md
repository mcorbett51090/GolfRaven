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
| K1 | Operator + sponsor signal | Matt (outreach/relationship calls) | OWNER — needs direct operator/sponsor outreach; an agent cannot run these calls | _(blank)_ |
| K2 | Player signal (organic landing page) | Matt (promotion through his own channels) | OWNER — needs landing-page promotion through the owner's own networks/social accounts; an agent cannot post as Matt | _(blank)_ |
| K3 | SEO signal (SWC Search Console + Keyword Planner) | Matt (account access) | OWNER — needs Matt's SWC Search Console access and a Google Ads account, then Keyword Planner reads (`docs/owner/k3-seo-reads.md`) | _(blank)_ |
| K4 | Sync signal = X1 **or** K4b | Matt (physical devices) | OWNER — needs borrowed devices + real rounds (K4 = X1 OR K4b; see `X1.md` and `docs/owner/x1-k4b-device-protocol.md`) | _(blank)_ |

Each `docs/p0/<ID>.md` memo carries the check verbatim, its pre-registered pass bar and kill consequence
verbatim, the method, the owner split, and a dated log. No memo in this directory has a measured value or
verdict filled in yet — none of the 11 checks has been run.

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
| Applications with dated receipts: GolfNow T1 + business form, Lightspeed, GHIN GPA, Arccos, Garmin waitlist + Golf API BD email, Supreme Golf (applicant = P0 legal entity) | Matt | PENDING — none filed yet (`docs/partners/applications.md` not yet created) |
| Counsel brief L1–L7 and L-OSM | Matt (retains counsel) | PENDING — see `docs/owner/counsel-brief.md` |
| SP10 — `passport_mark` event in SWC (~1 h build; needs owner approval before it ships) | Agent (build), Matt (approval) | PENDING — approval not yet given |

## P0 exit rule (plan §10 P0 acceptance tests + §15 P0 DoD)

1. **All 11 gating verdicts are written**, each with its measured value quoted against its numeric threshold.
2. Every application has a dated receipt.
3. `pnpm -r build` passes on the skeleton in CI.
4. **Any kill verdict has an owner-signed replan note** before P1 starts.
5. The GolfRaven domain resolves, SMTP passes a DMARC check, and the organisation store accounts exist in
   the operating entity's name (or their pending status is dated).
6. The P0 DoD carries a `/security-review` report and Matt's recorded self-attestation (O22).

A kill on any one of the 11 checks means: **replan before P1** (plan §10 P0 Scope: "A kill on any one → replan
before P1.").
