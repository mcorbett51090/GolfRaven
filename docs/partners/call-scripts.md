# P0 call scripts — SP4, SP5, SP6, SP9

Draft scripts for Matt to run himself. Nothing here has been sent or called. Sourced against
`docs/golf-trails/02-build-plan.md` §9.2 (course-QR onboarding checklist), §10 P0 non-gating work list
("SP4: 3 pro-shop calls … SP5: 2 unique-code-import calls … SP6: the TN public-body email and the RSA
(RTJ) call … SP9: 2 reverse-integration pitches"), and the research files. Facts outside those files are
marked `[unverified]`.

---

## SP4 — Pro-shop calls (run this script 3 times, once per pro shop; also dry-runs the §9.2 onboarding checklist)

**Goal.** Confirm a pro shop can operationally support the course-QR marker-purchase flow (print/display
QR, staff portal sign-in, daily PIN read-out, "Marker sold" tap) and the special-marker stock ledger +
hand-over, before any of this is built. This is a dry run of the checklist in build plan §9.2, not a
sales pitch — the goal is to find out what breaks.

**Questions (7):**
1. Does the shop have a device (tablet, laptop, or phone) at or near the till that could stay signed in
   to a web portal during business hours?
2. Is there reliable Wi-Fi or cellular data at the counter, or is connectivity spotty/none? (Decides
   whether this shop needs the rotating-QR method or the printed-QR + daily-PIN fallback, and whether it
   needs the offline code path at all — §9.2 methods Q1 vs Q2.)
3. Roughly how many ball markers (any brand, not co-branded) does the shop sell in a typical week/month?
4. Who would be the one or two staff members enrolling in a partner portal account (name/role, not
   necessarily contact info on this call)?
5. Would the shop be willing to keep a trail's special/finisher markers behind the counter, record
   deliveries and do a monthly physical count?
6. Does the shop already stock a course-logo ball marker, or would it need to start?
7. Any operational objection to tapping one button ("Marker sold") at each marker sale, or reading a
   4-digit code off a screen when asked?
8. Would you be open to being one of the first shops we test this with, once it's built?

**What a yes/no means for the plan:**
- **Yes on device + connectivity (Q1/Q2)** at ≥ 2 of 3 shops → the rotating-QR (Q1) method is viable as
  the primary method; a "no" at any shop routes that shop to the printed-QR + daily-PIN fallback (§9.2
  Q2), which is weaker but still supported.
- **No connectivity at any shop** → the offline-code seed provisioning cut item (§10 cut list #5) stays
  in scope; do not cut it if any pilot shop reports `connectivity: none`.
- **No to stocking the special marker / doing a physical count** at a shop → that shop either needs an
  `n-of-m` completion exception (cited from the trail's own published rule, O15) or the trail operator
  needs a different shop to hold stock for that course.
- **Overall reluctance/objection to any staff action** at 2+ of 3 shops → a signal that the "one tap"
  claim in the operator pitch (§9.9 outline) needs revisiting before it's used with an operator.

**Notes table (fill in during/after each call):**

| Shop / course | Call date | Device at till? | Connectivity | Weekly marker volume (approx) | Will stock special marker? | Objections | Overall fit |
|---|---|---|---|---|---|---|---|
| Pro shop 1 | | | | | | | |
| Pro shop 2 | | | | | | | |
| Pro shop 3 | | | | | | | |

---

## SP5 — Unique-code-import calls (run this script twice, once per course/tee-sheet vendor)

**Goal.** Confirm whether a course's own tee-sheet or POS system can import N unique single-use codes for
the discount/offer `code-pool` mode (build plan §4.4/§9.5, method C in §9.2's proof-of-purchase table:
"Course-uploaded unique codes … Only where the course's tee sheet or POS can import N unique single-use
codes"). This decides whether that course can use the strongest offer-redemption mode, or falls back to
`portal-verify`.

**Questions (6):**
1. What tee-sheet or POS system does the course use (name/vendor)?
2. Can that system import a list of unique, single-use discount or promo codes from a CSV or similar
   file?
3. If yes — who manages that import (course staff directly, or only the vendor on request)?
4. How would the course confirm a code was actually redeemed (a report, a flag in the POS, nothing at
   all)?
5. Is there a cost or contract change needed to enable code import on this system?
6. Roughly how many discount codes would the course expect to issue in a season (order of magnitude, to
   size the code batch)?

**What a yes/no means for the plan:**
- **Yes, self-service import** → that course/trail can run the `code-pool` mode described in §9.5,
  which needs no app-side redemption UI beyond generating and handing off the code list.
- **Yes, but only via the vendor** → still usable, but adds lead time and a per-batch coordination cost;
  note it so the BD checkpoint (§10) can account for it.
- **No import capability** → that course stays on `portal-verify` (the default mode, §9.5 — "the only
  mode until SP5 is confirmed per course"), which is already the fallback assumption in the plan, so a
  "no" here changes nothing about what gets built, only which courses get the stronger mode later.

**Notes table:**

| Course | Call date | Tee-sheet/POS vendor | Can import unique codes? | Who manages import | Redemption confirmation method | Notes |
|---|---|---|---|---|---|---|
| Course 1 | | | | | | |
| Course 2 | | | | | | |

---

## SP6a — TN public-body email (not a call; drafted as an email per the plan's own framing — "the TN public-body email")

**Goal.** Open a channel with Tennessee State Parks / TDEC for the Tennessee Golf Trail: confirm roster,
logo licensing process, who approves discount programmes at a state-park golf operation, and who runs
the pro shops day to day.

```
Subject: Question about the Tennessee Golf Trail — logo licensing and pro-shop operations

Hello,

I'm building a golf-trail completion tracker (GolfRaven) and I'm researching the Tennessee Golf Trail as
a potential pilot partner. Before I reach out with a formal proposal, I have a few process questions:

1. Who handles logo/brand licensing for third parties referencing the Tennessee Golf Trail name and mark?
2. Is there a standard process for a discount or promotional programme involving Tennessee Golf Trail
   courses, given the public-body procurement context?
3. Are the pro shops at Bear Trace and the other Trail courses run by TDEC staff directly, or by a
   separate concessionaire/operator at each site?
4. Is there someone on your team who handles partnership or sponsorship inquiries I could speak with?

I'm happy to provide more detail on the project by email or on a short call, whichever is easier on your
end.

Thank you,
Matt [Last Name]
[Entity name — TBD]
[Phone] / [Email]
```

**What a yes/no means for the plan:**
- **A response naming a licensing/procurement process** → confirms TN can be pursued as a normal
  operator target; route into the K1 outreach sequence (`k1-outreach.md`).
- **No response, or a response saying discounts/third-party programmes aren't permitted** → TN Golf Trail
  is at risk in the slate; the plan's fallback is Oklahoma (reserve), then Hammock Coast (§9.9).
- **Pro shops run by a separate concessionaire** → SP4's pro-shop calls for TN need to target that
  concessionaire, not TDEC directly, for the operational (device/connectivity/staff) questions.

**Notes table:**

| Sent date | Reply (Y/N/date) | Who replied / role | Licensing process named? | Pro shops: state-run or concessionaire? | Next step |
|---|---|---|---|---|---|
| | | | | | |

---

## SP6b — RSA (RTJ Golf Trail) call

**Goal.** Confirm RSA's willingness to have GolfRaven pitched as an extension of the existing $49.95 Trail
Card (not a competitor), cover logo licensing, discount-board approval, who runs the pro shops, and how
the special-marker programme would attach to Card-holder benefits.

**Questions (8):**
1. Is there interest in a completion tracker that shows a golfer's progress toward playing all 26 RTJ
   courses, positioned as a Trail Card companion, not a competing product?
2. Who at RSA/RTJ approves a change like this — is there a board or committee that reviews third-party
   programmes?
3. Who handles logo/brand licensing for the RTJ mark?
4. Are the 11 course pro shops run by RSA staff directly, or by a mix of operators per site?
5. Would RSA want the special finisher marker to be a Trail Card-holder-only reward, or open to any
   completer?
6. Is there appetite to report Trail Card sales at pilot sites before/during a pilot season, so we can
   both watch for any cannibalization effect (R32 in the build plan) directly rather than guessing?
7. Would RSA want to author its own discount offers in the app (so nothing undercuts Trail Card
   pricing), or prefer no discounts at all initially?
8. Is a 20-minute follow-up call, or a written one-pager, the better next step?

**What a yes/no means for the plan:**
- **Interest confirmed, no objection to Card-companion framing** → proceed to LOI outreach
  (`k1-outreach.md`); RTJ stays in the slate per O4.
- **Concern about cannibalizing Trail Card sales** → do not push past this call; note it as evidence for
  risk R32 and consider narrowing the pitch (e.g., marker-only, no discounts) before a second call.
- **Pro shops run per-site by different operators** → SP4 pro-shop calls for RTJ need per-site
  coordination, not one blanket RSA sign-off.
- **No interest / no response** → RTJ is the largest slate trail by course count; its loss moves
  Oklahoma from reserve into the slate per the plan's fallback order (§9.9).

**Notes table:**

| Call date | Contacted (name/role) | Interest (Y/N) | Cannibalization concern raised? | Pro-shop ownership model | Next step |
|---|---|---|---|---|---|
| | | | | | |

---

## SP9 — Reverse-integration pitches to golf apps (run this script twice, once per app)

**Goal.** Pitch an existing golf-tracking app (e.g. one from `research/passports-loyalty.md`'s comparison
table — Golfed, CourseVaults, TheGrint, 18Birdies, GolfN) on a **reverse integration**: they surface
GolfRaven trail-completion data or deep links inside their own app, rather than GolfRaven building
duplicate GPS/round-tracking infrastructure. This tests whether a distribution partnership is viable as
an alternative or complement to building the tracking stack in-house.

**Questions (6):**
1. Does your app currently support any form of "trail" or multi-course challenge concept, or would this
   be new for you?
2. Would you be open to a partner integration where a golfer's round data (course + date, already
   captured by your app) contributes toward a GolfRaven trail's completion count, via an API or export?
3. What would that require from your side — an API you already expose, or new development?
4. Is there a business-development or partnerships contact who owns integration decisions like this?
5. Would attribution (e.g. "tracked via GolfRaven, verified in [App]") be acceptable, or would you want
   the relationship framed differently?
6. Roughly what timeline would a conversation like this move on — weeks, months, not at all right now?

**What a yes/no means for the plan:**
- **Real interest + an existing exportable API** → a candidate integration partner for reducing the
  build cost of course-matching/GPS ingestion (see `research/golf-app-sync.md` — most third-party apps
  have no public read API today, so a "yes" here would be a meaningful exception worth prioritizing).
- **Interest but no API today** → log as a future partnership, not a P0/P1 dependency; nothing in the
  plan currently assumes this integration exists.
- **No interest** → no change to the plan; GolfRaven's own HealthKit/Health Connect + course-QR lanes
  (build plan §9.2, `research/golf-app-sync.md` §b) remain the primary path regardless.

**Notes table:**

| App | Call date | Contact (name/role) | Has exportable API today? | Interest level | Next step |
|---|---|---|---|---|---|
| App 1 | | | | | |
| App 2 | | | | | |
