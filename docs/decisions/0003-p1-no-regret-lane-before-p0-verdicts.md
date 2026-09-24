# 0003 — Start a no-regret slice of P1 before the P0 verdicts land

- **Status:** **Proposed** (Matt has not decided). Nothing in this record is built until Matt accepts it. To
  accept, change this line to `Accepted`, fill in the Decider line, and merge.
- **Date:** 2026-09-24
- **Decider:** _(blank until accepted)_
- **Amends, if accepted:** plan §10 P1 "Pre-build gates" ("P0 all-pass, or its replan is signed") and the way
  ruling C7 ("gating P1") applies, **only** for the lane defined below.

## Why this is on the table

Most of P0's calendar is external clocks, not builder work:

- K1's full gate is read around 2026-12-14.
- X1 and K4b need borrowed devices.
- X2, X4, X5, X6 and X7 wait for the network to be unblocked, then for p0-desk.
- K2 is deferred (decision 0002).

Every desk tool P0 needs is already built and merged, so the build lane has nothing to do for about ten weeks.
P1 is 10.75 pw. Some of it depends on no assumption that P0 tests. Starting that part now shortens P1 without
betting on any P0 result.

C7 exists so that no P1 engineering relies on a load-bearing assumption before that assumption has a pass/kill
signal. The test for this lane is exactly that: **for each of the 11 checks, does any pre-written kill
consequence change what this lane builds?** If the answer is "no" for all 11, the lane is outside what C7
protects against.

## The lane (S): a pre-freeze contract draft, with no data and no network

Everything in S stays at `CONTRACT_VERSION = 0`. It is unfrozen and unpublished, and no production ID is minted,
so every piece is a two-way door until the M-freeze.

| # | Work | Plan reference |
|---|---|---|
| S1 | `packages/catalog`: the §4.1 Zod schema as a **draft** (facility, course, trail, roster version with its own unit and rule parameters, `tz`, verification tiers, `composite`, `anyOf` members, `access`), plus JSON Schema generation (`verify-contract`) | P1 scope; §4.1 |
| S2 | `verify-catalog` run against **synthetic fixtures only**: the AT(1) must-fail / must-pass list **minus** the OSM-provenance rows (see "Excluded"); the slug-collision rule, AT(7); the ID-ledger mechanics (duplicate/reused id, tombstones, `mergedInto`) | P1 AT(1), AT(7) |
| S3 | `packages/rules`: completion evaluation and the §8.2 completion fixtures (AT(6)), **excluding the marker-rule fixtures**; the `RuleExpr` checker with R-F1–R-F7 must-fail and R-01–R-14 must-pass | P1 AT(1), AT(6); §8.1, §8.2 |
| S4 | Artifact signing: Ed25519 per-`kid` sign/verify, tampered-shard failure, `revokedKids[]` refusal (AT(2)), using **throwaway dev keys only**. The P3 gate already revokes every pre-P3 `kid` (§3.5) | P1 AT(2) |
| S5 | The unit-mechanics fixtures of AT(3): a 26-course / 11-facility marker-roster shape, an 18-hole hole-unit shape, and a 27-hole composite. They are **labelled as fixtures, not trail data** | P1 AT(3) |

Estimated size: about 3 of P1's 10.75 pw. `[inference — the estimate is not measured]` Agents build it, and each PR
merges on green CI. Under §10, agents never count as a reviewer, so merges rest on Matt's standing "merge when
green" instruction and the CI gates, as every pre-P3 PR does.

## Invariance: each P0 check's kill consequence, and its effect on S

| Check | Kill → pre-written consequence (plan §10 P0) | Effect on S |
|---|---|---|
| X1 (=K4a) | Health lane ships date-only; store copy drops "GPS match" | None. It is a mobile/P4 lane, and S holds no sync code |
| X2 | Swap in the reserve trails (OK, then Hammock Coast / Kauai) | None. S holds no trail data, and the S5 shapes test unit mechanics whichever trails are in the slate |
| X3 | Closed, PASS 2026-09-23 | — |
| X4 | Course-native link becomes primary for that trail | None. That is a per-trail data choice. S2's booking-host rule runs against a fixture allow-list and already covers the course-native rule (host = facility domain) |
| X5 | Before P1, choose manual polygons or Alt-5 (a licensed feed) | **This is why the OSM rows are excluded.** No geometry, seeding or OSM provenance is in S. If Alt-5 is chosen, the draft `prov` enum gains a value, which is a free change before the freeze |
| X6 | T0 is course-native only until counsel L4 clears | None. It concerns P2 linking |
| X7 | Server-side spatial queries dropped; dispute replay stays in TS | None. S has no Supabase work. The TS-only fallback is the path S already sits on |
| K1 early (0–1/5) | Replan before P1. Partner programme paused. P1–P4 proceed as directory + tracking + badges only if K2 and K3 allow | S is the directory + tracking + badges core, and it excludes marker evaluation. **Residual:** if the replan stops P1 entirely, S's effort is lost. Nothing else is (see "The one real risk") |
| K1 full | P5/P6 do not start; the programme is off on every trail | None. Marker evaluation is excluded. The schema's optional marker fields cost nothing if left unused |
| K2 | Deferred (0002). A kill holds P4.2 only; "P1 is not held" | None |
| K3 | Directory re-scoped or put on probation; **"P1 proceeds in every case"** | None |
| K4 | Garmin written statement; no automatic sync at launch | None. It is a mobile lane |

## Excluded: still waits for P0 all-pass or a signed replan, exactly as the plan says

- **OSM-dependent work (X5, counsel L-OSM):**
  - OSM seeding;
  - stub minting (AT(5), AT(8));
  - the geometry pipeline;
  - the ODbL layer split;
  - the OSM-provenance fixtures in AT(1).
- **Anything in `data/`:**
  - pilot rosters (X2; "never by a snippet");
  - the designer registry;
  - directory entries.
- **Marker-rule evaluation and its fixtures** (K1).
- **The Supabase import function** (AT(4)) and anything that needs an account or the network.
- **The booking allow-list's real contents** (X4, X6).
- **The M-freeze itself.** It is the one-way door, and it stays behind P0 exactly as written.

## Stop rule (fixed now, before any verdict is read)

- If **any** P0 kill verdict is written while S is in progress, S pauses at its next merge. The owner-signed
  replan note for that kill must say which S items survive before S resumes.
- S never sets `CONTRACT_VERSION` above 0, never writes to `data/`, and never publishes an artifact. A PR that
  does any of these is out of scope under this record and fails review.

## The one real risk

The residual is **sunk effort, not a wrong design**. After a K1 early-read miss, P1 proceeds "only if K2 and K3
allow". Under decision 0002, K2 gives no P0 signal, so that replan could decide not to build the directory at all.
If it does, about 3 pw of agent-built code and the owner's review time on it are lost. Nothing is published, frozen or minted, so rollback means leaving the code unused.
Whether that risk is worth about ten weeks of head start is Matt's call, so this record stays **Proposed**.
