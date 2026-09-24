# 0003 — Stage P1.0: a no-regret slice of P1 that may start before P0 all-pass

- **Status:** **Superseded** by decision 0004 (2026-09-24). The owner chose to build the full product
  before any outreach, so all of P1 starts now and the question this record asked, whether a slice may start
  early, no longer arises. The record is kept for its invariance analysis.
- **Date:** 2026-09-24
- **Decider:** _(blank until accepted)_
- **Start option:** _(A or B, blank until accepted)_
- **Merge authority for P1.0 PRs:** _(blank until accepted — see "Review and merge")_
- **Uses, and amends once accepted:** the plan's own staging rule, FM-08 (plan §10 conventions): _"Where only part of a phase depends on
  a gate, the phase is split into numbered stages, each with its own gate."_ P1.0 is such a stage. Once accepted,
  this record amends the plan's §10 P1 section and the §11 DAG to show it. The P1
  pre-build gate ("P0 all-pass, or its replan is signed") is **unchanged** for the rest of P1, which is now
  called P1.1.

## Why this is on the table

Under ruling C7, what gates P1 is:

- the P0 verdicts of the technical checks (X1, X2, X4–X7);
- K3 and K4;
- K1's **early read**, which closes on **2026-10-19** (0001, Addendum D, R1).

K1's and K2's **full** gates hold P4.2, not P1 (C7, plan §16). K2 is deferred anyway (decision 0002).

The long poles are therefore:

- **X1 and K4b**, which need borrowed devices and a real round;
- **X2, X4, X5, X6 and X7**, which need the network unblocked and then a p0-desk run.

Neither has a fixed date. Every desk tool P0 needs is already built and merged, so until those land the build
lane has nothing to do.

C7 exists so that no P1 engineering relies on a load-bearing assumption before that assumption has a pass/kill
signal. The test for P1.0 is exactly that: **for each of the 11 checks, does any pre-written kill consequence,
or any plausible pass result, change what P1.0 builds?**

## Start options

- **A — start on acceptance.** This gives the most head start. It carries one residual, the K1 early-read risk
  below.
- **B — start the day after a K1 early-read pass (≥ 2 of 5 acceptances dated ≤ 2026-10-19).** This carries
  **no** residual beyond ordinary v0 rework, and the long poles above almost certainly outlast 2026-10-19.
  `[inference]` This is the recommended option: it gives up about 3½ weeks of head start to remove the only
  sunk-effort branch.

## P1.0: a pre-freeze contract draft, with no data, no network and no keys that ship

Everything in P1.0 stays at `CONTRACT_VERSION = 0`. It is unfrozen and unpublished, and no production ID is
minted, so every item is a two-way door until the M-freeze.

| #   | Work                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Plan reference               |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| S0  | **Built first. A CI guard that fails the build if:** `CONTRACT_VERSION ≠ 0`; any file under `data/` is added or changed; a private key, keyset or `kid` registry file is committed; or any workflow is added or changed that deploys, runs the artifact emitter (`dist/catalog/v1/*`, §3.5) or uses a signing `environment:`. **Any change to the S0 guard itself or to `.github/workflows/` is merged by Matt personally**, whatever the Merge authority line says. It is removed or relaxed only by the P1.1 gate                                                                                                                                                                                                                                                                                                         | enforces the stop rule below |
| S1  | `packages/catalog`: the §4.1 Zod schema for **curated (verified) records only**, as a draft. It covers: facility, course, trail and `RosterVersion` (the unit, rule parameters and `trackingStartsOn` per version, with `markerUnit` and `markerRule` **required**, as in §4.1); `prov` on curated content fields, with the plan's non-OSM values only (an Alt-5 value would be a free v0 addition); `tz`; the verification tiers; `composite`; `anyOf` members; `access`; `ruleSource`. S1 also includes the JSON Schema regeneration that §3.5 gets from CI. It does not include `verify-contract`'s breaking-diff check, which has nothing to diff against before the freeze                                                                                                                                             | P1 scope; §3.5, §4.1         |
| S2  | `verify-catalog`, run against **synthetic fixtures only**. It covers the AT(1) must-fail / must-pass rows that concern curated records: duplicate or reused id; missing member; roster without a source; unit/member mismatch within a version; a published `RosterVersion` changed; a closed course in the latest version; the booking-host rule against a **fixture** allow-list, including course-native host = facility domain; the contact-field diff rule (`url`/`phone`/booking host changed without `contact-reviewed`); missing, non-IANA or wrong-zone `tz`; `course-claim` without `claimProof`; `n-of-m` without `ruleSource`; missing `access`; `access: 'private'` with a `booking[]` entry, plus its must-pass. It also covers slug collision (AT(7)), and ID-ledger id / tombstone / `mergedInto` mechanics | P1 AT(1), AT(7)              |
| S3  | `packages/rules`: **completion** evaluation and the §8.2 completion fixtures of AT(6) that involve no marker, i.e. addition, removal, closure, pre-launch history, `trackingStartsOn`, the three A2-02 rule-change fixtures, merge after publication, the user-pick member, the composite count and the date-only `local_date` case. Also the `RuleExpr` checker with the **non-marker, non-offer** fixtures of R-01–R-14 and R-F1–R-F7. The checker's closed aggregate list and `field` enum leave out the `markerSetComplete` / `markerCredits` signatures and the money-mode polarity rule; those are added in P1.1                                                                                                                                                                                                      | P1 AT(1), AT(6); §8.1, §8.2  |
| S4  | Artifact signing code: Ed25519 per-`kid` sign/verify, tampered-shard failure and `revokedKids[]` refusal (AT(2)). **Tests only use keys generated in-process during the test run**; no key is committed, and no `kid` is added to any keyset or signing environment. The pre-P3 keyset itself (§3.5) is a P1.1 item                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | P1 AT(2)                     |
| S5  | The completion-unit mechanics of AT(3): a 26-course / 11-facility shape; a hole-unit shape where 18 hole members resolve to 18 courses; a 27-hole composite. They are **labelled as fixtures, not trail data**. The "marker roster of 11" assertion is excluded (K1)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | P1 AT(3)                     |

Estimated size: about 2.5 of P1's 10.75 pw. `[inference — the estimate is not measured]`

**Nothing in P1.0 counts as a P1 acceptance test passing until P1.1 re-runs it.** When X2 confirms the slate's
rosters and `completionUnit`s (SP7), the S1 unit enum and the S5 shapes are re-checked against them, and AT(1),
(3) and (6) count only when they pass at the P1.1 gate.

## Invariance: each P0 check's consequence, and its effect on P1.0

| Check            | Kill → pre-written consequence (plan §10 P0)                                                                       | Effect on P1.0                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ---------------- | ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| X1 (=K4a)        | Health lane ships date-only; store copy drops "GPS match"; the result feeds K4                                     | None. It is a mobile/P4 lane                                                                                                                                                                                                                                                                                                                                                                                                           |
| X2               | Swap in the reserve trails (OK, then Hammock Coast / Kauai)                                                        | None from a kill: P1.0 holds no trail data. **A pass can still change the S1 unit enum.** That is covered by the re-run rule above and by the stop rule                                                                                                                                                                                                                                                                                |
| X3               | Closed, PASS 2026-09-23                                                                                            | —                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| X4               | Course-native link becomes primary for that trail                                                                  | None. That is a per-trail data choice, and S2's booking-host rule already covers the course-native case                                                                                                                                                                                                                                                                                                                                |
| X5               | Before P1, choose manual polygons or Alt-5 (a licensed feed, possibly not redistributable)                         | **This is why every OSM and geometry element is excluded.** Alt-5 would change `seed`, `osmRef`, `derivedFrom`, `geometry.layer`/`ref` and the stub optionality rule, and none of those are in P1.0. The `prov` field itself is in S1 with non-OSM values only, and an Alt-5 value would be a free v0 addition. The "before P1, choose" obligation is **neither discharged nor deferred** by P1.0: it still has to be made before P1.1 |
| X6               | T0 is course-native only until counsel L4 clears                                                                   | None. It concerns P2 linking                                                                                                                                                                                                                                                                                                                                                                                                           |
| X7               | Server-side spatial queries dropped; dispute replay stays in TS                                                    | None. P1.0 has no Supabase work                                                                                                                                                                                                                                                                                                                                                                                                        |
| K1 early (0–1/5) | Replan before P1. Partner programme paused. P1–P4 proceed as directory + tracking + badges only if K2 and K3 allow | Every partner-programme item is excluded (marker evaluation, the marker and offer `RuleExpr` fixtures, QC offer terms). What remains is the directory + tracking + badges core. **Residual under option A only:** see "The one real risk"                                                                                                                                                                                              |
| K1 full          | Holds P4.2; P5/P6 do not start; the programme is off on every trail                                                | None. `markerUnit` and `markerRule` are required §4.1 fields, and turning the programme off does not remove them from the contract                                                                                                                                                                                                                                                                                                     |
| K2               | Deferred (0002). A kill holds P4.2 only; "P1 is not held"                                                          | None                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| K3               | Directory re-scoped or put on probation; **"P1 proceeds in every case"**                                           | None                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| K4               | Garmin written statement, owed in writing **before P1** in almost every outcome                                    | None to the build. The statement is **neither discharged nor deferred** by P1.0: it is still owed before P1.1                                                                                                                                                                                                                                                                                                                          |

## Excluded: waits for the P1.1 gate (P0 all-pass or a signed replan), exactly as the plan says

- **OSM and geometry (X5, counsel L-OSM):**
  - `seed` / `osmRef`, `derivedFrom`, `geometry`;
  - the stub optionality rule, stub minting, `seedRefs[]`, ledger `status` / `transitions[]` (AT(5), AT(8), G3-01);
  - the geometry pipeline and the geometry-diff and polygon rules of AT(1);
  - the ODbL layer split and the OSM-provenance fixtures of AT(1).
- **Partner programme and money-mode grammar (K1):**
  - marker-rule evaluation and every marker fixture of AT(3) and AT(6);
  - R-12 `markerSetComplete`;
  - R-14, R-F6 and R-F7 (the offer and money-mode polarity grammar, A2-05);
  - the QC-offer-terms-without-FR fixture.

  P1.0's completion and `RuleExpr` code does land in `packages/rules`, which the plan names as the money path
  (plan §10 risk table). Before P3 no money flows, so no extra review is needed now. From P3, changes there need the
  external reviewer's approval, and the P3 gate reviewer covers P1.0's code with the rest.

- **Anything in `data/`:** rosters, `data/achievements/*.json`, the designer registry and directory entries (X2:
  "never by a snippet").
- **Keys and keysets:** the pre-P3 keyset, any committed key, any signing environment.
- **The Supabase import function** (AT(4)) and anything that needs an account or the network.
- **The booking allow-list's real contents** (X4, X6).
- **The M-freeze itself.** It is the one-way door, and it stays behind the P1.1 gate.

## Stop rule (fixed now, before any verdict is read)

- **No further P1.0 PR merges** (PRs in flight stay open) if **any** P0 memo:
  - ends in **kill** or **adjust**; or
  - reports a result that contradicts a §4.1 assumption P1.0 relies on (for example, an X2 `completionUnit`
    outside the enum).
- It resumes only when the owner-signed note for that memo says which P1.0 items survive.
- The S0 guard enforces the hard limits mechanically: no `CONTRACT_VERSION` above 0, no `data/` content, no
  committed key or keyset, and no deploy, emit or signing workflow. Because a PR could edit the guard itself,
  changes to the guard or to CI are always merged by Matt personally (S0).

## Review and merge

- **Before P3, the builder is the only reviewer** (plan §3.5, O22), and agents never count as a reviewer (plan
  §10 risk table).
- P1.0 PRs are therefore merged by Matt, **or** by an agent on green CI **only if** Matt writes that delegation
  into the "Merge authority" line above when he accepts this record. His earlier "merge when green"
  instructions to an agent session covered P0 PRs; they are not read as covering P1.0.
- The P1 DoD's O22 `/security-review` report and Matt's self-attestation cover P1.0 as part of P1.

## The one real risk (option A only)

The residual is **sunk effort, not a wrong design**. After a K1 early-read miss, P1 proceeds "only if K2 and K3
allow", and under decision 0002 K2 gives no P0 signal. That replan could therefore decide not to build the
directory at all. If it does, about 2.5 pw of agent-built code and the review time spent on it are lost. Nothing
is published, frozen, minted or keyed, so rollback means leaving the code unused. Option B removes this branch.
