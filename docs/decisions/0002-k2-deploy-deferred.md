# 0002 — K2 signup deploy deferred to the last responsible moment

- **Status:** Accepted
- **Date:** 2026-09-23
- **Decider:** Matt (owner): "wait until the last minute" for the domain, Cloudflare/Resend setup and the
  signup-worker deploy
- **Amends:** decision 0001 (P0 exit rule) and plan §10 P0 (K2 row)

## Decision

The K2 player-signal test (landing page + `apps/signup-worker`) is **not deployed in P0**. It is deployed at
the last responsible moment, defined so the deferral cannot silently become "never":

- **Deadline:** K2 day 0 must be logged **no later than 7 weeks before P4.2 starts** (6 weeks for the K2
  gate window, plus 1 week for domain, Resend verification, deploy and the end-to-end confirmation that sets
  day 0).
- **Where the date comes from:** P4.2's planned start is re-derived at every velocity re-plan (M-freeze, M1,
  M2 — plan §10). At each re-plan, Matt writes the current K2 deadline into `docs/p0/K2.md` ("Deploy
  deadline"). The first one is set at the M-freeze re-plan.
- **If the deadline passes without day 0 logged:** P4.2 does not start until the K2 gate verdict exists
  (the same hold a K2 miss would cause). The deferral never waives the gate.

## Consequences

- **P0 exit rule.** "All 11 gating verdicts written" is amended to **10 of 11 plus K2 deferred under this
  decision**. K2's only hard consequence was ever to hold P4.2 (its kill text: "P1 is not held"), so P1 may
  start once the other ten verdicts are written or replanned. This record is the owner-signed replan the P0
  acceptance test (4) requires.
- **Everything already pinned for K2 still applies unchanged:** decision 0001 Addenda D (R3) and F, the
  thresholds (100 advisory by day 14, 300 by day 42), exclusion dating and the no-restart rule.
- **Built and gated, not deployed:** `apps/signup-worker` and `apps/landing` are merged and CI-green, so the
  deploy is a runbook, not a build, when the deadline arrives.
- **Known risk, accepted by deferring:** `golfraven.com` (and `.golf`, `.ca`) may be registered by someone
  else in the meantime. Domain registration is separable from the deploy and cheap; it can be done early
  without starting the K2 clock.
