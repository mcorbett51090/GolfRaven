# 0004 — Build the full product before any outreach

- **Status:** Accepted
- **Date:** 2026-09-24
- **Decider:** Matt (owner). Asked how to decide decision 0003, he answered: "Everything needs to be built before
  outreach starts". Asked to choose between (a) the P1.0 slice before 2026-10-05, (b) a demo to show operators,
  and (c) the full product, he chose **"The full product first"**.
- **Merge authority:** Matt, when asked who merges build PRs: "Claude merges when green".
- **Supersedes:** decision 0003 (P1.0). Its question, whether a slice of P1 may start early, is moot now that all
  of P1 starts.
- **Amends:** plan ruling C7 (P0 gates P1), the plan §10 phase order, decision 0001 Addenda C, D (R1) and I (the
  K1 date anchors), and decision 0002 (the K2 deploy deadline anchor).

## Decision

The site, the apps and the partner-programme software are built **before** any operator or sponsor outreach
is sent. This reverses the plan's validate-first order for payer demand.

## What changes

1. **Phase order.** P1 → P2 → P3 → P4 → the P5 and P6 **software** are built now, in that dependency order,
   without waiting for the P0 verdicts. A trail's partner-programme **go-live** (P5's pilot) still needs a
   signed operator, so it waits for outreach. Building the software does not.
2. **K1 moves after the build.**
   - The 9 outreach drafts stay unsent.
   - K1's pre-registered windows keep their **lengths**: the early read is 2 weeks, the LOI window is 8 weeks,
     and the sponsor-conversation cutoff is the same as the LOI cutoff.
   - Their **anchor** changes from 2026-10-05 to the **outreach start date**. Matt writes that date into
     `docs/p0/K1.md` before the first email is sent, so it is still fixed before any reply exists.
   - `k1-verdict`'s hard-coded dates will be re-anchored to it then, in a gated PR.
3. **K1 no longer gates P1.** Its consequences still apply when it is read. After an early-read miss, the
   programme is paused on its trails. After a full operator miss, the programme stays off and the app runs as
   directory + tracking + badges (O17). After a sponsor-only miss, the programme runs operator-funded.
4. **The technical checks still run, but gate nothing.** X1, X2, X4–X7, K3 and K4 still run when their inputs
   exist (the network, devices, accounts). Each result is applied to what has been built when it lands. A kill
   changes the affected design, as its pre-written consequence says. None of them holds the start of a phase.
5. **K2 is unchanged in substance** (decision 0002). It still gates the public launch (P4.2), and its deadline
   is still derived from P4.2's planned start.
6. **The contract freeze becomes a soft freeze until launch.** The plan's one-way door is the first
   **production** play: "regenerate IDs freely before the first production play" (plan §10 P1, Reversibility).
   Nothing is played in production until launch, so the M-freeze happens on schedule, but a P0 result that
   lands before launch can still change the contract without a MAJOR bump. The hard freeze is at launch.
7. **Accounts and deploys stay at the last responsible moment** (decision 0002 and the owner's "wait until the
   last minute"). The domain, Cloudflare, Resend, Supabase, and the Apple and Google accounts are opened when a
   build step genuinely needs them to run, not before. Until then the build runs locally and in CI.
8. **Merges.**
   - PRs merge when CI is green. Matt has delegated merge-on-green to the agent.
   - Anything that computes a verdict, or touches auth, signing, secrets or the money path, also passes an
     Opus gate review and `/security-review` first.
   - The O22 P3 gate is unchanged: before real money or personal data goes live, the second admin must be named
     and the external reviewer engaged. Building is not going live.

## The trade-off, stated once

P0's K1 existed so that payer demand would be tested before the build was paid for. The plan's committed effort
for P1–P6 is 84.5 pw (91 pw minus P0's 6.5; plan §10 effort re-derivation) `[inference]`. Under this decision
that effort is spent before any operator has said whether they will pay. If K1 then misses, the pre-written
consequence applies to a finished build: the programme is switched off, and the app ships as directory +
tracking + badges. What this buys is a real product to show on every operator and sponsor call. Matt made this
trade deliberately.

## Housekeeping done with this record

- Decision 0003 is marked Superseded.
- The four K1 calendar holds (2026-10-05, 10-19, 11-30 and ≈ 12-14) are removed from Matt's Google Calendar,
  because those dates no longer apply.
- The P0 status board marks K1 as deferred under this record.
