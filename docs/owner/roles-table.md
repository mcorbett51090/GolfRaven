# Roles table

Covers the "Fill the roles table" P0 deliverable (plan §10 P0). Verbatim source:
`docs/golf-trails/02-build-plan.md` §10, "Named roles (G-P0-08, G-P1-29, FM-25, G2-06, G2-09) — v6 holders
(O6 solo; O22 second admin and reviewer at the P3 gate)."

## O6 — solo (Matt holds every P0–P2 lane)

O6 DECIDED 2026-09-23: "Solo / 1-2 people, no fixed season." One builder (Matt, full-stack, with Claude Code
agents) plus an optional second contractor; the data editor role folds into the builder plus agent-assisted
verification.

## Roles and responsibilities

| Role                                           | Holder                                                                                                                                                                                     | Responsibilities                                                                                                                           | Needed from                        |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------- |
| Tech lead; web / mobile / backend / data leads | Matt, with Claude Code agents                                                                                                                                                              | All engineering across `apps/site`, `apps/mobile`, `apps/ciq`, `packages/*`, `supabase/*`                                                  | P0                                 |
| **Product lead**                               | Matt                                                                                                                                                                                       | Owns P9 scope and the geofence spec's acceptance (§7.4/§9's C6 geofencing synthesis)                                                       | P4                                 |
| **QA**                                         | Matt                                                                                                                                                                                       | Agent-run release-candidate test passes (on the M2 build and the store-review build), plus the scripted field-test rounds walked in person | P4                                 |
| Security reviewer                              | **P0–P2:** `/security-review` (Claude Code) plus Matt's recorded self-attestation (O22). **From P3:** an external contract reviewer (≈ 3 days per phase DoD)                               | With one author, this is the plan's only independent code review from P3 onward                                                            | P0 (agent pass); **P3** (external) |
| Partnerships lead                              | Matt                                                                                                                                                                                       | K1 operator/sponsor outreach, pro-shop onboarding, applications                                                                            | P0                                 |
| Counsel                                        | External, on call                                                                                                                                                                          | The L1–L7 / L-OSM lane (`docs/owner/counsel-brief.md`)                                                                                     | P0, budget ceiling O20             |
| Privacy officer (Law 25)                       | Matt                                                                                                                                                                                       | PIA ownership, incident-register review with counsel (L2)                                                                                  | P3                                 |
| Admin                                          | Matt                                                                                                                                                                                       | Supabase/infra administration                                                                                                              | P1                                 |
| **Second admin / break-glass**                 | **Deferred — see P3 trigger below**                                                                                                                                                        | Break-glass recovery access, sealed recovery kit (TOTP seed + recovery codes, counsel-held)                                                | **Before P3 starts**               |
| Receipt and `held_review` reviewers            | Matt + the second admin as second reviewer; a contract reviewer on the §9.2 staffing trigger                                                                                               | Fraud/receipt review queue under the SLA                                                                                                   | P5                                 |
| Special-marker stock oversight                 | Matt (low-stock/reconciliation alerts only) — the trail's operator restocks and pro shops hand markers over; there is no fulfilment role and no backup fulfiller (O9/O10 removed shipping) | Watch alerts, not physical fulfilment                                                                                                      | P5                                 |
| Data ops                                       | The builder + agents, ≈ 0.1–0.2 FTE of claim-funnel and batch `two-source-match` PRs after M2b                                                                                             | Directory-verification throughput                                                                                                          | M2b                                |

## The P3 trigger for the second admin (O22)

**O22 DECIDED 2026-09-23: solo for now.** Naming the break-glass second admin and engaging the external
security reviewer are a **P3 pre-build gate**, because money and personal data go live after P3. Until then,
each phase DoD carries a `/security-review` (Claude Code) report as recorded self-attestation; the bus-factor
risk is accepted as **R26**.

**What the P3 gate requires (plan §10 P3 pre-build gates, verbatim):**

> (i) the break-glass **second admin named** (the optional contractor if engaged, otherwise a named trusted
> second person), the counsel-held sealed recovery kit made, `docs/runbooks/break-glass.md` written, and a
> break-glass dry run passed; (ii) the **external security reviewer engaged**; (iii) the second admin set as a
> required reviewer of the signing environment with "prevent self-review" on, the **production catalog keyset
> generated** under the §4.8 runbook, and every pre-P3 `kid` listed in `revokedKids[]` (§3.5).

The second admin is: the optional contractor, if Matt engages one; otherwise a named trusted second person,
backed by a counsel-held sealed recovery kit. This choice is **not yet made** as of this file's writing
(2026-09-23) — it is explicitly a P3 gate item, not a P0 one, and this runbook does not pre-select a name.

## Controls weakened while solo, and the compensating control (plan §10 P0, verbatim table)

| Combination                                                      | What weakens                                                                        | Compensating control                                                                                                                                                                                                                                                                                            |
| ---------------------------------------------------------------- | ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Author and security reviewer                                     | DoD sign-off becomes self-attestation                                               | **P0–P2 (accepted, O22):** a `/security-review` report and closed findings, labelled self-attestation, over phases with no money and no player accounts. **From P3:** the external reviewer signs every phase DoD; nobody signs a DoD for code they wrote                                                       |
| Builder and agent reviewer                                       | Agent review looks independent and is not                                           | Agents never count as a reviewer. From P3, the signing environment and the money path change only with the external reviewer's approval at each phase DoD; day-to-day PRs rely on the CI gates (§15). Before P3 no money path exists yet                                                                        |
| Sole admin and sole required reviewer of the signing environment | "Required reviewers" is a ceremony, or deadlocks with self-review blocked           | **Before P3 (accepted, O22):** P1–P2 sign with a pre-P3 keyset that no app compiles in, and it is revoked at the P3 gate (§3.5). **From P3:** the second admin is a required reviewer; GitHub "prevent self-review" is on                                                                                       |
| Admin and receipt reviewer in one person (FM-25)                 | Two weeks' absence in season halts receipts, `held_review` decisions and onboarding | Receipt SLA with escalation to the second reviewer (§9.2); `docs/runbooks/break-glass.md` (written and dry-run at the P3 gate); during a planned absence longer than the SLA, new programme enrolment pauses while earned rewards are still honoured. Special-marker hand-over no longer depends on us (O9/O10) |
| Privacy officer and product owner                                | Conflicting duties on data-use decisions                                            | Counsel L2 reviews the PIA and the incident register quarterly                                                                                                                                                                                                                                                  |

## Agent work is author-side work (plan §10 P0, verbatim)

> Code or data that an agent drafts counts as the builder's own. An agent is never the independent reviewer,
> never the second admin, and never the "independent" author of the money oracle (P3). `/security-review` is
> an agent pass, so it never counts as independent either. Independence comes from the external reviewer
> (from P3) and from the process rules in P3.
