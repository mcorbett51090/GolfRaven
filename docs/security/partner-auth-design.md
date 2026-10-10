# Partner (staff) authentication and authorization: design, P5.1a-0

Design only. No code and no migration is part of this change. It is the document the P5.1a security gate reads before anyone builds the staff path, and it settles the item the build plan leaves open: the staff-auth **mechanism** (plan §3.4 row "Staff auth", line 398; assumption A46, line 3247; FM-20, G-P1-05).

- Revision 5 (gate round 4 response, section 1.2). Revision 4 was `ba6d5d9` (gate round 3), revision 3 was `d59c425` (gate round 2), revision 2 was `c657a56` (gate round 1); revision 1 was `568f483`. Base: `main` at `eb92ee9`. Every `path:line` below is at that commit unless it says otherwise.
- "Plan" is the RavenGolf repo's `docs/golf-trails/02-build-plan.md` (linked from the root `README.md`). Plan line numbers are the ones read when this was written.
- Related, read first: `docs/security/edge-role-design.md` (the Edge database role model; "edge doc" below) and `docs/security/p3-money-path-requirements.md` ("money doc"; in particular "What P5 must do (the staff verification endpoint)", line 3831).

**How claims are marked.** Anything about a third party (Supabase, GoTrue, WebAuthn, iOS, SimpleWebAuthn, Deno) is `[unverified - training knowledge]` unless it carries `[verified 2026-10-04: <how>]`. Section 14 lists everything that was checked in the authoring session, and how. `[proposed]` marks a number or a name chosen here for the gate or the owner to challenge; it is not a fact about the repo.

## 1. Decisions at a glance

| # | Decision | Choice | Detail |
|---|---|---|---|
| D1 | Mechanism | `@simplewebauthn/server` in an Edge Function verifies passkeys; **opaque** random sessions live in Postgres. No JWT is minted, no new signing secret exists. Supabase Auth's own passkeys are rejected **for now** (revisit triggers in 3.3) | 3 |
| D2 | Staff identity | A staff member is a normal Supabase Auth user (the FKs and `bind_actor` need `auth.users`). Email OTP is used only to prove the mailbox (invite, recovery, PIN or TOTP set-up), verified **server-side**, and its GoTrue session is closed after use. Partner authority never comes from a JWT claim or `user_metadata` | 6.1 |
| D3 | Relying party | RP ID `partners.golfraven.<tld>` (the narrow host, not the parent domain), one exact origin, `userVerification: required`, `residentKey: required`, `attestation: none`. RP ID and origin are deploy-time configuration, fixed before the first enrolment. Needs **no outbound host** | 4.5, 5.1, 7 |
| D4 | Sessions | 256-bit random token, SHA-256 at rest, bound to member + credential, idle and absolute timeouts per role, at most 3 live per member, revocable instantly | 4.1, 5.1 |
| D5 | Lane | The partner lane is a **separate database role** `edge_partner` with no table privilege, its own binding kind `partner`, and `private.actor_uid()` returning NULL for it. Every partner definer begins with one shared `private.partner_authorize(...)`, which re-reads session, role, scope and assurance **on every call** | 4.2, 4.3 |
| D6 | Minting | Sessions, challenges, enrolment and invite acceptance are written only by a dedicated role `edge_partner_minter` (the `edge_signin_minter` precedent, migration 0041), never by `edge_actor` or `edge_partner` | 4.4 |
| D7 | Transport | `Authorization: Bearer gr_ps_...` header, token held **in memory only**. No cookie. Exact-origin CORS, a server-side Origin refusal, strict CSP | 4.6 |
| D8 | Step-up PIN | 4 digits, per person, **one PIN per attest-class action** (plan §9.2). PBKDF2-SHA256 runs in the **browser**, the **pepper and the comparison run in the database**, with lockout and backoff | 6.3 |
| D9 | Admin and operator | Passkey + TOTP. TOTP is our own, verified in the database; enrolment is gated and a confirmed TOTP can only be reset by a higher role | 6.4 |
| D10 | Invites | Hashed token in a URL fragment, email compared **in the database**, 72 h, single use, explicit role arrays, one facility org = one facility scope | 6.1, 5.2 |
| D11 | Revocation | Authority is re-read per call under row locks; triggers also kill sessions on update, delete and insert, so nothing can be revived | 6.5 |
| D12 | PostgREST read surface | **The existing PostgREST read surface over partner data is revoked** from `authenticated` (views, `api.my_offers()`, the offer policy and the base tables) and replaced by Edge reads. Without this the passkey is bypassable by email OTP alone | 5.5 |
| D13 | Credentials and recovery | A credential belongs to the **person**, not to an org. A second credential needs A2 and a fresh passkey assertion; a member who already has a credential never gets one from an invite or an email OTP. Recovery is its own manager action and its cross-org effect is stated | 6.1, 6.5 |
| D14 | Offline | The design keeps the hooks (challenge purpose, TTL, voucher binding, no local PIN verifier) but builds nothing offline. WebAuthn assertions offline in an installed PWA stay `[unverified]` (A60) | 6.7 |

### 1.1 Where this departs from the proposed direction

| # | Departure | Why |
|---|---|---|
| X1 | The partner lane is a **new role plus a new binding kind** (`partner`), not "resolve, then `bind_actor(uid)`" and not a kind on `edge_actor` | `edge_actor` holds the whole player write surface and ~84 policy references to `private.actor_uid()` that ignore `kind` (section 2, E3). Only a separate role with no table privilege keeps a partner transaction out of it |
| X2 | A dedicated **minter role** `edge_partner_minter` | A handler bug in any partner function must not be able to mint a session. Same shape and reasoning as 0041 |
| X3 | PIN: PBKDF2 runs **in the browser** (not the Edge); the stored verifier is `HMAC(pepper, PBKDF2 output)` and the **compare runs in the database** | For a 4-digit secret a slow KDF buys almost nothing against a leaked verifier: 10,000 candidates at 600,000 rounds is about 54 minutes on one core (measured, section 14). What protects it is that the table is unreadable, the pepper is not in the table, and online guesses are capped in the database. Deriving in the browser also keeps the PIN itself out of the Edge |
| X4 | **Revoke the PostgREST partner-lane read surface** (D12) | "The PWA never talks to PostgREST" is necessary but not sufficient: the same person's Supabase JWT still reads partner data today. The largest finding of the design |
| X5 | Operator/admin TOTP is **ours, in the database**, not Supabase MFA | The partner session is not a GoTrue session, so GoTrue's `aal` cannot be attached to it |
| X6 | Slice plan: slice 1 is split in five and re-ordered (PIN, TOTP, then invites and enrolment); the player-lane half of the course QR (`marker-scan`) can run in parallel; the PWA is its own track | Section 12 |
| X7 | The `facility org = one facility scope` invariant, a role-to-org-kind invariant and `partner_invite` additions | `partner_scope` is per **org**, not per member (G2); without the invariant "grant is a subset of the inviter's scope" has no precise meaning |
| X8 | **FM-20 as written**: the PIN is asked **per attest-class action**, not per window (plan line 2181: "asked before each attest") | Revision 1 proposed a 90 s window and did not list it as a departure. Revision 2 follows the plan; a window is an owner decision (Q2) |
| X9 | `offline_code_record_step_for_actor` loses its `edge_actor` EXECUTE in S1.1, not in S3. **The function and its atomic-replay proofs stay**; only the Edge wrapper and the cells that assert `edge_actor` can call it change | It is staff authority under a plain user binding (G7). The money doc depends on the replay property (12 parallel calls give exactly one `recorded`) |

### 1.2 Gate round responses

**Gate round 1 response**

Round 1 (against `568f483`): 4 HIGH, 6 MEDIUM, 12 LOW, 7 NIT. The NITs are numbered N1 to N7 in the order the gate listed them. Claims in the findings that touch the repository were re-read before acting (section 14).

| ID | Finding | Fixed in |
|---|---|---|
| H1 | Partner binding is accepted by the user lane (`actor_uid()` ignores `kind`) | D5; 2 (E3, G7); 4.2; 4.3; 5.3; 5.4; PA-3; PA-3b |
| H2 | Adding a credential has no step-up class; shared-iPad persistence | 6.3 (A2 and `reauth`); 6.5; 5.1 (server-derived label); PA-21; PA-22 |
| H3 | An invite to a second org mints a credential on an existing member; recovery contradicts the 409 | 6.1 (branches N and E); 6.5 (recovery); 5.1 (`partner_enrolment_token`); PA-23 |
| H4 | TOTP reduces to the passkey (deterministic seed, repeatable enrol) | 6.4; 5.1 (`partner_totp`); PA-20, PA-24 |
| M1 | D12 list incomplete (`api.my_offers()`, `api.offer` drafts) | 5.5; PA-6; S1.1 |
| M2 | `aal` not enforced for A0 | 4.1; 6.3 (class table); PA-20 |
| M3 | Staff authority already exists under a `user` binding | 5.4 item 11; check 14 (clause b); X9; S1.1 |
| M4 | The minter has no equivalent of 0041's half (b); missing minter definers; admin bootstrap | 4.4; 5.1 (`partner_rp_config`, `partner_enrolment_token`); 6.4 (admin bootstrap); S0 spike; S1.1; S1.6 |
| M5 | Undeclared FM-20 departure; shared-device PIN statement overstated | X8; 6.3; 4.1 |
| M6 | Global pre-auth bucket is a lockout lever | 8 |
| L1 | Failure counters roll back on RAISE | 5.3; 5.4 item 12; 6.3; PA-18; PA-14 |
| L2 | Accept-flow order closes the GoTrue session too early | 6.1 step 2 |
| L3 | Revocation gaps (DELETE, re-INSERT, TOCTOU) | 5.2 (triggers); 4.3 (locks, VOLATILE); PA-4 |
| L4 | The `token_hash` CHECK breaks fixtures in `helpers.sql` | 5.2; 5.5; S1.1 |
| L5 | Slice order: invites need A2 and A3 first | 12 (re-ordered); `partner_authorize` fails closed |
| L6 | CSRF and CORS: loose content-type, no Origin refusal, methods | 4.6; PA-10 |
| L7 | SimpleWebAuthn 14.0.3 behaviours | 7; 6.1; 6.2; PA-0a |
| L8 | Synced passkeys on a shared iPad | 11 (R-P3); S0 |
| L9 | Self-attest is per account, not per person | 6.5 |
| L10 | Revoke base-table SELECT too | 5.5 |
| L11 | PIN deny-list; offline PIN; voucher binding | 6.3; 6.7 |
| L12 | The 30 s token refresh defeats idle | 4.2 (keep-alive exemption) |
| N1 | `{derived}` sent by client vs Edge derives | 6.3 (browser derives); R-P2 |
| N2 | Role lists from `partner_role_rank` include `sponsor` | 5.2 (role-to-org-kind); 6.1 (explicit arrays) |
| N3 | Check 14 satisfiable by a comment; S3's `offline_code_bound_staff` extension | 4.3; 5.4 item 5 |
| N4 | A3 satisfying A2 for PIN-less members | 6.3 (class table) |
| N5 | `getActorFromRequest` rejects `gr_ps_` before GoTrue | 4.2; PA-11 |
| N6 | "Same HOTP primitive" needs parameters | 6.4 |
| N7 | Proof of possession in the S1.2 contract or deferred | 4.6 (deferred, reserved) |

**Gate round 2 response**

Round 2 (against `c657a56`): PASS with conditions, all round-1 items verified fixed; 2 required MEDIUM (before S1.1), 8 LOW, 3 NIT, three rulings on open items. Every LOW is fixed in this revision; none is deferred to its slice.

| ID | Finding | Fixed in |
|---|---|---|
| R2-M1 | The reach rule is vacuously true for a target with no membership (an admin) | 6.5 (reach rule, conditions 1, 3, 4); PA-25 |
| R2-M2 | `FOR SHARE` under FORCE RLS locks nothing for `private_definer` | 4.3 (revised by R3-M1: session row only, `FOR NO KEY UPDATE`); 5.3; 5.4 item 2; PA-4; 14 (reproduced on PG 17.11) |
| R2-L1 | Branch N bypasses the reach rule | 6.1 (cases a, b, c and the `register_first` rule); 4.4; PA-23 |
| R2-L2 | Credential self-revoke has no class | 4.5; 6.3 (A2); 6.5; PA-22 |
| R2-L3 | The post-bind assertion lacks grants | 4.2; 4.3 (EXECUTE list); 5.3; PA-13b |
| R2-L4 | A new operator or admin can never enrol TOTP at `aal` 1 | 4.1; PA-28 |
| R2-L5 | Branch N contradicts itself (membership written before the credential check) | 6.1 steps 2 and 3; PA-23 |
| R2-L6 | Unbounded challenge inserts | 5.1 (stateless challenges); 4.4; 8; 9; PA-7 |
| R2-L7 | S1.6 re-verifier spec inconsistent | 4.4 (what it reads and writes, who may call, where it runs); 12 (S1.6); PA in S1.6 |
| R2-L8 | X9 over-deletes the recorder and its proofs | 1.1 (X9); 5.2 |
| R2-N1 | `session/reauth` must assert the credential's owner is the session's user | 4.5; PA-27 |
| R2-N2 | `bind_partner_session` must refuse when any binding exists | 4.2; PA-13b; PA-27 |
| R2-N3 | The last-membership trigger must not delete an admin's TOTP | 5.2; PA-29 |
| U1 | In-portal notice acceptable under three conditions, tracked | 13 (U1, Q7) |
| U2 | Belongs to the S1.6 gate | 4.4; 13 (U2) |
| U3 | S0 spike changes return as a delta gate on 3.2, 4.4, 11 | 13 (U3) |

**Gate round 3 response**

Round 3 (against `d59c425`): PASS with conditions, all round-2 items confirmed, the stateless-challenge design judged sound on replay, purpose and key custody. 2 MEDIUM, 3 LOW, 2 NIT, all fixed in this revision.

| ID | Finding | Fixed in |
|---|---|---|
| R3-M1 | The `WITH CHECK (false)` lock policy on `partner_member` does not prevent updates (permissive policies are OR-ed with table-wide UPDATE and `pd_setnull_...`) | 4.3 (lock design replaced: session row only, authority-touch triggers); 5.2 (triggers, `partner_scope`); 5.4 item 2; PA-4; PA-4c; 14 (both repros) |
| R3-M2 | Registration challenges are not bound to an OTP-proven acceptance | 4.4 (issuers, `register_first`); 4.5; 5.1 (HMAC binding); 5.2; 6.1 steps 2 and 4; PA-7b |
| R3-L1 | Admin recovery is impossible (condition (1) applied to admins) | 6.5 (reach rule); PA-25 |
| R3-L2 | `partner_reverify_flag` is a mass-lockout lever; `partner_audit` needs `USAGE` | 4.4 (what it writes, who may call); 12 (S1.6) |
| R3-L3 | The first session after registration | 4.4 (`register_first`); 5.1 (`mint_kind`); 6.1 step 4; PA-7b |
| R3-N1 | HMAC message encoding | 5.1 (the HMAC message, constant-time comparison); PA-7 |
| R3-N2 | `facility_programme` changes take effect from the next call | 4.3 |

**Gate round 4 response**

Round 4 (against `ba6d5d9`): PASS with one condition; R3-M1, R3-M2 and every R3 LOW and NIT confirmed fixed, the register-mint gap accepted. 1 MEDIUM, 2 LOW, all fixed in this revision.

| ID | Finding | Fixed in |
|---|---|---|
| R4-M1 | The cross-session window policy breaks the HARD RULE: a planted GUC persists into a later definer call | 4.3 ("Who may write `partner_session`": three dedicated roles, no GUC window, the eight writers, the S1.6 flag and enforcement without a GUC); 5.2; 5.3; 5.4 item 5; PA-4c (planted GUC, re-run on every S1.5 policy); 14 (repro) |
| R4-L1 | A partner-bound definer can change any column of its own session row | 4.3 (guard trigger, narrowed column grants, artefact mechanism, column table); 5.1 (`last_ok_at`, `otp_proof_gotrue_session_id`); PA-4d |
| R4-L2 | `register_first` must make every DB-side check a create ceremony allows | 4.4 (`register_first` checks, re-verifier skip); 11 (R-P1 states there is no cryptographic check); PA-7c |

## 2. What the repository already gives us, and what it does not

Facts the design leans on. Each was read at `eb92ee9`.

| # | Fact | Where |
|---|---|---|
| E1 | Every Edge transaction is `SET LOCAL ROLE edge_actor`, `edge_system` or `edge_signin_minter` over one `edge_gateway` pool. Kinds are `actor`, `system`, `delegate`, `signin_mint`. The actor kind binds `private.bind_actor(uid)` and asserts `private.actor_uid()` equals the expected uid | `supabase/functions/_shared/privileged.ts:317-426`; edge doc sections 2-3 |
| E2 | Player identity is GoTrue `auth.getUser(token)` with the anon key. Nothing else is an identity source | `privileged.ts:486-512` (since 0051 the function also runs the review-account gate after `auth.getUser`) |
| E3 | **`private.actor_uid()` returns the bound uid whatever the binding `kind`** (it selects on pid and transaction only). The `edge_actor` policies of 0031 and 0032 reference it 84 times, and several user-lane definers check only `actor_uid()` and never the kind (`hit_actor_rate_limit`, `device_link_signals_for_actor`, `hold_play_rewards_for_actor`, `lock_own_reward_for_actor`). Only some definers refuse a non-`user` kind (`IF v_kind <> 'user'`). `actor_binding.kind` is `CHECK (kind IN ('user','system_delegate'))` | `supabase/migrations/0030_edge_role_core.sql:122,252-259,326,375,397,432`; `0031_edge_role_policies.sql`, `0032_edge_role_hardening.sql`; `0033_edge_role_pr2.sql:90,156`; `0045_offline_totp_seed.sql:214,266` |
| E4 | A fully compromised runtime can `bind_actor(<any uid>)` (residual R6). This design keeps the partner lane narrower than R6 where it can, and says where it cannot | edge doc section 3 "Honest limit", section 8 R6 |
| E5 | `partner_member(user_id, org_id, role, revoked_at, invited_by)` has PK `(user_id, org_id)`. `partner_scope(org_id, facility_id?, trail_id?, sponsorship_id?)` hangs off the **org**, not the member | `0004_partner_programme.sql:20-46` |
| E6 | `private.has_facility_scope(uid, facility, roles)` reads non-revoked member + scope, lets admin through, and lets an `operator` reach a facility through **any** `facility_programme` row of its trail (no filter on `participation`). `partner_role_rank`: staff 1, manager 2, operator 3, **sponsor 3** | `0007_private_helpers.sql:75-105,194` |
| E7 | Self-attestation has a database twin: a CHECK on `attestation`, and `22023 self_attestation_refused` in the offline-code recorder. Both compare **accounts** | `0004_partner_programme.sql:154`; `0045_offline_totp_seed.sql:283` |
| E8 | Every `api.` view is granted SELECT to `authenticated`, and the partner-lane ones filter on `auth.uid()`; `api.my_offers()` is EXECUTE-able by `authenticated` and unmasks offer columns for scoped callers; the base policy `offer_read` shows non-live offers to scoped members | `0010_api_views.sql:44-60,130-200`, grant loop `:213`; `0009_grants_revokes.sql:15-31`; `0011_rpc_functions.sql:59-94`; `0008_rls_policies.sql:303-309` |
| E9 | Registries fail closed. `delete_my_data` raises on an unclassified FK to `auth.users`; `export_my_data` needs a `pii_export_policy` row; every function needs a `function_inventory` row; every `private_definer` policy needs an allow-list row and a fixture line | `0014_hardening.sql:37-96`; `0045:380-396,573-640`; edge doc section 6 |
| E10 | Precedent for a narrow mint role | `0041_signin_proof_hardening.sql:61-103`; edge doc section 12.1.1 |
| E11 | `private.hit_actor_rate_limit` never raises over the cap and builds `<uid>:<key>` in the database; `hit_system_rate_limit` builds `system:<key>`; the failure-counter pattern is `reserve_signin_otp_attempt` / `release_signin_otp_attempt`. A definer that RAISEs rolls back its own counter writes (the lesson of 0020) | `0030:320`; `privileged.ts:462`; `0035:561,585`; `0020_rate_limit_no_raise.sql` |
| E12 | The staff offline-code requirement: verify **inside the database**, no seed reaches the staff runtime; and the HARD RULE that a GUC-keyed policy is not an ownership boundary against `edge_actor` | money doc lines 3831-3845 |
| E13 | `retention-purge` runs bounded definers, one try-lock per step, with `EXECUTE` granted to `edge_system` by owner decision | `privileged.ts:2561`; `0040_retention_hygiene_purges.sql`; edge doc sections 14.4, 14.8 |
| E14 | `app.audit_log` is insert-only (a trigger blocks update/delete except one redaction exception); nothing purges it | `0006_offers_booking_misc.sql:142-153` |
| E15 | An `npm:` import must be an exact entry in `supabase/functions/deno.json`, in `tools/service-role-lint/pinned-import-targets.json`, and in `supabase/tests/deno.lock` with a sha512 integrity; CI re-checks with `deno cache --frozen` | `tools/service-role-lint/src/config.ts:337-380`; `.github/workflows/ci.yml:395,451,509` |
| E16 | `_shared/http.ts` has **no CORS handling**, and `readJsonBody` accepts any content type that merely *contains* `application/json` | `supabase/functions/_shared/http.ts:103-106` |
| E17 | Admin and demo status are tables read by definers (`app.admin_user`, `app.app_review_demo_account`; `private.is_admin`, `is_demo_account`) | `0007_private_helpers.sql:18-47` |
| E18 | `partner_invite` has `token_hash text NOT NULL UNIQUE`, `invitee_email`, `expires_at`, `accepted_at`. It has no `revoked_at`, no `accepted_by`, no attempt counter. Test fixtures insert non-hex token hashes (`'th-a-invites-y'`) | `0004_partner_programme.sql:48-60`; `supabase/tests/helpers.sql:261-265` |
| E19 | OTP verification already runs server-side with the anon key, and the session it creates is closed **after** the mint on every path | `privileged.ts:3355-3395` |
| E20 | The held-review resolvers exist, are `service_role`-only, and say "the caller must authenticate the admin" | `0027_rewards_activation.sql:485-499`; money doc line 2132; edge doc line 163 |
| E21 | `offline_code_record_step_for_actor` is EXECUTE-able by `edge_actor` and wrapped by `Repo#offlineCode.recordStep`; `offline_code_bound_staff()` evaluates partner membership | `0045:171-191,310`; the wrapper was removed in S1.2 (`privileged.ts:3403` records why) |
| E22 | The mobile app uses only the Auth client (`@supabase/auth-js`); it makes no PostgREST read | `apps/mobile/src/auth/supabase-auth.ts:1-4` and a repo-wide search `[verified 2026-10-04: git grep for rest/v1, .from(", my_offers, api/my_ in apps and packages: no PostgREST use]` |

### 2.1 Gaps found while reading (each is closed in this design)

| # | Gap | Consequence | Closed by |
|---|---|---|---|
| G1 | **A person's Supabase JWT reads partner data directly through PostgREST** (E8): `api.staff_shift_log` (player handles), `api.staff_activity`, `api.facility_programme`, `api.facility_qr`, `api.marker_code_batch`, `api.special_marker_stock[_movement]`, `api.sponsorship`, `api.operator_rollup`, `api.sponsor_rollup`, `api.my_partner_{org,member,scope,invite}`, the unmasked columns of `api.offer` and `api.my_offers()`, and draft offers through `offer_read` | Whoever can obtain a Supabase session for a staff member's email (email OTP, or the player app on the same account) reads these with **no passkey**. The plan's "Staff / manager: passkey session" row (line 445) names "RLS helper `private.has_facility_scope()`" as the enforcement, which only works on a JWT; that reads as assuming the minted-JWT variant (an inference) | D12, 5.5 |
| G2 | `partner_scope` is per org. A member of an org holds **every** scope row of the org, whatever the invite's `facility_id` says | "Grant is a subset of the inviter's own scope" (plan line 839) is under-defined | The one-facility-per-facility-org invariant, 5.2 |
| G3 | The operator's reach to a facility is "any `facility_programme` row for its trail", including `declined` and `left` | An operator can invite staff into a facility that has left the programme | Raised for the gate in 6.1; a `participation` filter is a one-line change |
| G4 | `partner_invite` rows are never purged (they carry `invitee_email`) | Unbounded retention of staff email addresses | Section 9 |
| G5 | No CORS handling; a content-type check that a simple cross-site request can satisfy | A browser PWA cannot call any function; and without a server-side Origin refusal, pre-auth endpoints are reachable by simple requests | S1.2, 4.6 |
| G6 | `api.my_partner_invite` returns `token_hash` and `invitee_email` of every pending invite to **every member of the org, staff included** | Mild, but staff-visible PII | Revoked with G1 |
| G7 | **Staff authority exists under a plain `user` binding** (E21) and, more generally, the lane boundary does not exist: a transaction bound under any kind has the player lane's whole write surface (E3) | A partner design that adds a binding kind on `edge_actor` ships green and separates nothing | D5 (new role), 4.3, X9 |

## 3. The mechanism decision

The plan's two options, plus the hybrid it hints at (SimpleWebAuthn that mints a project JWT), against the proposed direction (C).

### 3.1 Comparison

| Criterion | A: Supabase Auth passkeys | B: SimpleWebAuthn, mints a project JWT | C (proposed): SimpleWebAuthn, opaque DB sessions |
|---|---|---|---|
| Status | The Supabase docs page says "Passkey support is experimental ... may change without notice" and needs an opt-in in the client `[verified 2026-10-04: docs page read from the supabase/supabase repo, master]` | Library mature (v14.0.3 on the registry `[verified: registry query]`); the minting is custom | Same library; the session layer is custom |
| User verification **required** | The handlers call `BeginDiscoverableLogin()` and `BeginRegistration(user, WithExclusions(...))` with no UV or resident-key option, and the docs show no setting `[verified: three handler files read from supabase/auth master; whether the hosted product differs is unverified]` | Ours: `required` (library output and a software-authenticator test, section 14) | Same as B |
| Proof that a session came from a passkey | A passkey login ends in the ordinary `issueRefreshToken(... PasskeyLogin ...)` `[verified: source]`. Whether the JWT's `amr` records it is `[unverified - training knowledge]` | The token exists only after verification | The session row exists only after verification |
| New secret in an Edge function | None | **The project JWT signing secret**: a function holding it can mint a token for any uid and any `role` claim, contradicting the repo's lint posture (the service key appears in exactly two places, `privileged.ts:579` (`adminClient`) and `:3079` (`isServiceRoleBearer`)). Asymmetric signing keys that a function cannot use are `[unverified]` | None. The token is random; the database stores a hash |
| Revocation | GoTrue session and JWT lifetimes | A minted JWT is valid until `exp` unless every function also checks the database | Instant: checked in the database on every call |
| Clone detection | The handler stores the sign count; `CloneWarning` is referenced in none of the three files read `[verified: grep]` | Ours | Ours |
| Per-role session length (admin short) | Global GoTrue settings `[unverified]` | Ours via `exp` | Ours |
| Offline countersign (plan §7.6 case 2, A60) | No such API | Ours | Ours |
| Passkey-gated reads through PostgREST | No (the JWT is reachable by email OTP) | Yes, if the JWT is only ever minted after a passkey | **No, by design**: partner reads move to Edge reads and the PostgREST surface is revoked (D12) |
| Supply chain | None | 25 npm packages + the signing secret | 25 npm packages |
| Build cost | Lowest | Highest | Middle |

### 3.2 Reading the table honestly

- **B's one real advantage is the read path.** A passkey-minted Supabase JWT is the only variant under which the plan's `has_facility_scope(auth.uid())` views stay usable by the portal. C gives that up on purpose and pays for it with Edge reads (5.5). The price of B is a secret that can mint anything, in the same process as the handlers, and an authority that outlives revocation by the JWT lifetime. This repo has spent three PRs moving the other way (edge doc sections 12-14).
- **A is the cheapest and probably the right end state**, and it is not available for P5.1a: it is experimental, it cannot be shown to enforce UV, and it cannot show a downstream function that a session came from a passkey. Credentials cannot be migrated later (private keys do not move), but a re-enrolment under the same RP ID is one passkey tap per person.
- **C's weak point is that the Edge runtime is the verifier.** Whether the database can check an ECDSA or RSA signature itself is `[unverified]`: no extension on a hosted Postgres does it, but RS256 is a modular exponentiation and ES256 is scalar multiplication on P-256, both expressible in PL/pgSQL `numeric` arithmetic with unmeasured performance. That was the S0 spike (4.4). **Resolved by the S0 gate ruling (section 15.2, recorded in 16.4): the spike passed (ES256 35.5 ms, RS256 3.7 ms worst warm call), so database-side signature verification is now the plan of record for sign-in sessions** (S1.1b puts a SQL verifier inside the mint definer). The passkey half of R-P1 closes for sign-in; registration still carries no signature (R4-L2). The separate re-verifier below is moot.

### 3.3 Verdict and revisit triggers

C, as the owner proposed. Revisit A when **all** hold: Supabase passkeys are GA; the project can force UV required; a function can prove the method of a session (an `amr` entry or an `auth.sessions` column) and a short admin session can be enforced; and the player app wants passkeys anyway. The migration then re-enrols every staff member once; the tables in section 5 stay (sessions, PIN, TOTP are independent of where the passkey is verified).

## 4. Architecture

### 4.1 Principals, factors and session policy

| Principal | Enrolment | Sign-in | Step-up | Session idle / absolute `[proposed]` | Concurrent |
|---|---|---|---|---|---|
| Staff | invite, email OTP, passkey, PIN | passkey (UV) | PIN per action (A1) | 30 min / 8 h | 3 |
| Manager | same | same | PIN per action (A1); PIN **and** a passkey assertion at most 5 min old (A2) | 30 min / 8 h | 3 |
| Operator | invite from an admin, OTP, passkey, TOTP | passkey, then TOTP (`aal` 2) | TOTP at most 5 min old (A3) | 15 min / 4 h | 3 |
| Admin | a row in `app.admin_user` written by ops (E17), then a single-use enrolment token (6.4), passkey, TOTP | `aal` 2 | TOTP at most 5 min old for every A3 action | 10 min / 1 h | 2 |
| Sponsor | none before P6. The binder refuses a member whose only active role is `sponsor` | - | - | - | - |
| App-review demo account | refused by the binder (plan §4.7.7: any partner route is 403) | - | - | - | - |

**The assurance a session needs is the highest role the person holds** (admin > operator > manager or staff), recomputed on every call, and it gates **every class including A0** (6.3). An `aal` 1 session of an operator or admin is refused every call except sign-out, lock, `GET session` (which reports the required assurance), `session/step-up/totp`, **and, only while the person has no confirmed TOTP**, `totp/enrol`, `totp/confirm`, `session/otp-proof/*` and `session/reauth` (without these a new operator or admin could never enrol, because enrolment itself needs the OTP proof or the enrolment window, 6.4). The enrolment gates of 6.4 still apply to them, so a passkey alone never reads another facility's shift log (plan §3.6 lines 446-448). A person promoted to operator keeps an old session, but it is usable for nothing except the TOTP step-up that raises it to `aal` 2.

**What the factors prove on a shared device.** On a shared shop iPad the user verification of a passkey is the **device passcode** (or a biometric enrolled on that device), so a session for *any* member whose passkey is on the iPad needs only the passcode. The passkey therefore proves the device, not the person. **The PIN is the only per-person factor** (plan §9.2, FM-20), which is why every evidence-minting action asks for it (A1) and why adding a credential asks for it (A2).

Why these numbers (all `[proposed]`): a pro-shop shift is about 8 hours; re-authentication is one passkey tap; staff sessions must outlast a quiet hour at the till. Admin and operator sessions run on personal laptops. The owner should tune them from pilot telemetry (Q2).

### 4.2 The request path

```
PWA --Authorization: Bearer gr_ps_<43 chars>--> Edge function (verify_jwt = false)
  1. Origin check, CORS, strict media type, strict zod body, 64 KB cap (4.6)
  2. sha256(token) in the Edge. The raw token is never logged, never stored, never sent to the database
  3. openScopedTx("partner", partnerBind(hash))
       SET LOCAL ROLE edge_partner; timeouts;
       select private.bind_partner_session(hash)   -- refuses if ANY binding already exists in this
                                                   -- transaction; binds kind='partner', session_id
       assertion: current_user = 'edge_partner', not SUPERUSER or BYPASSRLS,
                  private.partner_binding_kind() = 'partner'
  4. handler op -> private.<action>_for_partner(...)    (a named definer, never a table statement)
       first statement: private.partner_authorize(facility, trail, roles[], class)
  5. write + audit in the same transaction; response `cache-control: no-store`
```

**What the post-bind assertion is worth.** Revision 1 compared two values the database itself returned, which can never fail. The Edge assertion now checks that the transaction runs as `edge_partner` (so no `edge_actor` privilege exists) and that `private.partner_binding_kind()` is `'partner'` (an `edge_partner`-executable helper, 4.3). It does **not** call `private.actor_uid()`: that function is granted to `edge_actor` only (`0030:568`) and is not granted here. The property "the user lane sees no actor" is enforced where it can be: `bind_partner_session` itself checks, from the binding row it just wrote, that the row's kind is `partner` (which is exactly the condition under which `actor_uid()` returns NULL), and PA-3 proves `actor_uid()` is NULL under a partner binding by calling it as `edge_actor`. `bind_partner_session` also **refuses when any binding already exists in the transaction**, as `bind_actor_internal` does (0030, `42501`), so a transaction cannot be re-bound.

`bind_partner_session` accepts a session only if **all** hold: the hash exists; `revoked_at` is null; idle and absolute expiry have not passed; the bound credential exists and is not revoked; the user is not a demo account; the user holds at least one non-revoked membership whose role is not `sponsor`, or is in `app.admin_user`. Every failure raises the **same** SQLSTATE and message and the handler answers one constant `401` body, so there is no oracle between unknown, expired and revoked.

**Idle is extended only by user-initiated calls.** `last_seen_at` advances at most once a minute and **only on routes the server classifies as interactive**. Routes the server marks keep-alive-exempt (the course-QR token refresh that runs every 30 s while a sale screen is shown, `GET session` polling) never advance it. The classification is server-side, by route, never a client flag. The refresh route is class A0, bound to a nonce that an A1 mint created, and cannot create new authority (S2b specifies it; as built, section 24: it reads the state of the person's own token, class `A0_KEEPALIVE`).

`openScopedTx` needs a small extension (S1.2): today an actor kind must know the expected uid before it binds (`privileged.ts:317`, `:413`). The partner bind returns no uid to the handler's authority: the handler never supplies one. `getActorFromRequest` (`privileged.ts:486`) must **reject** a bearer that starts `gr_ps_` or `gr_inv_` before sending it to GoTrue, so a partner token is never forwarded to a third party (PA-11).

### 4.3 The lane, the binding and the one authorization seam

**The lane is a role.** A new role `edge_partner`: `NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION`, a member of nothing, `edge_gateway` its only member `WITH INHERIT FALSE, SET TRUE` (the 0030/0041 shape), `USAGE` on schema `private`, **no privilege on any table, sequence or schema `app`**, and `EXECUTE` on exactly: `bind_partner_session`, the read-only helpers `partner_binding_kind()` and `partner_binding()`, the `_for_partner` definers and the partner rate-limit twin `hit_partner_rate_limit` (the same list as 5.3, and what check 12 asserts, no more). It has no `EXECUTE` on `bind_actor`, on `private.actor_uid()`, on any user-lane definer, or on any `edge_actor` function. Because every `edge_actor` policy is `TO edge_actor`, a transaction running as `edge_partner` meets none of them.

**Defence in depth, because `edge_gateway` can `SET ROLE` to any edge role** (the "KNOWN LIMIT" of 0041): `private.actor_uid()` is redefined (same owner, ACL and signature) to return NULL when the binding's `kind = 'partner'`. A partner binding is therefore invisible to every `edge_actor` policy and every user-lane definer, including the four that check only `actor_uid()` (E3). Partner definers read the binding through a new `private.partner_binding()`, not `actor_uid()`.

**The binding.** `private.actor_binding.kind` gains `'partner'`, and the table gains a nullable `session_id`. Only `bind_partner_session` can write a `partner` row (it is not reachable through `bind_actor_internal`'s existing callers). Both directions are tested (PA-3): a `partner` binding is refused or invisible everywhere in the user lane, and a `user` binding is refused by every `_for_partner` definer.

**`private.partner_authorize(p_facility_id, p_trail_id, p_roles, p_class)`** is `SECURITY DEFINER`, **VOLATILE**, `search_path = ''`, EXECUTE for **nobody** (called only from sibling definers, the `offline_seed_derive` shape). In order it:

1. requires a `partner` binding in this transaction;
2. **locks the session row first** (`FOR SHARE`; `FOR NO KEY UPDATE` when this call will write the row, which is every call that consumes a PIN grant or advances `last_seen_at`, because two `FOR SHARE` holders that both then UPDATE the row deadlock) and checks it is live now (idle, absolute, not revoked, credential not revoked);
3. re-reads role and scope through `has_facility_scope` / `has_trail_scope` with an **explicit role array** (never `partner_role_rank`, whose `sponsor` ties `operator` at 3), with the session row already locked, so a concurrent revoke, scope change or admin change either waits for this transaction (its trigger cannot touch the locked session) or is seen by it (no check-then-act gap; the mechanism is below);
4. requires the session's `aal` to meet the person's required assurance **for every class** (4.1), and then the class prerequisite (6.3), consuming any single-use PIN grant in this same transaction;
5. fails **closed** on a class whose prerequisite is not implemented yet (S1.1 ships `partner_authorize` with A2 and A3 refusing everything until S1.3 and S1.4 enable them; no interim relaxation is allowed, PA-4b);
6. returns the member's uid.

Every refusal is `42501`, which the handler maps to `403` (or `404` where the plan's matrix says a foreign id must not be probeable).

**How the locks work (gate rounds 2 and 3).** Row locks (`FOR SHARE`, `FOR NO KEY UPDATE`) need UPDATE privilege on the table and apply the **UPDATE policy's USING clause** under FORCE RLS, so with no matching policy `SELECT ... FOR SHARE` returns **zero rows without an error** and `EXISTS (... FOR SHARE)` is false `[verified 2026-10-04: reproduced by the author on PostgreSQL 17.11, section 14]`.

Revision 3 answered that with `WITH CHECK (false)` lock policies on `partner_member` and `partner_scope`. **That was wrong (gate round 3).** Permissive policies are OR-ed, and `private_definer` already holds table-wide UPDATE (`0016:341`) and the permissive `pd_setnull_partner_member_invited_by` policy, `USING (invited_by = <GUC>) WITH CHECK (invited_by IS NULL)` (`0016:255`). The lock policy's `USING` makes a row visible to UPDATE, and the *other* policy's `WITH CHECK` then passes any update that leaves `invited_by` NULL, so `UPDATE ... SET revoked_at = NULL, role = 'manager', invited_by = NULL` **succeeded** and un-revoked and promoted a member. `[verified 2026-10-04: reproduced by the author on PG 17.11 with both policies present, section 14]` A policy added to make a lock possible must therefore never be a policy on a table that carries authority.

**Adopted design: serialise through the session row only.** No lock policy exists on `partner_member`, `partner_scope` or `admin_user`.

- `partner_authorize` locks **only the actor's session row** (`FOR SHARE`; `FOR NO KEY UPDATE` when the call writes it), **before** it reads membership or scope. The policy this needs is on `partner_session`: `pd_partner_session_action`, `USING (id = private.partner_binding_session())` and the same `WITH CHECK`, which also lets the action write `last_seen_at`, consume a PIN grant and record its own verification results. **That policy lets a partner-bound definer UPDATE any column of its own session row, so a trigger and column grants narrow it (R4-L1, below).**
- **Every change to authority already touches that user's sessions**, in the same transaction as the change, by trigger (5.2): any `partner_member` update of `revoked_at` or `role`, delete (an org-delete cascade included) or insert; any `admin_user` insert or delete; and, new in this revision, any `partner_scope` update or delete, which **touches** (does not revoke) the sessions of the org's members by setting `authority_touched_at`. That session UPDATE **waits** for an in-flight action's lock on the session row. So a revoker's transaction cannot commit while an action that relied on the old authority is still open, and an action that starts after the revoker holds the session lock waits and then re-reads (READ COMMITTED, a fresh snapshot per statement) and sees the change. The membership, scope and `admin_user` tables are never locked by a partner call, so no policy on them is needed.
- The triggers' UPDATE of other users' sessions runs as a **dedicated role, not as `private_definer`, and there is no GUC window anywhere** (gate round 4, R4-M1; the full account of who writes `partner_session` is below).
- **`facility_programme` changes take effect from the next call (R3-N2).** The operator leg of `has_facility_scope` reads `facility_programme` (E6); a change there (a facility leaving a trail) is **not** serialised against an in-flight action, because it is not authority held by a member. An action already inside its transaction finishes; the next call sees it. The same is true of a role *rank* change that is not a `partner_member` write.
- **The OR rule is a standing review item (R3-M1).** Every `private_definer` policy on `partner_member`, `partner_scope`, `partner_session` and `admin_user` is evaluated **OR-ed with every other policy and with the table-wide grants** (`0016:341`). S1.5's revoke and accept definers add their own policies on these tables; each must be reviewed against the **union**, not alone, and the pgTAP cell below is run with **all** existing `private_definer` policies installed.

**Who may write `partner_session`, and why no GUC window (gate round 4, R4-M1).** Revision 4 let the triggers' cross-session UPDATE through a transaction-local GUC window. That breaks the money doc's HARD RULE (line 3833): `set_config` is open to every session, `edge_partner` included, and a transaction-local GUC **persists into a later `SECURITY DEFINER` call**, because the definer's `SET` pins only `search_path`. `[verified 2026-10-04: reproduced by the author on PG 17.11, section 14]` With an own-session policy `USING (id = own)` and a window policy `USING (window = 'on')` on `private_definer`, a definer `revoke_session(2)` returned 0 rows without the window and **1 row** (another user's session revoked) after the caller planted it; and an own-session `UPDATE ... SET user_id = 200, aal = 2` returned 1 row. Policies are **per role**, so the rule is: **`private_definer` never gets a wide `partner_session` policy; each wide writer is a different, dedicated role that nobody can become.**

Three new roles (**five as built**: the `flagger` below was dropped at the S1.1a gate, and the three verifier-owner roles of R5-L1 join the other two, 16.2), each `NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS`, **a member of nothing and with no member** (the migrating role holds membership only for the length of the migration, to `ALTER FUNCTION ... OWNER`, then loses it; check 9 asserts no role is a member of them and none is reachable by `SET ROLE`), a policy `TO` that role keyed on **nothing settable** (`USING (true)`), and column-level grants that are the real limit:

| Role (function owner) | Privileges on `partner_session` (and others) | Functions it owns |
|---|---|---|
| `partner_session_toucher` | `SELECT`, and `UPDATE (revoked_at, revoke_reason, authority_touched_at)`; `SELECT` on `partner_member`, `partner_scope`, `partner_credential`; `UPDATE (revoked_at, revoked_by, revoke_reason)` on `partner_credential` | the authority triggers (5.2); `private.partner_sessions_revoke(user_ids, reason)` (EXECUTE for `private_definer` only, called by the member-revoke, recover, revoke-all, credential-revoke and TOTP-reset definers **after** their own reach-rule and scope checks); `private.partner_flag_enforce(max)` (EXECUTE for `edge_system`) |
| `partner_session_issuer` | `INSERT` and `SELECT` on `partner_session` (and on `partner_credential` for `register_first`) | the mint definers and `register_first`'s insert path; evicting the oldest session goes through `partner_sessions_revoke` |
| ~~`partner_session_flagger`~~ | **removed at the S1.1a gate** (the S1.6 re-verifier is moot, 16.4): the role, its two policies and the `flagged_at` / `flag_reason` columns are not in 0047 | none |

Every writer, so none is a surprise: (1) the **action** writes (own session, `private_definer`, `pd_partner_session_action`); (2) **mint and `register_first`** insert (`issuer`); (3) the **PIN, TOTP, reauth and OTP-proof definers** record their verification on the bound session (`private_definer`, own-session policy, plus the guard trigger below); (4) **sign-out** and own revoke (`private_definer`, own session, revoke direction only); (5) **member revoke, recover, org revoke-all, credential revoke and TOTP reset** (`toucher` helper); (6) the **authority triggers** (`toucher`); (7) the **S1.6 flag** (`flagger`); (8) the **system-lane enforcement** (`toucher`, below). None of the eight is keyed on a GUC.

**R4-L1: the own-session policy must not let a definer rewrite its own row.** A BEFORE UPDATE guard trigger `partner_session_guard` on `partner_session` (SECURITY DEFINER, so it can read the artefacts) plus narrowed column grants (`private_definer` may UPDATE only `last_seen_at`, `aal`, `mfa_until`, `pin_grant_until`, `reauth_until`, `otp_proof_until`, `otp_proof_gotrue_session_id`, `revoked_at`, `revoke_reason`; the three roles above only their own columns) enforce the table below. **The mechanism for the verification-gated columns, as decided by gate round 5 (R5-L1) and built in S1.1a, is a ROLE, never a GUC and never an `xmin` comparison.** Three further NOLOGIN owner roles, `partner_pin_verifier`, `partner_totp_verifier` and `partner_reauth_verifier`, each hold the column-level `UPDATE` on exactly the columns its verification gates (`pin_grant_until`; `aal` and `mfa_until`; `reauth_until`), each with its own `TO <role>` policy keyed on the bound session, and `private_definer` holds none of those columns. The PIN, TOTP and reauth definers (S1.3, S1.4, S1.5) are owned by their verifier role, so a definer that skips the verification cannot write the column: there is no artefact row to forge and nothing to compare. The guard keeps the immutability, monotonicity and now + N caps of the table below. (The earlier `xmin` text was withdrawn: `xmin` proves a row changed in this transaction, not that verification succeeded.)

| Column(s) | May change only when |
|---|---|
| `id`, `user_id`, `credential_id`, `token_hash`, `created_at`, `mint_*`, `mint_kind`, `enrolment_until` | **never** after insert (`enrolment_until` is set at insert by `register_first`) |
| `expires_at` | it may **not increase** |
| `revoked_at`, `revoke_reason` | null to non-null only; **never back to null** |
| `aal` (1 to 2 only) and `mfa_until` | written only through the `partner_totp_verifier` column grant (S1.4's TOTP definer is owned by that role); the guard: `aal` never decreases, `mfa_until` at most now + 5 min |
| `pin_grant_until` (set) | written only through the `partner_pin_verifier` column grant (S1.3's PIN definer is owned by that role); at most now + 60 s. **Clearing to NULL** (consumption, `partner_pin_grant_consume()`) is always allowed |
| `reauth_until` | written only through the `partner_reauth_verifier` column grant; at most now + 5 min |
| `otp_proof_until` with `otp_proof_gotrue_session_id` | both change together, and that GoTrue session id exists in `auth.sessions` for this user and is fresh (the 0041 check); at most now + 10 min; a `UNIQUE` index makes one GoTrue session prove at most one proof (R5-L1, the 0041 shape); no artefact row |
| `last_seen_at` | monotone (never decreases) |
| `authority_touched_at`, `flagged_at`, `flag_reason` | only by the owning role's column grant |

**The S1.6 flag and enforcement, specified without a GUC.** The flag definer is owned by `partner_session_flagger` (above) and writes only `flagged_at` and `flag_reason`. `partner_flag_enforce(max)`, owned by `toucher` and executable by `edge_system`, revokes (via its own grants) only sessions where `flagged_at IS NOT NULL AND revoked_at IS NULL`, at most `max` (k per hour) per run; it revokes a credential only when **two sessions of that credential carry independent flags**; it writes `audit_log` and the operator alert. Its UPDATE is covered by the `toucher` policy and column grants, and the guard trigger still refuses an un-revoke.

PA-4 asserts the serialisation is **effective**: with an action transaction open, a member revoke and a scope DELETE each issued from a second connection **wait** (seen in `pg_locks`) and complete only after the action commits. PA-4c is the must-fail cell for the OR rule: with every existing `private_definer` policy installed, an UPDATE of the bound user's `partner_member` row under a partner binding (including `SET revoked_at = NULL, role = 'manager', invited_by = NULL`) is refused or affects 0 rows.

**Check 14: making "forgot to call it" fail the build** (`tools/db/verify-function-inventory.mjs` and its matrix twin), three clauses:

- (a) every function named `*_for_partner` has `private.partner_authorize(` as its **first executable statement** (the body is parsed with comments and whitespace stripped, so a comment cannot satisfy it), **and** has one behavioural pgTAP cell: called under a partner binding with no scope it raises `42501`;
- (b) **no `edge_actor`-executable definer outside that family evaluates partner scope**: its body must not call `has_facility_scope`, `has_trail_scope`, `has_sponsorship_scope`, `is_staff_or_manager_of_facility`, `is_manager_or_operator_of_facility`, `is_operator_of_facility`, `is_org_member`, `is_admin`, nor read `partner_member` or `partner_scope`. This is what finds `offline_code_record_step_for_actor` today (E21);
- (c) no function outside the family reads `kind = 'partner'`, **except a named exception list in the checked-in fixture**. S3 needs a predicate like `offline_code_bound_staff()` for a partner-bound verify-and-record; it is added as a `partner_bound_*` function inside the family, or listed, never silently allowed.

Each clause has a must-fail fixture (a planted function).

### 4.4 The minter role

A role `edge_partner_minter`, shaped exactly like `edge_signin_minter` (`0041:61-103`): `NOLOGIN NOINHERIT NOBYPASSRLS`, a member of nothing, `edge_gateway` its only member `WITH INHERIT FALSE, SET TRUE`, `USAGE` on schema `private`, `EXECUTE` on exactly the mint definers and nothing else (checked by check 12). `openScopedTx` gains a kind `"partner_mint"` that runs as that role and binds nothing; the privileged lint's `privileged-mint-scope` rule is generalised to allow that kind only inside `openScopedTx` and one named caller module.

| Mint definer (EXECUTE: `edge_partner_minter` only) | What it does |
|---|---|
| `partner_challenge_issue_sign_in()` | **the only externally callable issuer**, and it accepts **only** `sign_in` (R3-M2): stateless, no row written (5.1): returns 32 random bytes plus a token `exp || HMAC` over the encoding of 5.1. There is no purpose or binding argument to choose |
| *(register challenges)* | issued **only inside** `partner_invite_accept` and `partner_enrolment_token_accept`, after all their checks pass, and returned in the `accept/verify` response; the HMAC binds uid, invite-or-token id and acceptance time (5.1) |
| *(reauth challenges)* | issued by a `_for_partner` definer (`partner_session_reauth_options_for_partner`) that takes the **session id from `partner_binding()`**, not from an argument |
| *(no separate consume step)* | single use is enforced **at mint**: `partner_session_mint` (and the register and reauth definers) recompute the HMAC, check `exp`, and `INSERT` the used challenge's `sha256(nonce)` as a primary key, so a replay is a unique violation (5.1) |
| `partner_credential_lookup(credential_id)` | public key, sign count, user id, algorithm; one uniform "not found" for unknown or revoked |
| `partner_session_mint(...)` | see below |
| `partner_invite_email_for_token(token_hash)` | returns the `invitee_email` of a live invite (or nothing) to `accept/start`; the Edge never returns it to the client (the response is constant) |
| `partner_invite_accept(token_hash, verified_uid, gotrue_session_id)` | 6.1: checks credential and membership status **before** writing |
| `partner_enrolment_token_*` (`email_for_token`, `accept`) | recovery and admin enrolment tokens (6.1, 6.4) |
| `partner_credential_register_first(...)` | first credential of a person with **no** active credential **and, for an invite-bound enrolment, no active membership in any other org** (6.1, R2-L1); refuses otherwise. It **re-verifies** that the bound invite or token was accepted by that uid **less than 15 minutes ago**, and records on that invite or token that it has produced its credential (`registered_credential_id`): **one registration per acceptance**. **DB-side checks it must make (R4-L2)**, every one a create ceremony allows: `clientDataJSON` parses with `type = 'webauthn.create'` and `crossOrigin` not true; `origin` equals `partner_rp_config.origin` and `challenge` equals the nonce of the bound HMAC challenge; the attestation object's `fmt` is `'none'`; `authenticatorData` has `rpIdHash = sha256(partner_rp_config.rp_id)` and the **UP, UV and AT** flags set; the credential id and the COSE key **parse**, the key's algorithm is `-7` or `-257`, and the key and credential id equal the columns being stored. It **mints the first session in the same transaction** (R3-L3): the session row stores the create ceremony's evidence, `mint_kind = 'register'`, and the nonce is recorded once, so a later `partner_session_mint` on the same challenge would fail on the used nonce and is never needed |
| `partner_session_otp_proof(token_hash, verified_uid, gotrue_session_id)` | sets `otp_proof_until` (10 min) on a live session of that uid, if the GoTrue session for that uid is fresh (the 0041 mechanism); needed for first PIN set, `must_change` and first TOTP enrolment (6.3, 6.4) |

**`partner_session_mint` checks what the database can check.** The Edge verifies the signature (the database cannot, section 3.2); the definer additionally verifies, from the raw bytes it receives: that `clientDataJSON` parses, has `type = 'webauthn.get'`, `crossOrigin` not true, `origin` equal to the configured origin and `challenge` equal to the consumed challenge; that `authenticatorData` has `rpIdHash = sha256(configured rp_id)`, the UP and UV flags set, and a counter equal to the `new_sign_count` argument; that the challenge's HMAC verifies for this purpose and binding, `exp` has not passed and its `sha256(nonce)` is not already recorded; and that the credential's sign count advances by compare-and-set. The configured `rp_id` and origin come from `app.partner_rp_config` (5.1), a one-row table written by ops at deploy, so staging and production differ. A forged mint therefore has to fabricate consistent client data and authenticator data bound to a real, just-consumed challenge; the only thing it can still forge is the signature itself.

**SUPERSEDED (S0 gate ruling, 16.4): the re-verifier below is moot.** The S0 spike showed database-side verification is practical, so S1.1b verifies the signature **inside the mint definer** and slice S1.6, `partner_reverify_batch`, `partner_reverify_flag`, the login `partner_audit`, `partner_flag_enforce` and the out-of-runtime job (open item U2) are not built. The `partner_session_flagger` role, its policies and the `flagged_at` / `flag_reason` columns were built in the first S1.1a pass and **removed at the gate**; the `mint_*` evidence columns stay. The text that follows is kept as the record of the alternative.

**What the signature gap costs, and what was scheduled.** The raw assertion (authenticator data, client data JSON, signature; about 400 bytes) is kept on the session row for 30 days. Slice **S1.6** adds the **re-verifier**, specified as follows (R2-L7).

- **What it reads.** The database already checked everything except the signature (4.4), so the job needs only, per mint: `mint_authenticator_data`, `mint_client_data_json`, `mint_signature`, and the credential's `public_key` and `alg`. (It needs neither the challenge bytes nor `partner_rp_config`: those were checked at mint.) It **deliberately skips `register`-kind sessions**: an `attestation: none` create ceremony carries no signature, so there is nothing to re-verify (R-P1). One definer, `private.partner_reverify_batch(after_id, limit)`, returns exactly those columns for sessions not yet re-verified, bounded.
- **What it writes.** One narrow definer, `private.partner_reverify_flag(session_id, reason)`, **owned by `partner_session_flagger`** (4.3; not `private_definer`, and no GUC), sets `flagged_at` and `flag_reason` on a session. It revokes nothing itself. A **system lane step** (`private.partner_flag_enforce(max)`, owned by `partner_session_toucher`, executable by `edge_system`; specified in 4.3) in the existing hourly Edge scheduler (the `retention-purge` pattern, `edge_system`) acts on flags: it **revokes only the flagged session**, writes `audit_log` and raises the operator alert. **Revoking the credential needs a second independent flag** (a flag on a different session of the same credential, from a separate re-verification run) **or an operator's decision**, because `partner_reverify_flag` is otherwise a mass-lockout lever: a compromised or buggy job (or a flood of bad rows) could revoke every credential. The alert fires when flags exceed **k per hour** (`k = 3` `[proposed]`), and an automatic session revoke is capped at the same k per hour so a flood degrades to alerts, not an outage. Revoking from the Edge is the safe direction: a compromised runtime that refuses to revoke is the case the re-verifier exists to *detect*, and the flag and the alert still exist.
- **Who may call them.** A new login `partner_audit` (LOGIN, NOINHERIT, no table or sequence privilege) with **`USAGE` on schema `private`** (it cannot call a function there without it) and `EXECUTE` on those **two** definers and **nothing else**; check 12 asserts exactly that pair of privileges (USAGE on `private`, EXECUTE on the two) and no other, the 0041 shape.
- **Where it runs.** **Not in the Edge runtime** (a compromised runtime would otherwise vouch for itself) **and not in GitHub Actions**: a database credential in a CI workflow sits badly with P3 acceptance test (7) ("no `service_role` secret in any CI workflow"). The login is not `service_role` and can read only signature material, so it is arguably outside that test's letter, but the safe reading is to avoid it. Default: a scheduled job on a **second runtime that holds only that login** (any scheduler the owner already operates for the site; the repository chooses none). The choice of host and the reading of AT(7) go to the S1.6 gate (U2).
- The S0 spike on database-side signature verification (3.2) may replace it for the passkey half.

| Attacker | Result |
|---|---|
| A handler bug or injected statement in a partner (`edge_partner`) transaction | cannot mint (`42501`); cannot bind another member; has no table privilege; the user lane is invisible to it |
| The same in an `edge_actor` or `edge_system` transaction | cannot mint; a `partner` binding is invisible to it (`actor_uid()` NULL) |
| A statement that can also `SET ROLE` (`edge_gateway` holds SET on every edge role) | **can reach the minter role**, as it can reach `edge_actor` today (0041's "KNOWN LIMIT (R6)"). It can mint a session for any member with consistent fabricated assertion data, until the re-verifier flags it |
| A fully compromised runtime (R6) | unchanged: it can already `bind_actor(<any uid>)` and act through every **user**-lane definer. For the **partner** lane it can mint a session for any member (above), and it sees each real token and PIN-equivalent that passes through it |

### 4.5 API surface

All under `/v1/partner/`. Three functions (one directory each, so the derived function inventory and the matrix stay small, plan §4.7.1a): `partner-session`, `partner-invites`, `partner-members`. Later slices add the plan's `partner-attest`, `partner-offers-redeem`, `course-qr`, `partner-entitlements-redeem`, `stock-admin`, `offers-admin`, `programme-config` and friends; each must carry matrix cells for every id it accepts.

| Route | Auth | Purpose |
|---|---|---|
| `POST session/options` | none (minter) | sign-in challenge (usernameless: `allowCredentials` empty, UV required) |
| `POST session` | none (minter) | `{challengeId, assertion}` to `{token, expiresAt, aal}` |
| `GET session` | session | who am I: roles, facility and trail scopes, required assurance, step-up state (all re-read) |
| `DELETE session` | session | sign out (revokes this session) |
| `POST session/reauth/options`, `POST session/reauth` | session | a fresh passkey assertion for this session: sets `reauth_until` (5 min). Challenge purpose `reauth`, bound to the session; the definer **asserts the assertion's credential belongs to the session's user** (a coworker's own passkey cannot satisfy it) |
| `GET session/pin`, `POST session/step-up/pin` | session | salt and iteration count; `{derived}` (derived **in the browser**) sets a single-use `pin_grant_until` (60 s, or 30 s for A2) |
| `POST session/step-up/totp` | session | `{code}` sets `aal` 2 and `mfa_until` |
| `POST session/otp-proof/start`, `.../verify` | session | email OTP to the member's own address; sets `otp_proof_until` |
| `POST session/lock` | session | clears every step-up grant now |
| `POST invites` | session, A2 | create a `join` invite |
| `GET invites`, `DELETE invites/{id}` | session | list / revoke, by definer, scoped |
| `POST invites/accept/start` | none | `{token}`: sends the OTP to the address on the invite (server-side, anon key) |
| `POST invites/accept/verify` | none (minter) | `{token, code}`: branch N (6.1) |
| `POST invites/accept` | session, A2 | branch E: an existing member joins another org |
| `POST enrolments/accept/start`, `.../verify` | none (minter) | recovery and admin enrolment tokens (6.1, 6.4) |
| `POST credentials/options` | session, **A2 + `reauth`** | options for **adding a second credential**. There is **no enrolment-mode `credentials/options`**: an enrolling person's `register` challenge comes back in the `accept/verify` response (6.1) |
| `POST credentials` | enrolment (minter, challenge from `accept/verify`) or session, **A2 + `reauth`** | register; the first one of a person mints their first session in the same transaction |
| `GET`, `PATCH`, `DELETE credentials[/{id}]` | session | list (A0), edit the **display note** only (A0), **revoke: A2 for every revoke, one's own included** (a coworker with the passcode must not be able to revoke all of someone's credentials), another member's under the 6.5 reach rule |
| `POST pin` | session | set or change own PIN (6.3) |
| `POST members/{id}/pin-reset`, `POST members/{id}/recover`, `POST members/{id}/revoke` | session, A2 | 6.5 |
| `POST orgs/{id}/sessions/revoke-all` | session, A2 | the "panic button" |
| `POST totp/enrol`, `POST totp/confirm`, `POST members/{id}/totp-reset`, `POST admin/enrolments` | session | operator and admin (6.4) |

Errors follow `_shared/http.ts` (`errorResponse(status, code, message)`); a bad session is always the same `401 unauthenticated`.

### 4.6 Transport: header in memory, not a cookie

> **Origin and RP ID (S0-N1, recorded at S1.1b).** The wrapper accepts an origin whose host is the RP ID **or a subdomain of it** (`webauthn.ts`), while this design says "one exact origin". The two are consistent: a subdomain is a *permitted shape for the configured value*, not a set of accepted origins. The configured origin is a single string (`app.partner_rp_config.origin`), and **both** the wrapper and the database mint (S1.1b) compare the assertion's `clientDataJSON.origin` to it by **exact string equality**, never by suffix, so an origin that is merely another subdomain of the RP ID is refused (`bad_origin`). The RP ID may be a registrable parent of the origin's host (so passkeys are shared across `partners.` and a future sibling host); the origin is what pins the page.

Chosen: the session token lives in a JS variable in the PWA and travels as `Authorization: Bearer gr_ps_<43 base64url chars>` (the prefix makes it greppable by secret scanners). It is never written to `localStorage`, `sessionStorage` or IndexedDB.

| Concern | HttpOnly Secure SameSite=Strict cookie | Header in memory (chosen) |
|---|---|---|
| Needs a same-site API | **Yes.** The functions are served from the Supabase project host, a different registrable domain from `golfraven.<tld>` `[unverified - training knowledge: default function URL shape]`. A Strict cookie is not sent on a cross-site fetch at all. The ways round it are a same-site proxy (a new component that sees every token) or `SameSite=None`, which loses Strict and meets Safari's third-party cookie blocking on the iPad `[unverified - training knowledge]` | No |
| CSRF | Ambient authority: needs SameSite or a CSRF token | **No ambient credential**: a cross-site page cannot attach the token. A custom `Authorization` header forces a CORS preflight |
| XSS, token theft | The page cannot read the token | A script on the page can read it. **Mitigated, not removed**: strict CSP, no third-party script, no inline script |
| XSS, token *use* | Same page can still call the API with the cookie | Same. Neither option stops riding a live session; the per-action PIN, caps and the idle timeout bound it |
| Reload or iOS memory eviction | Survives | Lost: one passkey tap to sign in again. Accepted |
| Log exposure | Cookie headers are often redacted | `Authorization` is the header log tools redact by default `[unverified]`; our code never logs it (a source scan, as for the offline seed, money doc line 3817) |

**Pre-auth endpoints are reachable without a token**, so CSRF-by-simple-request matters for them (sign-in options, `accept/start`, which sends email). `readJsonBody` accepts a content type that merely contains `application/json` (E16), so `text/plain; x=application/json` is a CORS "simple" request that needs no preflight. Therefore, for every partner function (a new `readPartnerJsonBody`, the existing reader is left alone):

- the **media type must be exactly `application/json`** (a `charset` parameter allowed), anything else `415`, **before** the body is read;
- a request with an `Origin` header that is not the one allowed origin is refused `403` **by the server**, before routing, for every method, whatever CORS does in the browser; a request with no `Origin` (a non-browser client) is allowed, because no ambient credential exists to abuse;
- CORS itself is a new `_shared` helper: the allowed origin is one exact string from an environment variable, `Vary: Origin`, `Access-Control-Allow-Methods: GET, POST, PATCH, DELETE, OPTIONS`, `Access-Control-Allow-Headers: authorization, content-type`, `Access-Control-Max-Age` short, no `*`, no credentials mode, `OPTIONS` answered without touching the database. Any other origin gets no CORS headers.

Other hardening that goes with the choice (S1.2 and S7a):

- **`verify_jwt = false`** on the three partner functions, so the gateway does not demand a Supabase JWT in the header the partner token occupies `[unverified - training knowledge: per-function setting in config.toml; edge doc section 15 item 7 already treats the gateway check as not-the-authentication]`. A mistakenly enabled gateway check fails closed. The cost is losing the gateway's free filter of header-less floods.
- **CSP** for `apps/partners` (served with `_headers` on the static host `[unverified: host features]`): `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' <functions origin>; manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`, plus `Referrer-Policy: no-referrer`, `Permissions-Policy: publickey-credentials-get=(self), publickey-credentials-create=(self)`, `Cross-Origin-Opener-Policy: same-origin`. `require-trusted-types-for 'script'` is desirable and `[unverified]` on the iPad's Safari.
- **Proof of possession is deferred, with a reserved slot (N7).** A session could be bound to a non-extractable WebCrypto key generated at sign-in, each request carrying a signature, which turns the in-memory token from "stealable" into "rideable only from the page". It is **not built in P5.1a**. The S1.2 contract reserves it: `partner_session.pop_jkt` (nullable JWK thumbprint, set at mint when the client sends one) and a header name `X-GR-PoP`; a server that does not verify it ignores it, and turning it on later needs no schema change. The gate may require it before P5.2 go-live.

## 5. Data model

### 5.1 New tables (all in `app`)

Every one: `ENABLE` and `FORCE ROW LEVEL SECURITY`; `REVOKE ALL ... FROM PUBLIC, anon, authenticated`; **no** grant to `edge_actor`, `edge_system`, `edge_partner`, `edge_partner_minter` or `service_role` (these hold credential material; 0045 gave `service_role` SELECT on its replay table, these get nothing). Access is only through the definers in 5.3, and `private_definer` policies are keyed on the **binding** (`private.partner_binding()`), never on a settable GUC (the HARD RULE, E12).

| Table | Key columns | Notes |
|---|---|---|
| `partner_credential` | `id uuid pk`, `user_id` (FK `auth.users` cascade), `credential_id bytea unique` (at most 1,023 bytes), `public_key bytea` (COSE), `alg smallint` (-7 or -257), `sign_count bigint`, `transports text[]`, `backup_eligible bool`, `backup_state bool`, `aaguid uuid`, `label text` (**derived by the database**: creation date, the AAGUID or "unknown", and the creating credential's id prefix; never client-supplied), `note text` (at most 40, member-chosen, **display only, never used by a security decision**), `created_via_credential_id` (null for the first), `created_at`, `last_used_at`, `revoked_at`, `revoked_by` (FK, set null), `revoke_reason` | at most 5 active per user, checked in the register definers; the WebAuthn user handle is the uuid's 16 bytes `[proposed]` |
| `partner_auth_challenge` | `nonce_hash bytea pk` (`sha256` of the challenge nonce), `purpose` in (`sign_in`, `register`, `reauth`; `countersign` reserved for 6.7), `user_id`, `session_id`, `used_at`, `minted_session_id` | **rows exist only for challenges that were used.** Challenges themselves are stateless (below) |
| `partner_session` | `id uuid pk`, `token_hash text unique` (64 hex, CHECK), `user_id`, `credential_id`, `aal smallint` in (1, 2), `created_at`, `last_seen_at`, `expires_at` (absolute, fixed at mint), `pin_grant_until`, `reauth_until`, `otp_proof_until`, `enrolment_until` (15 min after `register_first`), `mfa_until`, `pop_jkt`, `revoked_at`, `revoke_reason`, `authority_touched_at`, `otp_proof_gotrue_session_id`, `mint_kind` (`sign_in` or `register`), `mint_nonce_hash`, `mint_authenticator_data`, `mint_client_data_json`, `mint_signature` (null for a `register` mint: an `attestation: none` create ceremony carries no signature), `flagged_at`, `flag_reason` | the assertion columns are the 4.4 evidence; the flag is the S1.6 re-verifier's (4.4) |
| `partner_pin` | `user_id pk`, `last_ok_at`, `salt bytea`, `iterations int`, `pepper_kid text`, `verifier bytea`, `failed_count smallint`, `failed_today smallint`, `last_failed_at`, `next_attempt_at`, `locked_at`, `must_change bool`, `set_at` | verifier is `HMAC-SHA256(pepper, PBKDF2-SHA256(pin, salt, iterations))` |
| `partner_totp` | `user_id pk`, `seed_version int`, `enrolled_at`, `enrol_session_id`, `confirmed_at`, `last_step bigint`, `failed_count`, `locked_until`, `revoked_at` | the seed is **derived** (below), never stored; 6.4 |
| `partner_enrolment_token` | `id uuid pk`, `user_id` (FK), `purpose` in (`recover`, `admin`), `issued_by` (FK, null for the ops bootstrap), `token_hash text unique` (64 hex), `expires_at` (at most 24 h), `consumed_at`, `registered_credential_id` (FK, set null), `revoked_at`, `attempts smallint` | no org: recovery and admin enrolment are about a person (6.1, 6.4, 6.5) |
| `partner_rp_config` | one row: `rp_id text`, `origin text` | written by ops at deploy; the mint refuses if the row is absent |

**Stateless challenges (R2-L6, R3-M2, R3-N1).** Revision 2 inserted a row per `session/options` call while the only limiter was alert-only (M6): an unauthenticated caller could grow the table without bound. Two ways out; the choice is the first. (1) **Stateless:** the challenge is 32 random bytes plus a token carrying `exp` and an HMAC with a Vault key `partner_challenge_key` (the pepper pattern, below); nothing is persisted when it is issued, and single use is enforced by inserting `sha256(nonce)` **at mint**, where the primary key refuses a replay. (2) A hard global insert ceiling: it bounds growth, but one attacker could exhaust it and lock every staff member out of sign-in, which is exactly the lever M6 removed. **Trade-off accepted:** a failed verification no longer burns the challenge; it can be presented again within its 120 s, but each attempt needs a real signature, the per-credential cooldown applies, and a success records the nonce.

**The HMAC message, fixed width like 0045.** `label || 0x00 || purpose || exp || nonce || binding [|| ref_kind || ref_id || accepted_at]`, with the label `golfraven/partner-challenge/v1` (UTF-8), `purpose` one byte (1 sign_in, 2 register, 3 reauth), `exp` an 8-byte big-endian integer (epoch seconds), `nonce` 32 bytes, `binding` a 16-byte uuid (zeros for `sign_in`; the enrolling uid for `register`; the **session id** for `reauth`). A `register` challenge appends `ref_kind` (1 invite, 2 enrolment token; one byte), `ref_id` (the invite's or token's 16-byte uuid) and `accepted_at` (8-byte big-endian epoch microseconds). Everything after the label is fixed length, so no two different tuples produce the same message. Verification recomputes the HMAC and compares **the HMACs of the two values** (`HMAC(K, presented) = HMAC(K, expected)`), so the comparison does not depend on a byte-by-byte equality of a secret-derived value.

**Why `register` challenges are issued only inside the accept definers.** Registration with `attestation: none` carries **no signature**, so the challenge is the only proof that an enrolment followed an OTP-verified acceptance. If the minter exposed an issuer for `register` with a caller-chosen binding, a handler bug could register an attacker's passkey for any uid in an enrolment gap. So the only code that can produce a `register` challenge is the code that has just verified the OTP, the email, the freshness and the credential and membership state, for **that** uid and **that** invite or token, and `register_first` re-verifies the acceptance (4.4). A challenge bound to invite X cannot enrol for invite Y because the invite id is inside the HMAC and `register_first` checks the acceptance row.

**PIN pepper and TOTP seed** use the offline-seed pattern (`0045:129-160`): a Vault secret (`partner_pin_key`, `partner_totp_key`, `partner_challenge_key`; at least 32 bytes), read in **one** `SECURITY DEFINER` core with `EXECUTE` for nobody, `public.hmac` in Postgres, a labelled fixed-length message (`'golfraven/partner-totp/v1' || 0x00 || user_id || seed_version`). Staging and production keys differ. The Vault call and `public.hmac` are `[unverified]` on a real project, exactly as 0045 records.

### 5.2 Changes to existing objects

| Object | Change | Why |
|---|---|---|
| `private.actor_binding` | `kind` CHECK adds `'partner'`; new nullable `session_id uuid` | D5 |
| `private.actor_uid()` | returns NULL when `kind = 'partner'` (same owner, ACL and signature) | 4.3 defence in depth |
| `app.partner_invite` | add `accepted_by` (FK `auth.users`, set null), `registered_credential_id` (FK, set null; one registration per acceptance), `revoked_at`, `revoked_by`, `attempts smallint default 0`; CHECK `token_hash ~ '^[0-9a-f]{64}$'`; CHECK `expires_at <= created_at + interval '7 days'` | E18. **The hex CHECK breaks the fixtures** at `supabase/tests/helpers.sql:261-265` (`'th-a-invites-y'`, `'th-y-invites-a'`) as well as the partner matrix; S1.1 updates them to 64-hex values. The 72 h default is the writer's, the CHECK is the ceiling |
| `app.partner_scope` | a trigger: an org of kind `facility` may hold **at most one** scope row, and it is a `facility_id`; plus `UNIQUE (org_id, facility_id)` | G2. A chain is one org per facility with the person a member of several; the portal shows a switcher (Q4). The request names the facility, and `partner_authorize` checks it per call, so there is no "current org" in the session |
| `app.partner_member` | a trigger tying `role` to the org's kind: `staff` and `manager` only in a `facility` org, `operator` only in an `operator` org, `sponsor` only in a `sponsor` org | N2, so role arrays can never be confused with `partner_role_rank` |
| `app.partner_member` | triggers that revoke the user's sessions on **`AFTER UPDATE OF revoked_at, role`, `AFTER DELETE` (including an org-delete cascade) and `AFTER INSERT`**, the accepting session itself exempt; revoking the **last** active membership deletes the user's `partner_pin` rows and, **unless the user is in `app.admin_user`**, their `partner_totp` rows (an admin holds no membership and needs the TOTP regardless). These UPDATEs of `partner_session` are also what serialises a revoke behind an in-flight action (4.3) | L3, R3-M1: a delete or re-insert by ops, or a cascade, must not revive an old session |
| `app.admin_user` | the same trigger on `INSERT` and `DELETE` | L3, R3-M1 |
| `app.partner_scope` | an `AFTER UPDATE` and `AFTER DELETE` trigger, owned by `partner_session_toucher` (4.3), that **touches** (sets `authority_touched_at` on) the sessions of every member of the org; it revokes nothing | R3-M1: scope loss is serialised behind an in-flight action like a revoke, without killing sessions |
| `private.function_inventory` | new columns `expected_edge_partner` and `expected_edge_partner_minter` (0041 added the same shape for the signin minter) | E9 |
| `api.offer`, `api.my_offers()`, policy `offer_read` | `offer_read` becomes `status = 'live'` (the scope legs are removed); `api.offer` and `api.my_offers()` return constant NULL for the five scope-conditional columns (`CREATE OR REPLACE VIEW` can append but not drop columns, `0024_evidence_queued_claims.sql:73-76`; the function is replaced the same way). The partner read moves to Edge | G1, M1 |
| `private.offline_code_record_step_for_actor` | `REVOKE EXECUTE ... FROM edge_actor`. **Kept, not deleted.** Only the Edge wrapper `Repo#offlineCode.recordStep` goes (removed in S1.2; `privileged.ts:3403` records why). Of the ~55 test references, the atomic-replay proofs (12 parallel calls give exactly one `recorded`; 12 across two facilities) are **kept** by calling the primitive as its owner: the harness writes the binding with `bind_actor` and then `SET LOCAL ROLE private_definer` in the same transaction. Only the cells that assert `edge_actor` can call it flip to "refused" | M3, X9. S3's verify-and-record definer supersedes the function, and the money doc's replay property stays proven meanwhile |

### 5.3 Functions

| Function | EXECUTE | Notes |
|---|---|---|
| `private.bind_partner_session(token_hash)` | `edge_partner` | the only producer of a `partner` binding; 4.2 |
| `private.partner_binding()`, `partner_binding_kind()` | `edge_partner` (read-only helpers) | return the binding row's kind and session id for the current transaction only. `partner_binding_kind()` is what the Edge's post-bind assertion calls (4.2) |
| `private.partner_binding_session()` | `private_definer` only | the predicate inside `pd_partner_session_action` (4.3); no edge role needs it |
| `private.partner_authorize(...)` | nobody | 4.3 |
| the mint definers of 4.4 | `edge_partner_minter` | refuse inside any bound transaction (the 0041 rule) |
| `private.hit_partner_rate_limit(key, window, max)` | `edge_partner` | the `hit_actor_rate_limit` body keyed on the session's user |
| `private.partner_whoami_for_partner()`, `partner_session_revoke_for_partner(...)`, `partner_session_lock_for_partner()`, `partner_session_reauth_for_partner(...)` | `edge_partner` | |
| `private.partner_pin_params_for_partner()`, `partner_pin_set_for_partner(...)`, `partner_pin_verify_for_partner(derived)`, `partner_pin_reset_for_partner(member)` | `edge_partner` | 6.3 |
| `private.partner_totp_enrol_for_partner()`, `partner_totp_confirm_for_partner(code)`, `partner_totp_verify_for_partner(code)`, `partner_totp_reset_for_partner(member)` | `edge_partner` | 6.4 |
| `private.partner_invite_create_for_partner(...)`, `..._revoke_...`, `..._list_...`, `partner_invite_accept_for_partner(...)`; `partner_member_revoke_for_partner`, `partner_member_recover_for_partner`, `partner_credential_register_for_partner`, `partner_credential_revoke_for_partner`, `partner_org_sessions_revoke_for_partner`, `partner_admin_enrolment_issue_for_partner` | `edge_partner` | |
| `private.partner_sessions_revoke(user_ids, reason)` | `private_definer` only | owned by `partner_session_toucher` (4.3); called by the revoke, recover, revoke-all, credential-revoke and TOTP-reset definers after their own checks |
| `private.partner_flag_enforce(max)` | `edge_system` | owned by `partner_session_toucher` (4.3, 4.4) |
| `private.purge_partner_challenges()`, `purge_partner_sessions()`, `purge_partner_credentials()`, `purge_partner_invites()`, `purge_partner_enrolment_tokens()` | `edge_system` | section 9; each `EXECUTE` grant is the same owner-approved shape as 0040 and needs the same sign-off |

**Failure paths return a status; they do not RAISE.** Every definer that updates a failure counter or an attempt count (`partner_pin_verify_for_partner`, `partner_totp_verify_for_partner`, `partner_invite_accept` and `partner_enrolment_token` accept, including the **email-mismatch refusal**, and the sign-in credential cooldown) returns a status row (`ok`, `wrong`, `locked`, `retry_after`, `refused`) and the handler commits. A RAISE would roll back the counter write, which is the defect 0020 fixed for the rate limiter (E11). Only malformed arguments and missing authority raise (`22023`, `42501`), and neither writes a counter. Tests assert the counter **after a real commit** (PA-18).

Every function: `SECURITY DEFINER`, owned by `private_definer`, `search_path = ''`, inside the ownership bracket (`SET ROLE private_definer` ... `RESET ROLE`, `0045:129-132,344`), `REVOKE ... FROM PUBLIC` then the grants above, a row in `private.function_inventory`, and must-fail cells.

### 5.4 The invariants checklist (what the gate should find in the migrations)

1. Every new table has FORCE RLS and no grant to `anon`, `authenticated`, any edge role or `service_role`. `private.edge_policy_allowlist` and its fixture are **unchanged** (no edge role holds a table privilege on them).
2. Every `private_definer` policy is narrow, keyed on the binding, and has a `private.definer_policy_allowlist` row plus a line in `supabase/tests/fixtures/definer_policy_exprs.txt`. This includes the two `partner_session` policies of 4.3, and **no policy is added on `partner_member`, `partner_scope` or `admin_user` for locking** (R3-M1); policies S1.5 adds there are reviewed against the OR-ed union.
3. Every FK to `auth.users` is classified in `private.pii_retention_policy` (`delete_row`, or `set_null` for `revoked_by`, `accepted_by`, `issued_by`) **and** has a `private.pii_export_policy` row (credentials: `export` of metadata without the public key; sessions, PIN, TOTP, challenges, enrolment tokens: `exclude` with a reason). Without them `delete_my_data` raises (E9). `delete_my_data` and `export_my_data` were last rebuilt in 0045 and 0044: the next change starts from those copies.
4. Every function has a `function_inventory` row, including both new role columns.
5. Checks 9-13 in `tools/db/verify-function-inventory.mjs` and `supabase/tests/matrix/10_function_inventory.sql` extend to **both** new roles (the 0041 edits are the template: attributes, membership closure, `NOLOGIN`, who can `SET ROLE`; for `edge_partner` and the minter, **no privilege on any relation** and no CREATE). The three session-writer roles of 4.3 (`partner_session_toucher`, `partner_session_issuer`, `partner_session_flagger`) are covered the same way: `NOLOGIN`, a member of nothing, no member, not reachable by `SET ROLE`, and holding exactly the privileges tabulated there and no other. Check 14 is new (4.3, three clauses). Each has a must-fail fixture.
6. `tools/db/check-migrations-immutable.sh` passes (no earlier migration is edited).
7. The privileged-file lint keeps its rules: no `service_role`, no new `Deno.env` read outside the allow-listed shapes, the new kinds only through `openScopedTx`. New env reads are limited to the exact CORS origin string; nothing secret is added to the environment (the pepper and TOTP key live in Vault, RP configuration in `partner_rp_config`).
8. Each new function directory is added to the three CI lists (`supabase/tests/unit/ci-function-lists.test.ts` fails the build until it is).
9. A matrix cell exists for every partner function times every id it accepts, including a foreign id (plan §4.7.1a).
10. A generated test enumerates, from the catalog, **every function EXECUTE-able by `edge_actor` and every policy `TO edge_actor`**, and proves each yields nothing or refuses under a planted `partner` binding (PA-3b). A future user-lane object is covered without anyone remembering.
11. After S1.1 no `edge_actor`-executable definer outside the `_for_partner` family evaluates partner scope (check 14 clause b).
12. Counter-writing definers return a status (5.3).

### 5.5 Revoking the PostgREST partner-lane read surface (D12)

One migration in S1.1. **Mobile is unaffected**: the app uses only the Auth client and no PostgREST read (E22). The views have no other consumer, so nothing breaks except `supabase/tests/matrix/06_partner_scope_matrix.sql`, whose cells are rewritten into "denied" cells, and `03_views_and_rpc.sql:100-110`, whose `api.my_offers()` masking cell for player B stays true and gains a cell for a scoped staff member (now also NULL).

`REVOKE SELECT ... FROM authenticated` on:

| Surface | Replaced by | Slice |
|---|---|---|
| `api.staff_shift_log` | `GET /v1/partner/shift-log` (A0, staff and manager of the facility) | S3 |
| `api.staff_activity` | `GET /v1/partner/staff-activity` (manager, operator) | S3 |
| `api.special_marker_stock`, `..._stock_movement` | stock read in `stock-admin` | S5 |
| `api.facility_programme`, `api.marker_code_batch`, `api.facility_qr`, `api.sponsorship`, `api.operator_rollup`, `api.sponsor_rollup` | `programme-config`, `qr-print`, `sponsorships-admin`, rollup reads | S2b, S6 |
| `api.my_partner_org`, `..._member`, `..._scope`, `..._invite` | `GET session` and `GET invites` | S1.5 |
| the **base tables** `app.partner_org`, `partner_member`, `partner_scope`, `partner_invite`, `facility_programme`, `attestation_shift_log`, `staff_activity`, `special_marker_stock`, `special_marker_stock_movement`, `sponsorship`, `operator_rollup`, `sponsor_rollup`, `marker_code_batch`, `facility_qr` (`0009_grants_revokes.sql:15-31`) | defence in depth: the views above are dead, so the table grants have no consumer and a future view must not inherit them | with the views |

**Redefined, not revoked** (players need them): `api.offer`, `api.my_offers()` and the `offer_read` policy (5.2). They answer players live offers only, with the five budget and eligibility columns NULL for everyone; the partner read of offers moves to `offers-admin` (S6). Left alone on purpose: `api.trail_programme`, `api.special_marker_availability` (readable by all authenticated players by design, plan §4.7.3) and the player-own `my_*` views.

## 6. Flows

### 6.1 Invite, accept, enrol

The invite rule, in the database (`partner_invite_create_for_partner`, class A2 or A3):

- **Role strictly below the inviter's own, by explicit array** (not `partner_role_rank`, whose `sponsor` ties `operator`, E6): a manager invites `{staff}`; an operator invites `{staff, manager}`; only an admin invites `{operator}`; `sponsor` invites stay disabled until P6.
- **Grant is a subset of the inviter's reach.** With the one-facility-per-org invariant (5.2) an invite names an org, and the inviter must pass `has_facility_scope(inviter, <that org's facility>, <the explicit above-roles array>)`: `{manager, operator}` for a staff invite, `{operator}` for a manager invite. That covers both "member of that org with a higher role" and "operator of a trail that includes the facility" (E6). Cells: manager invites at another facility: `403`; manager invites a manager or operator: `403`; operator invites at a facility not on its trail: `403` (plan §4.7.7).
- *For the gate (G3):* that operator reach ignores `participation`. Filtering `declined` and `left` out of `has_facility_scope`'s operator leg is a one-line change and is recommended.
- An invite to an org where the invitee already has an **active** membership **in that org** is refused (`409`). A **revoked** membership is reactivated with the invite's role: old sessions stay dead (6.5), the PIN is reset (`must_change`), and **no credential is created** if the person still has one (branch E below).
- The token is 32 random bytes, `gr_inv_` + base64url, generated in the Edge; **only its SHA-256** reaches the database (`token_hash`, 64 hex). The link is `https://partners.golfraven.<tld>/invite#<token>`: a fragment is never sent to a server, so no CDN or access log holds it, and a mail scanner that prefetches the link cannot consume it. Expiry 72 h `[proposed]`, hard ceiling 7 days (CHECK).

**Credentials belong to the person, so acceptance has two branches** (H3). The invite is org-scoped; a credential authenticates *every* membership the person holds. If an invite could create a credential for a person who already has one, any manager anywhere could mint a second credential on an existing member by inviting their mailbox to a second org.

- **Branch N: the person has no active credential.**
  1. `POST invites/accept/start {token}`. Rate-limited (section 8). The Edge asks the database (`partner_invite_email_for_token`) for the `invitee_email` of an unexpired, unaccepted, unrevoked invite with `token_hash = sha256(token)`; if there is one it **sends an OTP to that address** (no email is typed, so a token holder cannot redirect the code), and either way answers a constant body, so the endpoint is neither an invite-existence nor an email oracle.
  2. `POST invites/accept/verify {token, code}`. The Edge calls `verifyOtp` with the anon key (the E19 verifier) and takes the user id and the GoTrue `session_id`. **Then** `partner_invite_accept(token_hash, uid, gotrue_session_id)` runs, in one transaction, **in this order**: locks the invite; refuses unless it is live and `lower(btrim(auth.users.email)) = lower(btrim(invitee_email))` **in SQL** (one implementation of the normalisation, the lesson of 0041 L2), the email is confirmed, and **the GoTrue session row for that uid is still fresh**; increments `attempts` (an invite locks after 10); **then checks the person's state, before writing anything**: (a) an **active credential** exists: status `existing_member_sign_in`, nothing written; (b) **no active credential but an active membership in any org** (a person who self-revoked or was panic-revoked): status `recover_required`, nothing written, because the reach rule of 6.5 must apply to anyone who already works somewhere and an invite must not become a way round it (R2-L1); (c) otherwise inserts or reactivates `partner_member`, sets `accepted_at` and `accepted_by`, and issues a `register` challenge (stateless, bound to uid, invite id and the acceptance time, 5.1) **inside this definer, only now**, which the Edge returns in the `accept/verify` response (R3-M2; there is no separate options call in enrolment mode). **Only after the definer returns** does the Edge close the GoTrue session (`closeSession`, in a `finally`), exactly the order E19 uses; revision 1 closed it first, which would have made the freshness check unsatisfiable.
  3. In case (a) the response is `409 existing_member_sign_in` (the mailbox owner is the only person who gets here, because the OTP was just proved), the membership is **not** activated, **and the invite is not consumed** (`accepted_at` stays null, only `attempts` moves), so it stays usable for branch E. In case (b) the response is `409 recover_required` and the person asks a manager for recovery (6.5); the invite likewise stays unconsumed.
  4. WebAuthn create in the PWA (`residentKey: required`, UV required, `attestation: none`, exclude the person's credential ids). `POST credentials` verifies in the Edge (wrapper rules below), then `partner_credential_register_first` stores it, re-verifying that this invite was accepted by this uid under 15 minutes ago and has produced no credential yet (**one registration per acceptance**), **refusing if an active credential exists** (a race with another enrolment) **or, for an invite-bound enrolment, if the person holds an active membership in any org other than the one this invite just activated** (the same R2-L1 rule, enforced again at the point of creation), and **mints the first session in the same transaction** (R3-L3), storing the create ceremony's evidence. That session carries `enrolment_until` (15 min): inside it the first PIN may be set and, for operator or admin, the first TOTP enrolled, without a further OTP proof.
  5. The PWA forces setting the PIN (6.3) before it shows anything, and TOTP enrolment (6.4) for operator or admin.
- **Branch E: the person already has an active credential.** They sign in with it (6.2) and `POST invites/accept` with the invite token, class A2 (their PIN and a fresh passkey assertion). `partner_invite_accept_for_partner` checks, in SQL, that the **session user's confirmed email equals `invitee_email`**, then activates the membership. No credential is registered and no OTP is needed; a forwarded link fails because the forwardee's session user has a different email (`403`).

A forwarded link fails in both branches: in N the OTP goes to the invited mailbox, which the forwardee cannot read, and `partner_invite_accept` refuses any uid whose verified email is not the invite's; in E the session user's email must match. The email-mismatch cell calls the definer directly with a different account, because the HTTP path cannot reach that state (plan §4.7.7, AT 16). An invite for an address that signs in with an Apple private-relay address fails closed (the relay address is a different email); the player-account linking rules do not apply here (plan §3.4 rule 3).

**The WebAuthn wrapper must (L7).** `[verified 2026-10-04: read in the 14.0.3 source]` SimpleWebAuthn 14.0.3 (a) accepts `crossOrigin: true` when the response carries no `topOrigin`; (b) processes **any attestation format** it recognises even though `none` was requested, which puts its X.509 and ASN.1 parsers on client-supplied data; (c) never compares `response.id` with the credential it was verifying against; and (d) defaults the accepted algorithms to EdDSA, ES256 and RS256. So `_shared/partner/webauthn.ts` **must**: reject `clientDataJSON.crossOrigin` outright; decode the attestation object with the library's `decodeAttestationObject` helper (`npm:@simplewebauthn/server@14.0.3/helpers`, an exact entry of its own in the import map and allow-list) and **refuse any `fmt` other than `none` before calling `verifyRegistrationResponse`**; pass `supportedAlgorithmIDs: [-7, -257]` to both `generateRegistrationOptions` and `verifyRegistrationResponse`; assert `response.id` equals the credential id the database returned and, at sign-in, that the stored `userHandle` matches the response's. Each is a must-fail cell (PA-0a).

### 6.2 Sign-in

1. `POST session/options` returns a 32-byte challenge, `userVerification: required`, empty `allowCredentials`, `timeout: 120000` (verified to be what `generateAuthenticationOptions` emits when asked).
2. The PWA calls `navigator.credentials.get`. On a shared iPad the operating system's chooser is expected to list every staff passkey registered for this RP ID on that device and the person picks theirs `[unverified - training knowledge; S0 checks it on a real iPad]`. No email or username is typed, so there is no username oracle.
3. `POST session`: the Edge verifies the challenge token's shape and expiry, looks the credential up, and runs `verifyAuthenticationResponse` with the stored key and counter, exact origin, exact RP ID, `requireUserVerification: true`, through the wrapper rules above. It then calls `partner_session_mint`, which recomputes the challenge HMAC, records the nonce (single use), and repeats the checks the database can make (4.4).
4. Counter policy `[verified: software-authenticator test]`: a non-zero counter that does not strictly increase is **refused** (equal and lower both), and a `0` against a stored `0` is **accepted**. A refused regression writes an `audit_log` row and raises an operator alert (the plan §8.3 alert path), and blocks that assertion; the credential is not auto-revoked (a flaky authenticator would lock a person out), a manager decides. Synced passkeys report `0`, so **clone detection does not exist for them**: R-P3.
5. `aal` is 1; an operator or admin must continue with TOTP before any call except those in 4.1.

Replay of an assertion fails because the nonce is recorded at mint and the primary key refuses a second use; replay of a token needs the token.

### 6.3 Step-up PIN and the action classes

The passkey proves the credential (and, on a shared iPad, the device); the PIN picks the **person** (plan §9.2, FM-20). It is not authentication by itself: it is useless without a live session of the same member.

**PIN rules.** Exactly four digits. Refused at set: repeated digits, ascending and descending runs, years `1900`-`2099`, valid `MMDD` dates, and a deny-list of the most common 4-digit PINs (the top 100 of a published breach list `[unverified - training knowledge; the list is chosen and committed in S1.4]`). Set or changed only when the session shows **one** of: `enrolment_until` (the session minted by `register_first`, 15 min), or `otp_proof_until` (a fresh email OTP to the member's address, 10 min, via `session/otp-proof`); **and**, for a change of an existing PIN, the current PIN. A `must_change` PIN (after a reset) needs the OTP proof. A passkey assertion alone is **not** enough, because on a shared iPad anyone with the passcode holds one (H2).

**Where the secret goes.** The **browser** fetches the member's salt and iteration count (`GET session/pin`, refused while locked), runs PBKDF2-HMAC-SHA256 with WebCrypto (`[proposed]` 600,000 iterations, the OWASP-style figure `[unverified - training knowledge]`; the value is stored per row so it can rise on the next set) and sends only the **derived** bytes. The Edge never sees the PIN; it sees a PIN-equivalent, which is useful only against this member's verifier (so R-P2 shrinks from "the PIN" to "a value that works only here"). In Postgres `partner_pin_verify_for_partner` locks the row, applies lock and backoff, computes `HMAC-SHA256(pepper, derived)` with the Vault pepper (E12 pattern), compares, and records the outcome, returning a status (5.3). The stored verifier is useless without the Vault pepper. `[unverified]`: PBKDF2 time on a low-end iPad (S0 measures it; the floor is 210,000 rounds, 115 ms measured on this host).

**Honest arithmetic.** With the pepper unknown, a stolen table gives an attacker nothing to test against. With the pepper also known, 10^4 PINs at 600,000 rounds is about 3,230 s (about 54 minutes) on one core as measured (section 14). The KDF therefore protects little; the pepper and the online cap do the work, and this document does not claim otherwise.

**Lockout.** Counters live in the `partner_pin` row: after the 3rd consecutive failure the next attempt is refused for 30 s, after the 4th for 5 min, after the 5th the member is **locked** (`locked_at`). 20 failures in a day lock regardless of successes between them. A lock survives new sessions. Unlock: a manager (or operator, or admin) under the 6.5 reach rule, class A2, never for themselves; it sets `must_change`, so the person chooses a new PIN under an OTP proof and nobody else ever learns it. A lone manager is reset by an operator; an operator by an admin. Every failure, lock and reset writes `audit_log`.

**Action classes.** `partner_authorize` takes the class; the table is the policy. **Every class first requires the session's `aal` to meet the person's required assurance (4.1).**

| Class | Needs | Examples |
|---|---|---|
| **A0** | a live session at the required `aal` | reads (`GET session`, shift log, own stock), sign-out, lock, list own credentials |
| **A1** | A0 and a **single-use PIN grant**: a PIN verified at most 60 s ago and not yet used, **consumed by the action in its own transaction**. One PIN, one action | `partner-attest`, "Marker sold" token mint (`course-qr`), offer redeem, special-marker hand-over (R1 scan and R2 token), stock movements by staff, the offline-voucher countersign |
| **A2** | A0, a single-use PIN grant at most **30 s** old, **and** `reauth_until > now()` (a passkey assertion at most 5 min old) | **adding a credential**, **any credential revoke (own included)**, invite create or revoke, member revoke, recover, PIN reset, "Rotate PIN" for the course QR, revoke-all, branch-E invite accept |
| **A3** | `aal` 2 and `mfa_until > now()` (a TOTP at most **5 min** old) | operator and admin actions: programme and sponsor config, offer approve, `qr-print`, `codes-generate`, `settlement-export`, held-review resolve, stock reconciliation overrides |

**A3 as the substitute for PIN-less members.** An operator or admin who holds no staff or manager role has no PIN. For such a member the A1 prerequisite is met by A3, and the A2 prerequisite by A3 plus `reauth_until > now()`. A member who holds both (a manager who is also an operator) uses the PIN for A1 and A2 and TOTP for A3. The rule is in `partner_authorize`, tested per combination (PA-19).

**Adding a credential is A2 plus notice (H2).** On a shared iPad a coworker with the device passcode can pick someone else's passkey and obtain a session. Without this rule they could register a passkey of their own on their phone for that member, lock the member's PIN with five guesses, and set a new PIN after the manager's reset. Now: A2 needs **that member's PIN**; the credential's `label` is derived by the database (5.1), so an attacker cannot choose a label that hides it; the member receives an **out-of-band notice** of every credential add (the transport is open item U1: the repository has no mail egress other than GoTrue's OTP mail; until it is decided the notice is an in-portal item for the member and their manager plus an `audit_log` row and an operator alert); and the 6.5 panic button revokes by **creation time** ("every credential created after T"), not by label.

**One PIN per attest follows the plan (X8).** Revision 1 proposed a 90 s window; a window lets a second person who walks to the iPad act as the first. If pilot telemetry shows a PIN per sale is too slow, a window of N actions inside S seconds is an owner decision (Q2), recorded as a deliberate departure.

### 6.4 TOTP for operator and admin

TOTP is **our own**, verified in the database. The seed is derived (5.1) and shown once as an `otpauth://` QR (SHA-1, 6 digits, 30 s, which authenticator apps support reliably `[unverified - training knowledge]`).

- **Enrolment is gated (H4).** Because the seed is a function of `(user, seed_version)`, a second `enrol` under the same version would return the **live** seed, which would let an `aal` 1 session (a passkey that may be synced) reach `aal` 2. So: `partner_totp_enrol_for_partner` **refuses once `confirmed_at` is set**; it needs `enrolment_until` or `otp_proof_until` on the session the first time; **every enrol call (an unconfirmed re-enrol too) bumps `seed_version`**, so an earlier shown seed is dead; and `confirm` must run in the **same session** that called `enrol` (`enrol_session_id`).
- **Reset** of a confirmed TOTP is its own action, `members/{id}/totp-reset`, by a **higher role** (an admin for an operator, another admin for an admin), class A3, which bumps `seed_version`, clears `confirmed_at` and revokes the member's sessions; the member then re-enrols under an OTP proof.
- **Verification** is `partner_totp_verify_for_partner(code)`: HOTP computed in SQL with the Vault-derived seed, window plus or minus 1 step, replay refused by `UPDATE ... SET last_step = $s WHERE last_step < $s`, 5 failures in an hour lock for 15 minutes (a status, not a RAISE), a success sets `aal` 2 and `mfa_until`.
- **Parameters, so the shared primitive is not mistaken for a shared configuration (N6).** The SQL core is `hotp(seed, counter, digits, algo)` (RFC 4226 dynamic truncation over `public.hmac`). The partner TOTP uses **SHA-1, 30 s, 6 digits**; the money doc's staff offline code uses **SHA-256, 600 s, 6 digits** (`_shared/offline-code/params.ts`). Only the core is shared; each parameter set has its own test vectors, proven against `_shared/offline-code/totp.ts` and the RFC 6238 appendix vectors for the matching algorithm.
- **Admin bootstrap (M4).** There is no invite for an admin (no org). The first admin: the project owner, with database admin access, inserts the `app.admin_user` row and runs a SQL-only function `private.partner_admin_bootstrap_token(user_id, token_hash)` (EXECUTE for nobody; run from a SQL session); the token is generated off-line (for example `openssl rand`) and only its hash is passed. Thereafter an admin issues enrolment tokens with `partner_admin_enrolment_issue_for_partner` (A3, 24 h). Both write `partner_enrolment_token(purpose = 'admin')`. Acceptance is the branch-N flow against that table: an OTP to the user's auth email, `register_first`, then TOTP enrolment, the person having no active credential. An admin with no `confirmed` TOTP is refused every class, so an enrolled-but-unconfirmed admin has no power.

### 6.5 Revocation, recovery, self-attest

- **Authority is per call.** Revoking a member or deleting a scope row takes effect on the **next call** because `partner_authorize` re-reads under row locks that bind (4.3); a concurrent revoke waits for an in-flight action or is seen by it. The session-killing triggers (5.2) cover update, delete (including an org-delete cascade) and insert, so a later re-insert or a re-added `admin_user` row cannot revive an old session.
- **Membership revoke versus credential revoke.** Revoking a *membership* (one org) kills the user's sessions, so they sign in again, and other memberships continue. A *credential* belongs to the person, so revoking one affects **every** org the person works in; that is why the manager rule below exists.
- **Who may act on a person's credentials, PIN or recovery: the reach rule.** An actor `A` may revoke another person's credential, reset their PIN or recover them only if **all** hold: (1) **if the target is not in `app.admin_user`**, the target holds **at least one active membership** (a universal check over zero memberships is vacuously true, which is how revision 2 let any facility manager act on an admin, who normally holds none; (1) is stated on its own and is not implied by (2). It is **not** applied to an admin target: admin targets are governed by (3) and (5), otherwise nobody could act on a zero-membership admin, and admin recovery would be impossible); (2) for **every** active membership of the target, `A` passes `has_*_scope` with a role strictly above the target's role in that org (explicit arrays, 6.1); (3) **if the target is in `app.admin_user`, `A` is an admin**, whatever memberships the target also holds (a staff member who is also an admin is an admin target); (4) **if the target holds an operator membership, `A` is an admin**: an operator's credentials, PIN and recovery are an admin matter, never a manager's or another operator's; (5) `A` is not the target. An admin may act on any non-admin target, **including one with no active membership** (a zero-membership non-admin is an admin-only matter); an admin target needs a **different** admin, so another admin can recover a zero-membership admin, and facility staff can never reach the admin plane. A manager at facility A therefore **cannot** lock out a person who also works at facility B, nor an admin, nor an operator; that needs an operator whose trail covers every membership, or an admin.
- **Recovery is its own manager action** (`members/{id}/recover`, A2, under the reach rule), not an invite. It **revokes all of the person's credentials and sessions across every org** (credentials are per person), sets `must_change` on the PIN, and issues a `recover` row in `partner_enrolment_token` (24 h, bound to the person's own auth email, no org). The person then runs the branch-N flow against it. The cross-org effect is stated plainly: until they re-enrol, the person cannot work at any org. Recovery does **not** use `partner_invite`, so it cannot collide with the "invite to an active member is `409`" rule, and `register_first` still refuses while an active credential exists (there is none after recovery).
- **Self-revoke is A2 too.** Revoking one's own credential is class A2 (the person's PIN and a fresh passkey assertion): on a shared iPad a coworker with the passcode would otherwise revoke every credential of the member and force a recovery.
- **Sole credential.** A person adds a second passkey while signed in (A2, strongly encouraged at enrolment). Email OTP alone **never** adds a credential to a person who has an active one, whatever invite or token is presented: that would make the email account the real credential.
- **Stolen-iPad button.** `orgs/{id}/sessions/revoke-all` (A2) and "revoke every credential created after T" for the affected members, under the reach rule. The `label` is database-derived, so a manager can trust it; the member's `note` is display only.
- **Self-attest** (plan AT 16, A2-21), **per account, not per person**. The partner definers compare the target player's uid with the bound actor (`22023`, mapped to `422`); the CHECK on `attestation` and the 0045 recorder compare accounts too (E7). A staff member with a work email and a separate personal player account is **not** caught by any of them; the plan's same-device rule (a manager invites an account on the same device: the first attest goes to `held_review` plus `fraud_signal`) and the fraud signals in S3 are the compensating control, and the gate should not read AT 16 as person-level.

### 6.6 Admin actions and the audited surface

Admin passes every `has_*_scope` (E6). An admin session is short (4.1), always `aal` 2, and every A3 action writes `audit_log` with the actor, the action, the subject and no secret. This design adds no new admin power; it only makes the existing one reachable solely through a passkey, a TOTP and a short session.

### 6.7 Offline (plan §7.6)

- **Online staff, offline player** (the expected case): staff enter the player's handle and 6 digits on an online device. This needs the session and the money-doc verify-and-record definer; it is slice S3 and is **independent of WebAuthn offline**.
- **Both offline (conditional build):** the PWA holds up to 20 prefetched staff challenges and countersigns a voucher with the member's passkey. Two things stay `[unverified]`: that `navigator.credentials.get` against a stored challenge works in an installed PWA with no network (A60, S7e), and the storage lifetime of the challenge cache on iOS `[unverified - training knowledge]`. The plan's prefetched challenges live in `app.checkin_challenge(staff_user_id, facility_id)` (plan §4.4), whose `edge_actor` insert policy forces `staff_user_id IS NULL` (edge doc section 4); issuing them needs a new partner definer.
- **No local PIN verifier (L11).** Offline, nothing on the device can check a PIN: a local verifier would be a 4-digit secret with no lockout. The design therefore reserves: the PWA derives the PIN value as usual and sends it **at sync time**; the database verifies it then and counts failures then. The number of offline guesses is bounded by the number of prefetched challenges (20 per member per prefetch), each also needing a user-verified passkey assertion. That residual is accepted for the conditional build and stated in 11.
- **Voucher binding (L11).** The countersign challenge is `H(voucher hash || kind || facility)` bound at issue time, so a captured countersignature cannot be replayed against another voucher; purpose `countersign` with a 24 h TTL (the plan's figure). An assertion verified later must belong to the same member as the session that uploads it.
- **Reserved now so it need not be redone:** `offline_code_bound_staff()` (`0045:181`) is keyed on `kind = 'user'`; S3's verify-and-record definer runs under a `partner` binding, so it adds its own predicate inside the family (check 14 clause c), not an edit to the old one.

## 7. Supply chain and outbound hosts

| Item | Entry | State |
|---|---|---|
| Import map | `"@simplewebauthn/server": "npm:@simplewebauthn/server@14.0.3"` and `"@simplewebauthn/server/helpers": "npm:@simplewebauthn/server@14.0.3/helpers"` in `supabase/functions/deno.json` (the latest at authoring time `[verified: registry]`; pin the version current at S0) | added in S0 at 14.0.3, still the registry's `latest` at S0 (section 15) |
| Allow-list | the same two strings in `tools/service-role-lint/pinned-import-targets.json` | added in S0 (section 15) |
| Lockfile | `supabase/tests/deno.lock`: **25 `npm` entries** for the Deno graph (the library, `@hexagon/base64`, `@levischuck/tiny-cbor`, fifteen `@peculiar/*`, `asn1js`, `pvtsutils`, `pvutils`, `reflect-metadata`, `tsyringe`, two `tslib` versions) `[verified 2026-10-04: deno info --json on a scratch import, Deno 2.5.2]`. Today the lock has 5 npm entries. Each needs a `sha512` integrity (`NPM_INTEGRITY`, `config.ts:337`) and a `specifiers` row | added in S0 (section 15): 30 npm entries now; the three CI function lists name the wrapper |
| Outbound host | **none.** Registration with `attestation: none` and assertion verification ran with `--deny-net` after the packages were cached `[verified: 13 cases, section 14]`. The library also exports a `MetadataService` (`[verified: export list]`); that it downloads the FIDO metadata blob is `[unverified - training knowledge]`, and it is **not used**. Attestation formats other than `none` are refused by the wrapper (6.1) | no allow-list entry |
| Email OTP | through GoTrue with the anon key, as the player flow already does (E19) | none |
| **Security notices by email** | **not available today**: the repo's only outbound mail is GoTrue's OTP mail. A notice sender needs a mail host and a sender domain | **open item U1**; a new outbound host would need an allow-list entry (the pull-request checklist) |

The graph is five times the size of today's. That is the cost of the library (its X.509 and ASN.1 stack is there for attestation formats this design does not use, and the wrapper now refuses them). Options for the gate, in order of preference: accept it with the lock, the integrity check and a quarterly bump discipline; or replace the library with a small in-tree verifier for the two ceremonies used (attestation `none`, ES256 and RS256 assertions: about 150 lines of CBOR, authenticator-data parsing and WebCrypto verification). The second removes 24 packages and creates the "own WebAuthn code" risk; this design recommends the first.

## 8. Rate limits

Reuses `private.hit_actor_rate_limit` and `hit_system_rate_limit` (E11). Pre-authentication buckets cannot use an actor limiter (nothing is bound), so they use system buckets. A per-IP key depends on a client IP the Edge reads from a forwarded-for header, **which is `[unverified]` as trustworthy behind the gateway**, and a shop's staff share one NAT address. Therefore **an IP-keyed or global bucket is alert-only, or set far above expected traffic; it is never the only thing standing between a person and a login.** Hard limits are keyed on objects the attacker cannot choose or share: the credential, the invite token, the member, the target mailbox. A `partner` twin of `hitRateLimitForActor` (`hit_partner_rate_limit`, same body, partner binding) serves authenticated calls. Every number is `[proposed]`. The plan's existing caps (staff attest 60/staff/h, hand-over 5 failures/staff/h, `course-qr` token issue 60/staff/h, the §8.3 cold-start caps) are unchanged.

| Endpoint | Key | Limit |
|---|---|---|
| `session/options` | IP hash; global | **alert at** 600/h per IP hash and 20,000/h global; no block. It **writes nothing** (stateless challenge, 5.1), so there is no growth to bound |
| `session` (verify) | credential | **5 failures, then a 15-minute cooldown** per credential (the 5th failure inside one hour starts it; a failure during the cooldown is not counted, so it is a fixed 15 minutes; a status, not a RAISE; S1.2 built it, 18.2) |
| `session` (verify) | IP hash | alert at 100 failures/h; no block |
| `session` (mint, S0-L5; built in 0048) | credential | **60 successful sign-ins per credential per hour**, counted from `app.partner_session` (`mint_kind = 'sign_in'`, `created_at` within the hour) and checked **before** any signature verification, so a holder of a valid credential cannot loop mints and a refusal here costs the database only that count; the status is `rate_limited` (a status, not a RAISE). The 60 is the sessions' own `created_at`, so it cannot be reset by anything but time |
| any partner call | member | 1,200/h (alert, not block) |
| PIN verify | member | the in-row rules of 6.3 (3 / 4 / 5 consecutive; 20 a day) |
| TOTP verify | member | 5 failures/h, 15 min lock; a step cannot be reused |
| `invites` create | inviter; invitee email hash | 20/day; 3 per email per day |
| `invites/accept/start` | token hash; invitee email hash | 3 sends per token per hour; 5 failed OTP proofs per target per hour (the `reserve_signin_otp_attempt` / `release_signin_otp_attempt` pair, 0035) |
| `invites/accept/verify`, `enrolments/accept/*` | token | 10 attempts per token, then locked (counted by status, not RAISE) |
| `session/otp-proof/*` | member; target mailbox | 3 sends/h; the same 5-per-target counter (**built member-keyed, 3 sends and 5 attempts per member per hour: 19.3 D5**) |
| credential add / revoke, `reauth` | member | 10/h |

Concurrency is tested in pgTAP as for the existing limits (plan §4.7.8).

## 9. Retention and purge

Follows `retention-purge` (E13): bounded definers (a constant `LIMIT 5000` inside each, never a parameter), `EXECUTE` for `edge_system`, a try-lock per step, run from the hourly scheduler already specified in edge doc section 15.

| Data | Kept | Mechanism |
|---|---|---|
| `partner_auth_challenge` (used nonces only) | 1 h after `used_at` (long past the 120 s validity; the HMAC `exp` also refuses it) | `purge_partner_challenges` |
| `partner_session` (including the assertion evidence) | 30 days after `expires_at` or `revoked_at` `[proposed]` | `purge_partner_sessions` |
| `partner_credential`, active | until the member's account is deleted (`delete_my_data`, the registry-driven pass) | - |
| `partner_credential`, revoked | 180 days after `revoked_at` `[proposed; counsel]` | `purge_partner_credentials` |
| `partner_pin`, `partner_totp` | until the last membership is revoked (trigger, 5.2) or the account is deleted | trigger / `delete_my_data` |
| `partner_invite` | 90 days after accepted, expired or revoked | `purge_partner_invites` (closes G4) |
| `partner_enrolment_token` | 90 days after consumed, expired or revoked | `purge_partner_enrolment_tokens` |
| `audit_log` auth events | **permanent** (insert-only, E14); credential and session ids and uids, never a secret | open question Q5 |
| rate-limit buckets | 2 days | existing `purge_rate_limit_buckets` |

Account deletion: the staff member's own `delete_my_data` removes credentials, sessions, PIN, TOTP, challenges and enrolment tokens through the registry (5.4 item 3); `audit_log.actor_user_id` is redacted by the existing narrow exception (E14).

## 10. Threat table

| Threat | Attack | Controls | Residual |
|---|---|---|---|
| Phishing, credential | A look-alike site asks for the passkey | WebAuthn is origin-bound; wrong origin and wrong RP ID are refused `[verified: both cases in the test]`; RP ID is the narrow host | none beyond browser bugs |
| Phishing, invite | An attacker relays the invite link **and** the emailed OTP and enrols their own passkey | the invite is single use, 72 h, email-bound; the inviter sees the acceptance and the new credential in the portal; cold-start caps apply to a new member (plan §8.3); branch E means a person who already has a credential never gets another this way | a relayed OTP at a **first** enrolment succeeds (any email-OTP bootstrap has this); mitigated by in-person onboarding at pilot sites |
| Coworker on a shared iPad | Someone with the device passcode picks another member's passkey | the PIN is the only per-person factor: A1 per action; adding a credential, invites and resets need A2; PIN set needs an OTP proof, not a passkey; database-derived credential labels; out-of-band notice (U1); revoke by creation time | reads (A0) as another member until idle or lock; collusion is a policy problem |
| Invite to a second org | A manager invites a known member's mailbox to a new org to mint a credential on them | branch E: an existing credential holder must sign in and pass A2; `register_first` refuses with an active credential (PA-23) | none |
| TOTP bypass | An `aal` 1 operator session re-enrols TOTP to read the live seed | enrol refused once confirmed; first enrol needs the enrolment window or an OTP proof; re-enrol bumps the seed; confirm only in the enrolling session; reset needs a higher role (PA-24) | an attacker who holds the mailbox **and** a first-enrolment window |
| Stolen shop iPad | Thief has the device | UV (the iPad passcode or biometrics) for every assertion; idle 30 min; A1 per action; manager revokes credentials and runs `revoke-all` | thief with passcode, an open session and the PIN acts until revoked |
| PIN shoulder-surfing | Watcher learns a PIN | masked entry; useless without the member's credential and a session; 5-failure lock; single-use grant; per-member only | a watcher who also holds the unlocked iPad |
| Session theft by XSS | Script reads the in-memory token | strict CSP, no third-party or inline script, `frame-ancestors 'none'`; not persisted; A1 and A2 need a PIN the script would have to capture; per-staff caps and anomaly alerts; proof of possession reserved (4.6) | a script on the page rides the live session and can read keystrokes; same for a cookie |
| Session theft in transit or logs | Token captured on the wire or in a log | TLS; our code does not log it; header redaction `[unverified]`; hashed at rest | an observer inside the Edge runtime sees tokens (R-P1) |
| CSRF | A third-party page triggers a call | no ambient credential; custom header forces preflight; **server-side Origin refusal and exact media type for pre-auth endpoints**; exact-origin CORS | none |
| Invite forwarding | Link sent to a colleague | OTP goes to the invited mailbox; SQL email comparison; `403` otherwise (AT 16) | the colleague **is** the mailbox owner |
| Replay | Assertion, challenge, session token, invite | stateless HMAC challenge, nonce recorded at mint so a replay is a primary-key violation; token needs the live session; invite single use under lock; sign count | a replayed *token* inside its lifetime (needs theft first) |
| Counter regression, cloned authenticator | Two copies of one key | a non-zero counter must strictly rise; regression refused, audited, alerted | synced passkeys report 0: no clone detection (R-P3) |
| Staff collusion | A staff member sells scans, or hands a friend their PIN | co-signal required for hard evidence (plan §4.5); per-staff and per-facility caps and the anomaly rule (§8.3); attribution to a person and a credential | collusion is a policy problem, not an authentication one |
| Manager abuse | A manager floods invites | rank and scope rule in the database; 20 invites/day; audited; the operator sees `staff_activity` | an honest-looking manager can still invite real people |
| Enumeration | Probe members, invites, credentials | usernameless sign-in; constant `401`; constant invite-start body; foreign id `404` where the plan says so | timing differences are not measured |
| Brute force | PIN, TOTP, OTP, invite token, sign-in | PIN and TOTP lock in the database (status, not RAISE); OTP reuses the 0035 counters; invite tokens are 256-bit and attempt-capped; credential and token keyed limits | an attacker with a live session can lock the member's PIN (a lock lever) |
| Privilege confusion | A Supabase JWT used as partner authority, or the reverse | partner functions never call `getActorFromRequest`; `gr_ps_` bearers are rejected before GoTrue; **D12 removes the PostgREST reads**; the partner role has no table privilege | none after D12 |
| Lane crossing | A partner transaction used as a player | separate role `edge_partner`; `actor_uid()` NULL for a partner binding; catalog-driven test (PA-3b) | `SET ROLE` is judged by the session user (R6) |
| Stale authority | Revoked member keeps working | per-call re-read after locking the session row, which every authority change must touch (4.3); triggers on update, delete, insert; reactivation cannot resurrect | none inside a committed revoke |
| Compromised Edge runtime | Runtime or a dependency is malicious | minter role, partner role, DB-side assertion checks, re-verifier (S1.6), locked and integrity-checked dependencies | R-P1: it can mint sessions until the re-verifier flags them, and sees tokens and PIN-equivalents in flight |
| Compromised dependency | A malicious `@simplewebauthn/server` release | exact pin, sha512 lock, `--frozen` CI, tamper test (E15); the wrapper refuses non-`none` attestation | a malicious *pinned* version |
| Mailbox takeover | Attacker owns a staff mailbox | email never adds a credential to a person who has one (D13); invites need an inviter | takeover at first enrolment |
| Admin takeover | Attacker targets an admin | passkey + TOTP, 10 min idle, 1 h absolute, every A3 action needs a TOTP within 5 min, audited, TOTP reset only by another admin | a device-bound hardware key is not required (R-P4) |
| Lock-out DoS | Lock a person out, or an admin | PIN lock needs a live session; recovery and credential revoke only under the reach rule, which excludes admin and operator targets and zero-membership targets | a pro shop with one person and no manager waits for the operator (Q3) |
| Clock skew | Device or server clock off | all windows use the database clock; a TOTP step is plus or minus 1 | a badly wrong device clock fails closed |

## 11. Residual risks and honest limits

- **R-P1: the Edge runtime is the WebAuthn signature verifier.** A compromised runtime can ask the minter for a session for any member, with fabricated but consistent assertion data (4.4), and sees every token and PIN-equivalent that passes through it. The partner lane is narrower than R6 (a separate role with no table privilege; a compromised runtime cannot act as a partner who is not signing in without minting; the user lane cannot see a partner binding), but it is not closed. The S0 spike made the database the verifier for sign-in (S1.1b verifies the signature in the mint definer; the S1.6 re-verifier is moot, 16.4); registration still has no signature to check (R4-L2). Closing R6 itself is the "PR5" the edge doc already names.
- **Registration has no cryptographic check at all (R4-L2).** With `attestation: none` the create ceremony carries **no signature**: nothing proves the public key belongs to a live authenticator. The only protections are the structural DB-side checks of 4.4 (type, origin, challenge, `rpIdHash`, UP/UV/AT, `fmt`, key parse and algorithm) and the fact that a `register` challenge exists only inside a just-verified accept (5.1). A compromised runtime that gets a valid register challenge can register a key it generated. The re-verifier **deliberately skips `register`-kind sessions** (no signature exists to re-verify), so a forged enrolment is detected only by the first-credential notice and the manager's view of new credentials (6.3), not by S1.6.
- **R-P2: the Edge sees a PIN-equivalent.** The PIN is derived in the browser (6.3); the Edge handles a value that works only against that member's verifier. The derived key also reaches Postgres as a **bind parameter** of the verify, set and change calls, so statement logging with parameters (`log_parameter_max_length`, `log_statement = 'all'` or `'mod'`, or an extension that records parameters) must stay **off** for the project: a logged derived key is a PIN-equivalent in a log file. What Supabase logs by default `[unverified - training knowledge]`; S0 checks it on the real project.
- **R-P3: synced passkeys, and shared Apple IDs on shared iPads.** A passkey synced through a platform account (backup eligible) can be used from any device in that account, and reports a counter of `0`. On a shared shop iPad, **every staff passkey may sync into whatever Apple ID the iPad is signed in to, often the owner's personal account**, so a second device, and the account holder, hold every staff passkey. "The passkey proves the device" is true only for device-bound credentials. `backup_eligible` and `backup_state` are stored; nothing is enforced on them in P5.1a. S0 checks, on a real iPad, whether a passkey registered on a shop iPad syncs to other devices of its Apple ID and what the onboarding checklist must say (a dedicated shop Apple ID with iCloud Keychain off is the likely rule; whether Keychain-off passkeys remain usable is `[unverified]`).
- **R-P4: admin without a hardware key.** The design asks for passkey + TOTP (plan line 448); it does not require a device-bound key. Requiring `backup_eligible = false` for admin is a later hardening if the platform's authenticators make it practical `[unverified]`.
- **R-P5: A0 reads as another member.** On a shared iPad, a coworker with the passcode has A0 as any member whose passkey is on it, until idle or lock. Reads are scoped to that member's facilities.
- **R-P6: the stray Supabase JWT.** After D12 a staff member's Supabase JWT reads no partner data and authorizes no partner function. It still authorizes the **player** lane for that account, which is correct.
- **R-P7: offline PIN guesses.** In the conditional offline build the PIN is verified only at sync (6.7); offline guesses are bounded by the prefetched challenges.
- **R-P8: the credential-state timing oracle (S1.2 gate L6).** Sign-in answers one uniform `401` for an unknown credential, a revoked one, one in cooldown and a refused assertion, but it does **not** take the same time: an unknown or revoked credential and a credential in cooldown return from the lookup, while a live one goes on to the S0 wrapper's signature verification (and, on success, the mint). Someone who can time `session` requests can therefore tell **"this credential id exists and is not cooling"** from **"it does not, is revoked, or is cooling"**. What that reveals is bounded: a credential id is 16 to 1,023 random bytes that the browser holds and the server never lists (usernameless sign-in, 6.2), so it cannot be enumerated; the answer says nothing about the person; and finding a live id by guessing is a 128-bit search. What it does not hide is that a **known** credential id is in cooldown (the cooldown is the point). Not mitigated, because padding the lookup path to the verification's cost would make every refusal pay for a signature check (a denial-of-service lever) for an oracle that needs an id the attacker already has. Recorded in the threat table under "Enumeration" (`timing differences are not measured`) and here.
- **Unverified in the hosted environment** (S0 resolves them on a real project): npm resolution of the 25-package graph; CPU time for assertion verification; `verify_jwt = false` per function; function CORS preflight; Vault and `public.hmac`; `auth.sessions` columns for the freshness checks; the S0 database-side signature spike; an installed-PWA passkey ceremony, the shared-iPad chooser, passkey sync on a shop iPad, and PBKDF2 time on a low-end iPad; A60.

## 12. Slice plan for P5.1a

Each slice is one or more PRs, each independently gateable and each with an "as built" section appended to this document (the repo's convention). Database halves ship before their TypeScript halves (the edge doc's PR1 / PR2 split). **The order of slice 1 changed (L5):** invites need class A2 (a PIN) and the operator and admin invites need A3 (TOTP), so PIN and TOTP come before invites. Until a class is implemented `partner_authorize` **fails closed** on it, and no interim relaxation is allowed; a cell proves A2 and A3 refuse before S1.3 and S1.4 (PA-4b). Credentials for the S1.2 sign-in are seeded in staging by a test-only fixture, never by a production path.

| Slice | Content | Needs |
|---|---|---|
| **S0** | Supply chain and spike: the npm pins (two entries), allow-list, lock and CI list changes; the `_shared/partner/webauthn.ts` wrapper with the L7 rules; the software-authenticator fixture as unit tests; **the database-side signature spike** (RS256 modexp and ES256 in PL/pgSQL `numeric`: pass criterion, verification under 200 ms and no extension); the real-project checks of section 11; the shop-iPad passkey-sync check (R-P3); browser PBKDF2 timing on a low-end iPad | this design signed off |
| **S1.1** | **DB spine.** Roles `edge_partner` and `edge_partner_minter`; binding kind `partner` and `actor_uid()` change; tables `partner_credential`, `partner_auth_challenge`, `partner_session`, `partner_enrolment_token`, `partner_rp_config`; `bind_partner_session`, `partner_authorize` (A2 and A3 fail closed), the mint definers with the DB-side assertion checks; revoke triggers; the scope and role-to-org-kind invariants; `partner_invite` additions and **fixture updates** (`helpers.sql`); **the PostgREST revocation (D12, 5.5)**; **`REVOKE EXECUTE` on `offline_code_record_step_for_actor` and removal of its Edge wrapper only (X9); the session policy and guard trigger, the three session-writer roles and the authority triggers of 4.3 (no GUC window)**; registries; checks 9-14; pgTAP | S0 |
| **S1.2** | **Edge core.** `openScopedTx` kinds `partner` and `partner_mint`; lint rule; the CORS helper, Origin refusal and `readPartnerJsonBody`; `getActorFromRequest` prefix rejection; function `partner-session` (options, verify, get, sign-out, lock, reauth); the partner rate-limit twin; the reserved `pop_jkt`/`X-GR-PoP` slot; Deno integration suite | S1.1 |
| **S1.3** | **PIN and step-up.** `partner_pin`, Vault pepper, definers, browser derivation contract, `session/step-up/pin`, lockout, reset, OTP proof, A1 and A2 enabled | S1.2 |
| **S1.4** | **TOTP and `aal` 2.** `partner_totp`, the SQL `hotp` core (shared with S3), gated enrolment and reset, operator and admin session policy, the admin bootstrap function, A3 enabled and `aal` enforced for every class | S1.3 |
| **S1.5** | **Invites, enrolment, members.** `partner-invites` (create, list, revoke, branches N and E), `partner-members` (list, revoke, credential add and revoke, recover, revoke-all), `enrolments/*`, server-side OTP, first-credential registration; purge definers for challenges, sessions, invites, enrolment tokens | S1.4 |
| **S1.6** | **MOOT (S0 gate ruling, 16.4).** ~~**Assertion re-verifier.** Definers `partner_reverify_batch` and `partner_reverify_flag`, the login `partner_audit`, the system-lane enforcement step, and the out-of-runtime job with its runbook (4.4; open item U2, decided at the S1.6 gate); skipped if the S0 spike shows database-side verification is practical~~ The spike passed; the verifier is in the mint (S1.1b) | S1.1 |
| **S2a** | **Player lane** (parallel; no staff dependency). `marker-scan` and the player's co-signal intake: accept `{facilityId, fix, jti}` and tie it to the purchase evidence row (plan §7.6 G2-03, §4.6(q)): `pending` without a qualifying fix, `valid` within 7 days of one, the 120 s rule judged against the fix's time | P3 |
| **S2b** | **Staff lane.** `course-qr` (rotating token on "Marker sold", today's PIN and "Rotate PIN", hand-over token, the A0 refresh route), `qr-print`, the Ed25519 signing key in Vault, `facility_qr` and `course_qr_token` writers; their reads | S1.3, S1.5, S2a. **Built (section 24; the hand-over token is not)** |
| **S3** | **Attest and redeem.** `partner-attest` (online token and the offline code with the money doc's verify-and-record definer, superseding the recorder), `partner-offers-redeem`, self-attest, same-device rule, cold-start caps, `staff_activity`, `attestation_shift_log`, their Edge reads | S1.3, S1.5 |
| **S4** | **Receipts and review.** `receipts`, the review and `held_review` queue (wrapping `resolve_held_*`, E20), SLA alerts | S1.4, S3 |
| **S5** | **Hand-over and stock.** `partner-entitlements-redeem`, `entitlements-collect`, `stock-admin`, vouchers, the availability projection, the stock reads | S3 |
| **S6** | **Programme and sponsors.** `programme-config`, `offers-admin` (including the offer read that D12 removed), `sponsorships-admin`, settlement (P5.1b), rollup reads | S1.4 |
| **S7** | **`apps/partners` PWA.** 7a shell, CSP, enrolment, sign-in, PIN (with browser derivation), lock (against fixtures, from S1.2); 7b attest and course-QR screens; 7c hand-over and stock; 7d manager, operator, admin; 7e offline (the A60 spike, then the voucher if built) | S1.2 onward |

### 12.1 Acceptance tests per slice

`PA-n` are new for this design. `AT(n)` are the build plan's P5 acceptance tests (plan line 2807 onward). pgTAP files continue the existing numbering (`supabase/tests/matrix/24_...`).

**S0**
- PA-0a: the software authenticator registers and signs in against the wrapper; wrong origin, wrong RP ID, missing UV, equal and lower counters and a wrong challenge are each refused; `0` against `0` passes; **and** `crossOrigin: true` is refused, a non-`none` `fmt` is refused before verification, an algorithm outside `[-7, -257]` is refused, a `response.id` different from the looked-up credential is refused (the section 14 cases plus the L7 rules, as a committed test).
- PA-0b: `deno cache --frozen` passes; the tamper step still fails on a changed hash; the verification suite passes with network denied.
- PA-0c: the real-project checks, the shop-iPad passkey-sync check, the iPad PBKDF2 timing and the signature spike are recorded, with pass or fail.

**S1.1**
- PA-1: no privilege for `anon`, `authenticated`, any edge role or `service_role` on the new tables; FORCE RLS on; `edge_partner` and the minter hold **no privilege on any relation**; checks 9-14 pass and each has a must-fail fixture.
- PA-2: `bind_partner_session` refuses an unknown hash, an idle-expired session, an absolute-expired one, a revoked one, a revoked credential, a demo account, a sponsor-only member and a member with no active membership, with an **identical** SQLSTATE and message.
- PA-3: **lane separation.** (i) a `partner` binding is invisible to the user lane: under a binding planted through the binder and then `SET ROLE edge_actor`, `private.actor_uid()` is NULL, every `edge_actor` policy yields 0 rows or fails its WITH CHECK, and the four definers that check only `actor_uid()` (`hit_actor_rate_limit`, `device_link_signals_for_actor`, `hold_play_rewards_for_actor`, `lock_own_reward_for_actor`) refuse; (ii) a `user` binding is refused by every `_for_partner` definer; (iii) as `edge_partner`, every table in `app`, `private` and `auth` denies, and `bind_actor` is not executable.
- PA-3b: a **catalog-driven** test enumerates every function EXECUTE-able by `edge_actor` and every policy `TO edge_actor` and runs each under the planted partner binding, so a future user-lane object is covered without a hand list.
- PA-4: **serialisation binds**: with an action transaction open, a member revoke and a **scope DELETE** issued from a second connection each **wait** (seen in `pg_locks`) and complete only after the action commits; a revoke issued while the revoker already holds the session lock makes the action wait and then see the revoke. Staff at A acting at B is `403`; a revoked member's next call is `403` on a live session; **reactivation, a membership DELETE then re-INSERT, an org-delete cascade and an `admin_user` delete then insert do not revive old sessions**; deleting the scope row refuses the next call (AT 1, authentication half).
- PA-4c: **the OR rule and the planted GUC.** (i) With **all** existing `private_definer` policies and grants installed (the `0016:255` and `0016:341` pair included), an UPDATE of the bound user's `partner_member` row under a partner binding, `SET revoked_at = NULL, role = 'manager', invited_by = NULL` in particular, is refused or affects 0 rows. (ii) **As `edge_partner`, plant every GUC the repository uses** (the retired `app.partner.authority_touch`, `app.delete_my_data.target_user_id`, `app.offline_code.target_device_id`, the sign-in proof purge window and the fix-coordinate purge window), then call **each partner definer that writes `partner_session`** (the eight writers above) against **another user's session**: expect **0 rows** every time. (iii) Re-run (i) and (ii) **on every policy S1.5 adds** on `partner_member`, `partner_scope`, `partner_session`, `admin_user` or `partner_credential`; a failing planted-GUC case is a gate failure.
- PA-4d: **the guard trigger (R4-L1), one cell per row of its table.** Each of `user_id`, `credential_id`, `token_hash`, `created_at`, each `mint_*` column, `mint_kind` and `enrolment_until` cannot be changed by a partner-bound definer on its own session (including `SET user_id = <other>, aal = 2`, which the author showed succeeds under the bare policy); `expires_at` cannot increase; `revoked_at` cannot go back to NULL; `aal` 2 and `mfa_until` are refused without a same-transaction TOTP verification and accepted with one; `pin_grant_until` is refused without a same-transaction correct PIN verification, refused above now + 60 s, and clearing is accepted; `reauth_until` is refused without a same-transaction `reauth` challenge row for this session; `otp_proof_until` is refused without a fresh GoTrue session for this user; `last_seen_at` cannot decrease.
- PA-4b: before S1.3 and S1.4 land, an A2 or A3 call is refused for every actor, admin included. **(As built: S1.3 enabled A2; S1.4 enabled A3. The cell now reads that A2 and A3 are refused without their prerequisites, not that the classes themselves are closed: `25_partner_auth_spine.sql` PA-4b, `28_partner_pin_step_up.sql` section 5, and `31_partner_totp_aal2.sql`.)**
- PA-5: a facility org with a second scope row, or a non-facility scope, is refused by the trigger; a `sponsor` role in a facility org, or `staff` in an operator org, is refused.
- PA-6: every view and table in 5.5 answers "denied" to `authenticated` for every actor, including `staff@X` with a valid JWT; `api.offer` and `api.my_offers()` return only live offers with NULL budget and eligibility columns **to a scoped member too**; a draft offer is invisible to a scoped member through every PostgREST path.
- PA-7: the same signed challenge presented to 12 concurrent mints succeeds once (primary-key refusal); an expired, wrong-purpose, wrong-binding or tampered-HMAC challenge is refused; the HMAC encoding is pinned by a vector computed outside the database (as 0045's derivation is); `session/options` called 10,000 times leaves the `partner_auth_challenge` row count unchanged.
- PA-7b: **registration challenges (R3-M2).** (i) a `register` challenge requested through the external issuer is refused (the issuer takes no purpose and issues only `sign_in`); (ii) a challenge bound to invite X cannot enrol for invite Y, nor for a different uid; (iii) a **second registration from one acceptance** is refused, and a registration more than 15 minutes after the acceptance is refused; (iv) `register_first` creates the first session in the same transaction (the session row exists with `mint_kind = 'register'`, the nonce is recorded once, and a `partner_session_mint` on that challenge fails on the used nonce); (v) a `reauth` challenge cannot be issued for a session id other than the bound session's.
- PA-7c: **`register_first` DB-side checks (R4-L2)**: each of the following is refused: `clientDataJSON.type` other than `webauthn.create`; `crossOrigin: true`; a wrong origin; a challenge that does not match the bound HMAC; an attestation `fmt` other than `none`; a wrong `rpIdHash`; any of UP, UV or AT missing; a credential id or COSE key that does not parse; an algorithm other than `-7` or `-257`; a key or credential id that differs from the columns being stored.
- PA-8: only `edge_partner_minter` can mint; it executes nothing else; `edge_actor` and `edge_partner` cannot.
- PA-9: the sign count never decreases except `0`-to-`0`; the compare-and-set loses cleanly under concurrency.
- PA-9b: the mint refuses client data with a wrong `type`, `crossOrigin`, a wrong origin or a different challenge, and authenticator data with a wrong `rpIdHash`, a missing UP or UV flag, or a counter that differs from the argument.
- PA-9c: `offline_code_record_step_for_actor` is **not** executable by `edge_actor`; check 14 clause (b) finds a planted `edge_actor` function that calls `has_facility_scope`.

**S1.2**
- PA-10: CORS allows exactly one origin; any other gets none; `OPTIONS` never opens a connection; a request with a foreign `Origin` is `403` before routing; `Content-Type: text/plain; x=application/json` is `415`; `PATCH` and `DELETE` preflights succeed for the allowed origin.
- PA-11: a Supabase JWT sent to a partner function is `401`; a partner token sent to a player function is `401` **and is never forwarded to GoTrue** (a recording fake proves it); a source scan finds no `console.*` in the partner modules.
- PA-12: valid assertion mints; wrong origin, wrong RP ID, no UV, regression, replayed challenge, `userHandle` mismatch: one uniform `401`; a regression writes `audit_log` and raises the operator alert.
- PA-13: the lint fails on a fixture that uses a mint kind outside its caller.
- PA-13b: the post-bind assertion fails when the transaction runs as `edge_actor`, and when `partner_binding_kind()` is not `'partner'`; `edge_partner` can execute exactly the 4.3 list and **not** `actor_uid()`; `bind_partner_session` refuses a second bind in one transaction, and refuses when any binding (user or delegate) already exists.

**S1.3**
- PA-18: the stored verifier is not a function of the PIN alone (a dump without the Vault pepper verifies nothing); 5 consecutive failures lock, and the 6th correct attempt is still refused; 20 concurrent wrong attempts evaluate at most 5; **the failure counters are still there after a real commit** (no RAISE rollback); the lock survives a new session; reset sets `must_change`; deny-list PINs are refused at set.
- PA-19: a PIN grant is single-use and session-bound: a second action needs a second PIN; a second session of the same member does not inherit it; A1, A2 and A3 refuse outside their prerequisites; the A3-for-PIN-less-member substitution works per role combination and **not** for a member who has a PIN.
- PA-21: PIN set or change needs `enrolment_until` or `otp_proof_until`; **a passkey assertion alone is refused**; a coworker session (a valid passkey session of the member, no PIN) cannot set a PIN after a reset.

**S1.4**
- PA-20: SQL HOTP equals the TypeScript oracle and the RFC 6238 vectors for **each** parameter set (SHA-1/30 s here, SHA-256/600 s for the offline code); replay of a step is refused; plus or minus 1 step; lockout is a status; **an `aal` 1 session of an operator or admin is refused every call except sign-out, lock, `GET session` and `step-up/totp`** (an A0 read of the shift log included); promotion does not upgrade an old session.
- PA-24: `totp/enrol` after `confirmed_at` is refused; the first enrol needs an enrolment window or an OTP proof; an unconfirmed re-enrol returns a **different** seed; `confirm` from another session is refused; a reset by a non-higher role is refused; an unconfirmed-TOTP operator or admin is refused every class.

**S1.5**
- PA-14: AT(16) part two: a forwarded invite fails for a non-matching verified email (`403`, direct definer cell); single use under concurrency; expired, revoked and unknown are one `404`; only the hash is stored (no plaintext column, none in logs); the **email-mismatch attempt count survives commit**.
- PA-15: grant-subset and rank cells of plan §4.7.7 with the explicit role arrays (manager invites at Y, or a manager or operator: `403`; operator at a facility not on its trail: `403`); a staff member cannot invite; a `sponsor` invite is refused.
- PA-16: email OTP alone cannot add a credential to a person with an active one; revoked members' credentials and sessions are dead.
- PA-17: `accept/start` answers identically for a valid and an invalid token; the OTP goes only to the invited address; the GoTrue session is closed **after** the definer on every path (a recording fake).
- PA-22: **adding a credential and revoking any credential, one's own included,** need A2 with a fresh passkey assertion (a session without PIN grant or `reauth` is refused); the label is database-derived (a client-supplied label is ignored); the note is never read by any decision; revoke-by-creation-time works.
- PA-23: an invite to a second org for a person with an active credential returns `409 existing_member_sign_in`, creates no credential, writes no membership and **leaves the invite unconsumed** (it then works for branch E); a person with an active membership but **no** active credential gets `409 recover_required` and no credential, with the invite unconsumed (R2-L1); `register_first` refuses with an active credential (a race cell); branch E activates the membership only for a session whose confirmed email equals the invite's.
- PA-25: **recovery** revokes every credential and session across all orgs, sets `must_change`, issues a `recover` token, and works only under the reach rule: a manager at A cannot recover or credential-revoke a person who also works at B; an operator covering both can; an admin can act on any non-admin. **Cells for R2-M1:** a manager acting on a **zero-membership admin** gets `403`; a manager acting on a **staff member who is also an admin** gets `403`; a manager or another operator acting on an **operator** gets `403`; an admin acting on an admin succeeds only for a **different** admin, **including a zero-membership admin (admin recovery works)**; an admin acting on themselves is refused; a target with no active membership and not an admin is refused for any non-admin actor and **allowed for an admin**.

- PA-27: `session/reauth` with an assertion from a credential that does not belong to the session's user is refused; a second `bind_partner_session` in one transaction is refused.
- PA-28: a freshly invited operator or admin at `aal` 1 with no confirmed TOTP can reach `totp/enrol`, `totp/confirm`, `session/otp-proof/*` and `session/reauth` and **nothing else**; once TOTP is confirmed the same calls are refused at `aal` 1.
- PA-29: revoking the last active membership of a user who is in `app.admin_user` deletes their PIN but **not** their TOTP; for a non-admin both go.

**S1.6 (moot, 16.4)**: the re-verifier detects a planted session row whose signature is invalid or whose credential key differs, `partner_reverify_flag` marks the session, the system-lane step revokes the session and credential and alerts; `partner_audit` holds `USAGE` on `private` and `EXECUTE` on exactly the two definers and nothing else (check 12); the automatic credential revoke needs a second independent flag; flags above k per hour alert and cap the automatic session revoke; a `register`-kind session is not re-verified (no signature exists).

**S2a/S2b**: AT(19) in full (token replay `409`; more than 120 s from the fix `422 qr_expired`; no fix gives `pending`; the PIN rules and the 429 and rotation alarm; forged printed QR `422` plus `fraud_signal`; `staff@X` cannot mint or read the PIN for Y; an `unattestable` fix goes to `held_review`; the fix is counted once). Also AT(3), AT(4); the token refresh route does not extend idle (PA-26).

**S3**: AT(1) (attestation half), AT(2), AT(12), AT(13), AT(15), AT(16) part one (self-attest `422`, with the per-account limit stated); the shift-log read is exactly the old view's contents and no more; the verify-and-record definer never returns a seed or an expected code (money doc step 3); a partner-bound predicate replaces `offline_code_bound_staff` for the new definer and passes check 14 clause (c).

**S4**: AT(11), AT(18), AT(7) (handle escaping in exports); `resolve_held_*` reachable only through an A3 definer.

**S5**: AT(8) and AT(21) entire, including the race for the last unit and the voucher path.

**S6**: AT(10), AT(14), AT(17), AT(20); operator and admin A3 cells; `programme-config` and `offers-admin` foreign-id cells; the offer read formerly served by PostgREST.

**S7**: a browser test that the app works under the section 4.6 CSP (no inline script, no eval); the token is absent from every storage API after sign-in; a reload requires a passkey tap; the PIN prompt appears for every A1 action and the PIN is derived in the browser (the request body never contains it); and, for 7e only, A60.

## 13. Open questions and open items

Product calls (for the owner). The defaults below are what this document is written against until answered.

| # | Question | Default used |
|---|---|---|
| Q1 | **The partners domain.** Confirm the exact host before anyone enrols. The RP ID is baked into every credential; changing it re-enrols every staff member | placeholder `partners.golfraven.<tld>`; RP ID and origin are a deploy-time value (`partner_rp_config`) fixed before the first enrolment |
| Q2 | **Session and step-up ergonomics.** Idle 30 min and absolute 8 h for staff; a PIN per attest-class action; a fresh PIN per A2 action. Is a PIN per sale acceptable at a busy till, or is a window of N actions in S seconds acceptable? | the proposed values, **PIN per action** (X8) |
| Q3 | **Recovery ownership.** Manager, then trail operator, then admin | as written (6.5) |
| Q4 | **Chains and groups.** One login across several courses is a person who is a member of several facility orgs, with a switcher | multi-org membership |
| Q5 | **Retention of auth audit.** `audit_log` is permanent and insert-only; 180 days for revoked credentials; 30 days for session evidence. Counsel and the privacy officer (Law 25) | as proposed, flagged for counsel |
| Q6 | **PIN length** | 4 digits |
| Q7 | **Security notices by email.** Which mail provider and sender domain send "a credential was added to your account", and is a new outbound host acceptable? **Must be answered in time to ship before GA beyond the pilot sites or before P5.2, whichever is earlier (U1 condition 3)** | blocking in-portal interstitial plus manager notice until then |

Open items that a design document cannot resolve (for the gate and the build):

- **U1: the out-of-band notice transport** (H2). The repository has no mail egress except GoTrue's OTP mail. **Gate round 2 ruled this acceptable, and credential add is not blocked in production, on three conditions, tracked here:** (1) the in-portal notice is a **blocking interstitial at the member's next sign-in on any device**; it names the database-derived label and offers revoke; (2) the notice also goes to **every manager whose reach covers the member**, and the operator alert fires; (3) **email notice (Q7) ships before general availability beyond the pilot sites, or before P5.2, whichever is earlier.** Condition 3 is a tracked release condition, not an open question.
- **U2 (moot, 16.4): the re-verifier's host, login and runbook** (S1.6). Specified in 4.4: login `partner_audit`, two definers, a second runtime that is neither the Edge nor CI. **Belongs to the S1.6 gate.** Not needed if the S0 spike makes the database the verifier.
- **U3: the S0 spike results** (database-side signature verification, shop-iPad passkey sync, browser PBKDF2 time) can change sections 3.2, 4.4 and 11. **Per gate round 2 they come back as a delta gate on sections 3.2, 4.4 and 11 only**, not a re-gate of the document.

Gate round 5 (PASS) items carried to the build. Each lands with its slice, and that slice's gate checks it:

| ID | Item | Lands in |
|---|---|---|
| R5-L1 (**resolved in S1.1a, 16.2**) | Replace the `xmin` artefact check. `xmin` proves the row changed in this transaction, not that verification succeeded: a failed attempt's `failed_count` update passes it, and a write inside an `EXCEPTION` block or savepoint fails it. Make the PIN, TOTP and reauth verifiers `SECURITY DEFINER` functions owned by dedicated NOLOGIN roles (e.g. `partner_pin_verifier`, `partner_totp_verifier`). Only those roles hold column-level `UPDATE` on `pin_grant_until`, `aal`/`mfa_until` and `reauth_until`, and `private_definer` loses those columns. The guard keeps the immutability, monotonicity and now + N caps. Add a `UNIQUE` index on `otp_proof_gotrue_session_id`, as in 0041 | S1.3, S1.4 |
| R5-L2 (**built, 16.2**) | `partner_sessions_revoke` takes a subject `(kind, id)` (user, org or credential), not a list. It derives the sessions inside the function and writes one `audit_log` row per call carrying the caller's binding. Specify the credential-revoke helper the same way: subject-based, callable only from the reach-checked definers, and keeping `partner_flag_enforce`'s two-flag rule | S1.1 |
| R5-L3 (**built, 16.2**) | Check 9 for `partner_session_toucher` / `_issuer` / `_flagger` follows 0041's form. The migrating role may hold membership **without** SET or INHERIT, because a PG16+ non-superuser CREATEROLE role keeps ADMIN on the roles it creates `[unverified — training knowledge]` | S1.1 |
| R5-L4 (**built, 16.2**) | The owner roles need their own `TO <role>` SELECT policies under FORCE RLS: `toucher` on `partner_member`, `partner_scope` and `partner_credential`; `flagger` on `partner_session`. They also need USAGE on `app` and `private`. Each policy gets an allow-list row and a fixture line, and all of these go in the 4.3 privilege table | S1.1 |
| R5-N1 (**built, 16.2**) | `partner_session_guard` is `SECURITY DEFINER` with `search_path = ''`. It is owned by a role that cannot `ALTER TABLE … DISABLE TRIGGER`. The owner of `partner_session` is none of the writer roles | S1.1 |
| R5-N2 (**moot**) | The 32-bit `xmin` versus `xid8` comparison wraps mod 2^32. This is moot once R5-L1 removes the `xmin` check | S1.3, S1.4 |

## 14. What was verified in the authoring session, and how

| Claim | How it was checked | Result |
|---|---|---|
| `@simplewebauthn/server` current version, license, dependencies | `curl https://registry.npmjs.org/@simplewebauthn/server/latest` and `/14.0.3` | 14.0.3, MIT, `engines.node >= 20`, ten direct dependencies |
| It imports and runs under Deno | `deno run` of a scratch file (Deno 2.5.2) with `npm:@simplewebauthn/server@14.0.3` | exports `generateRegistrationOptions`, `verifyRegistrationResponse`, `generateAuthenticationOptions`, `verifyAuthenticationResponse`, `MetadataService` and others |
| Size of the dependency graph | `deno info --json` on that file | 25 npm packages |
| UV and resident-key options | `generateRegistrationOptions(... residentKey: "required", userVerification: "required", attestationType: "none", timeout: 120000)` and `generateAuthenticationOptions(... userVerification: "required")` | `requireResidentKey: true`, UV required, attestation `none`, challenge 32 bytes (43 base64url chars), default timeout 60,000 ms |
| Registration and assertion semantics | A software authenticator (WebCrypto ES256, hand-built authenticator data and CBOR attestation object) driven against the real library, 13 cases | registration with UP+UV+AT verifies; without UV refused; with BE+BS reports `multiDevice`, backed up; wrong origin refused; assertion counter 1 verifies; counter 1 again refused; counter 0 after 1 refused; no UV refused; wrong origin refused; wrong RP ID hash refused; counter 5 verifies; counter 0 against stored 0 **verifies**; a different expected challenge refused |
| No outbound host needed | the same 13 cases re-run with `deno run --cached-only --deny-net` | all 13 produced the same results with network denied |
| PBKDF2 cost | `crypto.subtle.deriveBits` PBKDF2-SHA256, 3-run mean, 4-core container, Deno 2.5.2 | 100,000: 57 ms; 210,000: 115 ms; 600,000: 323 ms; 1,000,000: 555 ms. 10,000 PINs at 600,000 = about 3,230 s |
| SimpleWebAuthn 14.0.3 behaviours (gate L7) | the cached package source, `esm/authentication/verifyAuthenticationResponse.js` and `esm/registration/verifyRegistrationResponse.js`, read in revision 2 | `crossOrigin` is checked only against `topOrigin` **when `topOrigin` is present**; the registration path branches on `fmt` (`fido-u2f`, `packed`, `android-safetynet`, `android-key`, `tpm`, `apple`, `none`) regardless of the requested attestation; no comparison of `response.id` appears in either file; the default algorithm list is EdDSA, ES256, RS256; registration `requireUserVerification` defaults to true; `decodeAttestationObject` and `decodeClientDataJSON` are exported from the `./helpers` entry |
| Supabase passkeys are experimental | the passkeys guide, `apps/docs/content/guides/auth/passkeys.mdx` in the `supabase/supabase` repo, master, fetched with `curl` from the raw file host | "Passkey support is experimental ... may change without notice", opt-in client flag, `supabase-js` 2.105.0 or later, discoverable credentials, up to 5 origins |
| GoTrue passkey handlers | `internal/api/passkey_authentication.go`, `passkey_registration.go`, `passkey_manage.go`, `api.go` and `go.mod` in `supabase/auth`, master, fetched the same way | routes under `/passkeys`; `BeginDiscoverableLogin()` and `BeginRegistration(user, WithExclusions(...))` take no UV, resident-key or attestation option; the challenge is consumed before verification; success calls `issueRefreshToken(... PasskeyLogin ...)`; `go-webauthn/webauthn` is a dependency; no `CloneWarning` reference in the three handler files |
| Gate claims about the repository (revision 2) | re-read at `eb92ee9`: `0030:252-259` (`actor_uid()` selects on pid and transaction only), the `v_uid := private.actor_uid()` pattern in `hit_actor_rate_limit`, `device_link_signals_for_actor`, `0033` `hold_play_rewards_for_actor` and `lock_own_reward_for_actor`, 51 + 33 `actor_uid()` references in `0031`/`0032`; `http.ts:103-106`; `helpers.sql:261-265`; `0011:59-94`; `0008:303-309`; `0045:310` and the `recordStep` wrapper in `privileged.ts` (removed in S1.2: `privileged.ts:3403`) | all as the gate stated |
| Row locks under FORCE RLS (gate round 2, R2-M2) | The author reproduced it on a scratch PostgreSQL 17.11 cluster: a role with SELECT and a column UPDATE grant, FORCE RLS, an UPDATE policy that does not match the row | `SELECT ... FOR SHARE` returned **0 rows** and `EXISTS (... FOR SHARE)` was **false**, with no error; after adding `CREATE POLICY ... FOR UPDATE USING (user_id = 1) WITH CHECK (false)` the same lock returned the row, and an UPDATE through that policy was refused (WITH CHECK). The gate's finding is confirmed, **but this repro tested the lock policy alone and the fix built on it was wrong (next row)** |
| The `WITH CHECK (false)` lock policy does not prevent updates (gate round 3, R3-M1) | The author re-ran it on PG 17.11 with the real policy set present: table-wide `UPDATE` granted to the role (as `0016:341`), the permissive `pd_setnull_partner_member_invited_by` shape `USING (invited_by = <GUC>) WITH CHECK (invited_by IS NULL)`, and the lock policy `USING (user_id = 1) WITH CHECK (false)` | `UPDATE m SET revoked_at = NULL, role = 'manager', invited_by = NULL WHERE user_id = 1` returned **`UPDATE 1`** and the row came back un-revoked and promoted (the same statement succeeded even with the GUC unset, because the lock policy's USING exposes the row and the other policy's WITH CHECK passes); an update that left `invited_by` non-NULL was refused. The gate's finding is confirmed, and design (a), no lock policy on authority tables, replaces it |
| Serialising through the session row (the adopted design) | Two sessions on PG 17.11: the first held `SELECT ... FOR SHARE` on a session row for about 3 s as a role with a matching UPDATE policy; the second ran `UPDATE` on the same row | the second connection **waited about 2 s** (until the first committed) before completing, so a trigger that UPDATEs the user's sessions does wait behind an in-flight action's lock |
| A GUC window policy is plantable by `edge_partner` (gate round 4, R4-M1) | The author reproduced it on PG 17.11: policies on a definer role `USING/WITH CHECK (id = <binding GUC>)` and `USING/WITH CHECK (window GUC = 'on')`; a `SECURITY DEFINER` function `revoke_session(id)` owned by that role, `EXECUTE` granted to an unprivileged role | as the unprivileged role, `revoke_session(2)` (another user's session) returned **0** without the window and **1** after `set_config('app.win', 'on', true)` in the same transaction: the GUC persisted into the definer call. Separately, under the own-session policy alone, `UPDATE ... SET user_id = 200, aal = 2 WHERE id = <own>` returned **1 row** (R4-L1). Both findings confirmed; per-role policies and a guard trigger replace the window |
| The mobile app makes no PostgREST read | `git grep` for `rest/v1`, `.from("`, `my_offers`, `api/my_` in `apps` and `packages` (non-markdown) | no match; the app imports only the Auth client |
| Repository facts | every `path:line` in section 2, read in the worktree at `eb92ee9` | as cited |

Not verified (and marked `[unverified]` where used): whether the hosted Supabase platform runs the `master` handlers read above; the hosted Edge runtime's Deno version, CPU limit, `npm:` resolution and `verify_jwt` setting; Vault and `public.hmac`; `auth.sessions` columns; whether a database can verify ES256 or RS256 acceptably in PL/pgSQL; any iOS or Safari behaviour (passkey ceremony in an installed PWA, shared-iPad chooser, passkey sync on a shop iPad, cookie blocking, storage lifetime, Trusted Types, low-end PBKDF2 time); the OWASP iteration figure; the common-PIN list; whether a function receives a trustworthy client IP; GoTrue's `amr` content; authenticator-app TOTP algorithm support.

## As built: S2a (the player lane of the course QR; P5.1a, migration `0046_course_qr_marker_scan.sql`)

S2a is the player's half of a marker purchase: `POST /v1/marker-scan` (`supabase/functions/marker-scan`, `supabase/functions/_shared/course-qr/`) over the database half in migration 0046. It has no staff dependency. The staff lane (minting the rotating token, showing and rotating today's PIN, `qr-print`, the signing keys, the writers of `course_qr_token` and `facility_qr`) is **S2b** and nothing here signs or mints. The offline-code staff step is **S3**; the one thing S3 needs from S2a is the pending-purchase seam below. Migrations 0001 to 0045 are untouched.

### What was built

| Piece | Where | Notes |
|---|---|---|
| Public verification keys | `app.course_qr_key (purpose, kid, public_key_b64url, revoked_at)` | Ed25519 **public** keys only, `kid`-addressed and revocable at once. FORCE RLS, `service_role` SELECT only. Read by `private.course_qr_public_key_for_actor(kid, purpose)`. The private halves are S2b's (Vault, plan §4.8) |
| Wrong-PIN alarm | `app.course_pin_alarm` | One row each time 30 wrong PINs at a facility on a local date rotated its PIN. No user id, no PIN |
| PIN derivation | `private.course_pin_derive(facility, date, epoch)` (and `course_pin_from_key`, `course_pin_matches`, `course_pin_epoch_at`) | The **only** readers of the Vault secrets `course_pin_pepper` and the optional `course_pin_pepper_previous`. **No role has EXECUTE**; reachable only through the definers below. S2b's "show today's PIN" wrapper must call this same function, so the staff screen and the app can never differ |
| PIN epoch log | `app.course_pin_epoch_log (facility_id, pin_epoch, previous_epoch, effective_from)` | When each PIN epoch took effect, written **only** by a trigger on any rise of `facility_programme.pin_epoch` (the failure alarm, S2b's "Rotate PIN", an operator). A PIN is judged under the epoch live at the fix's instant. FORCE RLS, no client grant, no user id |
| Wrong-PIN gate | `private.course_pin_attempt_for_actor(facility, pin, at)` | Returns `ok / wrong / locked / no_facility / no_programme` and **never raises**, so the counter commits. A right PIN also writes the in-transaction proof below |
| PIN proof | `private.course_pin_proof` | UNLOGGED, one row per right PIN **in this transaction and for this instant**. The scan refuses a printed-QR scan without a matching row and consumes it; a deferred constraint trigger deletes the backend's rows at COMMIT, so the table is **empty at rest** (round-2) |
| Pepper epoch | `app.course_pin_pepper_epoch (effective_from)` | When the current pepper took effect, written by the operator's rotation procedure; read only by `course_pin_matches`. No edge or client privilege |
| The scan | `private.marker_scan_for_actor(facility, variant, nonce_hash, qr_kid, pin, at, grade, fix_id, evidence_id)` | One purchase and one credit per eligible trail. Every refusal is a returned status, written before any write |
| The co-signal read-back | `private.marker_cosignal_check(uid, facility, local date, at, grade, fix id, evidence id)` | No EXECUTE for anyone. Reads the bound actor's own evidence row back; used by the scan and the intake |
| The co-signal intake | `private.marker_cosignal_attach_for_actor(facility, at, grade, fix_id, evidence_id)` | Joins a qualifying fix to the caller's own pending purchase at that facility. **Method-agnostic** (the S3 seam) |
| Edge | `marker-scan/index.ts`, `_shared/course-qr/{params,format,cosignal,request-shape,scan-handler}.ts`, `Repo#markerScan`, `Repo#catalog.matchFacilityFix` (`privileged.ts`) | Strict body; the per-user limit (20 a day, bucket `marker-scan:user`) **before** `withOwnership`; no environment read, no log line |
| Mobile | `api.scanMarker` (`apps/mobile/src/api/`), recorder entries `markerscan_*` | Behind `MARKER_COSIGNAL_UI_ENABLED`, which stays `false`: nothing calls it |

All new tables are FORCE RLS with no `anon`, `authenticated` or `edge_actor` grant; the only access is the four `_for_actor` definers (`private_definer`, `search_path = ''`, EXECUTE for `edge_actor` only), each registered in `private.function_inventory` (13 rows with the helpers), every policy registered (22 `pd_marker_scan_*` policies) in `private.definer_policy_allowlist` and `supabase/tests/fixtures/definer_policy_exprs.txt`. Every policy added is keyed on the actor **binding** (`private.actor_uid()`), never on a settable GUC (the money doc's HARD RULE); each definer also filters explicitly by the bound uid.

### The request

`POST /v1/marker-scan`, body (strict at the top level, inside `qr` and inside `fix`): `{ facilityId, qr?, deviceId?, fix?, jti? }`. `qr` is `{variant: "rotating", token}` or `{variant: "static_pin", kid, sig, pin}`. A **scan** carries `qr` (and, to be credited, `deviceId` + `fix` + `jti`, the redeemed check-in token). A **co-signal intake** carries only `facilityId`, `deviceId`, `fix`, `jti`. Rules: a fix needs a `deviceId`; a `jti` needs a fix; a fix with no `qr` needs a `jti`.

Answer: `{ outcome, facilityId, localDate, cosignal, purchases[] }`, 201 for a scan and 200 for an intake. `outcome` is the **worst** state across the purchases (`credited` only if every credit is; `held_review` if any needs a reviewer; else `pending`). No grade, nonce or other trust fact is returned.

| Status | `code` | When |
|---|---|---|
| 409 | `qr_used` | the rotating token was already scanned |
| 409 | `fix_already_used` | this fix id already has its evidence row (a replay; the outbox treats 409 as accepted), or its evidence row already backs another scan (the database's own check) |
| 409 | `fix_not_consumable` | the fix qualified at the read-only check but its check-in token was taken by a concurrent request before this one consumed it; rolled back, capture a new fix |
| 409 | `duplicate_scan` | the same player, same printed QR, same facility-local date |
| 422 | `qr_expired` | the token is more than 120 s from the scan's **instant**: the fix time **when the fix qualifies as a co-signal** (judged in both directions, so a qualifying offline scan uploaded days later is fine), otherwise now |
| 422 | `invalid_qr` | unknown token, wrong facility, malformed, a forged signature (a forged one also commits a `fraud_signal`), or a **genuine** token or printed QR whose `kid` has since been revoked (a stale code, not an attack: no `fraud_signal`, nothing committed) |
| 422 | `invalid_cosignal` | the database read the co-signal's evidence row back and it does not describe this fix here (an Edge bug or a forged call; not retryable) |
| 422 | `invalid_pin` | wrong PIN, another facility's, or the PIN of a rotated-out epoch tried for a later instant (counted). Yesterday's PIN is wrong for today's instant; it is **right** for a scan whose qualifying fix was captured yesterday |
| 422 | `no_pending_purchase` | an intake with nothing awaiting this fix (see departures) |
| 422 | `not_a_cosignal` / `fix_out_of_window` / `marker_programme_inactive` / `qr_variant_not_enabled` / `qr_revoked` / `unknown_id` | as named |
| 429 | `rate_limited` | the 20-a-day limit, or a user's sixth wrong PIN at a facility on a local date (with `Retry-After` to the facility-local midnight) |
| 503 | `course_pin_unavailable` | the Vault pepper is not provisioned (Q2 only; Q1 is unaffected) |

### Which refusals commit and which roll back

The order is the design: (1) validate the facility and the fix window; (1b) decide the scan's **instant** with a read-only check of whether the fix qualifies; (2) verify the QR signature; (3) Q2 only: the wrong-PIN gate; (4) consume the check-in token, grade the fix, write its evidence row; (5) the scan. A refusal that has to **persist** is decided before anything is consumed and is **returned** (`kind: "refused"`, the transaction commits): a forged QR (writes `fraud_signal(course_qr_forged)`), a wrong PIN and a locked PIN (the counters). Every refusal after step 4 is **thrown**, so `withOwnership` rolls the transaction back and the check-in token and the evidence row the request made are undone (the player can retry). A unit test pins the count of returned refusals; the Deno integration suite proves the rollback against Postgres (the refused scan leaves the second check-in token unspent).

### The scan's instant: when a client-chosen time counts (review L1)

A scan is judged at one instant: the 120 s rule (Q1), the PIN's date and epoch (Q2) and the purchase's `local_date` all read it. It is **the fix's capture time only when that fix qualifies as a co-signal**, and **now** in every other case: no fix, a fix with no token, a spent or another device's token, a simulated fix, a fix outside the polygon, an unattestable-and-failed grade. The Edge decides this **before** the PIN gate commits and before anything is consumed, with `Repo#checkinToken.peekForFix`, the read-only twin of `consumeForFix` (the same predicates, nothing written), and the same geometry match and grading the count step uses. Two results follow, each pinned by a test: a photographed rotating token cannot be burned days later by attaching a fabricated fix dated inside its window (`qr_expired`, the token stays unspent); and a client cannot choose the printed-QR PIN's date, because a fix that does not qualify is a client-chosen number, so the PIN is today's. The database holds the same line independently: `marker_scan_for_actor` raises `22023` for a `p_at` more than 5 minutes from now unless a co-signal accompanies it, so an Edge bug cannot reopen it. (If the fix qualified at the read-only check but a concurrent request spent the token before this one did, the request is `409 fix_not_consumable` and rolls back; it does not carry on at the fix's time.)

### A PIN rotation does not break a queued printed-QR scan (review M1, residuals from round 2)

The PIN a player typed is the PIN **displayed at the instant the fix was captured**. A rotation (the 30-wrong-PIN alarm, S2b's "Rotate PIN", an operator) must change the PIN of scans made after it only. So the database judges a scan's PIN under:

- **the date** of the fix's instant (facility-local), as before;
- **the epoch live at that instant**, from `app.course_pin_epoch_log` (a trigger on any rise of `facility_programme.pin_epoch` writes the new epoch, the one it replaced, and the effective time, so every rotation by whichever route is logged once). Two rotations on one day give three epochs for that date and each queued scan is judged under its own. An instant **at or after** the rotation is judged under the **new** epoch, so an old epoch's PIN tried for a later instant is a counted wrong guess (confirmed by a cell; a free answer would be a brute-force oracle);
- **the pepper in effect at that instant**: the Vault secret `course_pin_pepper` and, for a non-compromise rotation, `course_pin_pepper_previous`, with the moment the current one took effect in **`app.course_pin_pepper_epoch`**.

**The pepper's effective time is a table the operator writes, not Vault's timestamps (round-2 LOW 4; the choice).** The first build used `GREATEST(created_at, updated_at)` of the secret. That moves on any `vault.update_secret` call, a metadata edit included, and whether hosted Vault exposes `updated_at` at all was `[unverified]`; a metadata edit would have silently re-dated the rotation and sent the whole 7-day queue to the wrong pepper. `app.course_pin_pepper_epoch (effective_from)` is written by the rotation procedure itself (`service_role` may SELECT and INSERT, never rewrite or delete; no edge or client role has any privilege), read by one function, and it removes both the `updated_at` dependency and the column grant on `vault.decrypted_secrets` the first build needed. Procedure, one transaction:

1. **Non-compromise rotation** (scheduled): create the Vault secret `course_pin_pepper_previous` holding the **old** pepper (at least 32 bytes; copy it inside the database from `course_pin_pepper`, never by pasting the value: `edge-role-design.md` item 8), `vault.update_secret` the current one, then `INSERT INTO app.course_pin_pepper_epoch (effective_from) VALUES (now())`. An instant before the latest `effective_from` is judged under the previous pepper. **Delete `course_pin_pepper_previous` 7 days later** (the longest a scan can be queued); while it exists, a leaked **old** pepper still verifies for instants before `effective_from`. A previous pepper with no `pepper_epoch` row is **never used**.
2. **Compromise rotation: do NOT copy the old pepper anywhere, write no `pepper_epoch` row.** Replace `course_pin_pepper` only. **If the leaked secret is (or may be) `course_pin_pepper_previous`, delete it from Vault in the same procedure** (and never leave it behind "for later"): an old pepper that stays in Vault is a standing second key the moment any later non-compromise rotation writes a `pepper_epoch` row, because the matcher uses whatever `course_pin_pepper_previous` holds for every instant before the latest `effective_from`; deleting it is what makes the compromise rotation final (S2a gate NIT, closed in the text here; 0050 adds the table's CHECK, below). Every back-dated PIN from before it then no longer verifies (and counts as a wrong guess): the honest-offline players re-scan. That is the accepted, stated cost of a compromise rotation.
3. One previous pepper is kept: two rotations inside 7 days leave the older queued scans judged under the wrong pepper.

**Residual, not closed (round-2 LOW 3).** The instant is the **client-reported** capture time of a fix that qualifies as a co-signal, bounded only by the check-in challenge's window (a prefetched challenge lives 24 hours). So for up to about **24 hours** after an alarm or compromise rotation, a holder of a prefetched challenge issued **before** it can back-date a fix to before the rotation and have the **old epoch's PIN** (and, while a previous pepper exists, the previous pepper's) verify. An instant after the rotation is judged under the new epoch, so this is the whole exposure: back-dating inside the challenge window, nothing longer. The shortest fix would be a server-held issue time per challenge bounding the fix's instant from below, and a compromise rotation would also revoke the open challenges of the facility's devices; neither is built.

A failure counts only when the PIN is wrong for its own instant. A PIN that was **valid for its date and epoch** is never counted as a failure however the clock moved since (the cells: a scan dated yesterday, a rotation today, uploaded today is `ok` and counts nothing; two rotations on one day; an old epoch's PIN tried for a *later* instant IS a wrong guess and counts). The failure counters still run on the facility-local date of the *attempt*, so a client gets no fresh five tries per back-dated day.

### The printed-QR PIN gate cannot be bypassed, and its proof never outlives its transaction (review L5, round-2 MEDIUM)

`private.marker_scan_for_actor` is itself callable by `edge_actor`, so it must not be a way around the lockout. **The choice made: the scan refuses unless the PIN gate passed in the same transaction, for the same instant.** A right PIN makes `course_pin_attempt_for_actor` write a row in `private.course_pin_proof` (backend pid, transaction id, bound actor, facility, local date, **and the instant `p_at` it judged**); a `static_pin` scan without a matching row raises `42501` **before it looks at the PIN**, so the scan can never be called as an uncounted PIN oracle. A scan whose `p_at` differs from the gate's is refused the same way (round-2 NIT: the gate and the scan never judge two instants, so a wrong PIN can no longer go uncounted at the scan); a second gate for the same facility and date in one transaction **replaces** the first (the proof is for the last instant judged). The alternative (repeating the lockout and the counters inside the scan) would have two copies of the counting and a returned `wrong` that no longer commits; one gate, proven by a row, is smaller. (A caller who holds a proof already holds the right PIN, so a `pin_wrong` the scan returns after it reveals nothing.)

**The proof's lifetime is enforced, not assumed (round-2 MEDIUM).** The first build called the table "the same lifetime as `actor_binding`", which was wrong: `UNLOGGED` is a durability setting, not a transaction scope, so every committed printed-QR scan left a row `(backend pid, transaction id, actor, facility, date)` behind; the only cleanup was the attempt definer's `DELETE ... xact <> current`, which the actor-keyed SELECT policy limited to the current user's own rows, so on a pooled backend other players' rows stayed (4 rows from 4 users after the matrix) and nothing in `delete_my_data*` touched the table, contradicting "no new table holds personal data at rest" and the account-deletion promise. Now:

- the scan **deletes the proof it used** when it accepts the scan;
- a **DEFERRED constraint trigger** (`course_pin_proof_expire_trg`, `AFTER INSERT`, `DEFERRABLE INITIALLY DEFERRED`) deletes every row of the backend **at COMMIT**, whoever's it was, so a PIN gate that passed with **no scan after it**, a refused scan and an abandoned flow all leave nothing; a rolled-back transaction's rows vanish with it. (The attempt definer's old cleanup is gone: nothing can be stale, so it was dead code.)
- the table is therefore **empty at rest**, which is the answer to "add it to the delete-my-data purge": there is nothing to purge, and it is proven rather than argued: `24_course_qr_marker_scan_rows.sql` C0 reads `private.course_pin_proof` as the owner (a temporary policy, a positive control proving the probe can see a row) after the edge file **committed** scans and a gate-only transaction, and finds zero rows; the Deno test "the PIN proof is empty at rest" does the same through real commits on pooled connections (a committed gate with no scan, a committed scan, a refused scan);
- `CREATE TRIGGER` needs EXECUTE on the trigger function for the migrating role, so 0046 lends it for that statement and takes it back; an exact `proacl` cell pins `{private_definer=X/private_definer}` for both trigger functions in both harness modes (no lend left for `postgres` or `migration_owner`).

Cells: the scan with no gate, with a gate for another facility, date, instant or actor, and with the gate's transaction already ended all raise; the accepted scan consumes its proof (a second scan needs a second gate); a second gate replaces the first.

### The co-signal is tied to its evidence row by the database (review M2, round-2 LOW 1)

The Edge passes `grade`, `fix id` and `evidence id`; the database does not take them on trust. `private.marker_cosignal_check` reads the evidence row back, for the scan and for the intake, and answers `cosignal_invalid` (422 `invalid_cosignal`) or `cosignal_used` (409 `fix_already_used`) unless **all** hold:

- **identity**: the row belongs to the **bound** user; `source = 'foreground_checkin'` and `source_ref = 'fix:' || fix id`; it is at **this facility** and facility-level (no course); it was **accepted**; the claimed grade equals what the row records; its local date equals the scan's; its recorded capture time is within 1 s of the scan's instant; and **no other scan** already used it (a unique index on `(trail_id, cosignal->>'evidenceId')` is the race-proof backstop);
- **qualification** (round-2 LOW 1: the first read-back checked identity only, and an evidence-endpoint-shaped row, an attested facility-level `foreground_checkin` with `insideBuffer = false`, tier `unverified` and a `radius` geometry, was accepted as a co-signal and credited; only the Edge's `fix_already_used` stopped it): the row's own derived fix (`summary.fix`) must be what `coSignalGrade` and the scorer's `isQualityCoSignalFix` require: its fix id and facility are this call's, from the app, **not** simulated, foreground, bound to a `live` or `prefetched` challenge, accuracy a number from 0 to 50 m inclusive, geometry `polygon`, tier `play-verified`, **inside the buffer**, with a token that is present and whose grade is the claimed one.

Every one has a must-fail cell with a real evidence row (the pgTAP fixtures build real rows with the full derived fix, and a patch of one field each), plus the controls that qualify (a prefetched challenge; exactly 50 m). The same round pinned the scan's **+5 minute future bound with a co-signal** (the mutant that removed it had survived): 4.5 minutes ahead with a valid co-signal and token is accepted, 6 minutes and 2 days ahead are refused outright.

### Staff row landing after the player's sync (review L6)

If the player's intake arrives before S3's staff row exists, the answer is `422 no_pending_purchase`, **rolled back** (the check-in token is unspent, no evidence row is left), and the **same request succeeds** when the row exists. **The choice made: the client retries**, until the fix is 7 days old (the intake's bound). Refusing is safe to retry by construction: the refused request is rolled back, so the check-in token stays unspent and no evidence row is left; the same request is accepted the moment the row exists. The sender is not built (`MARKER_COSIGNAL_UI_ENABLED` stays `false` and nothing calls `api.scanMarker`), so this is a **requirement on that sender**, recorded here and in the wire-type comment: treat `422 no_pending_purchase` as retryable (back-off) until 7 days after the fix, and only then drop it. Keeping the fix server-side as an "awaiting" row was the alternative; it would hold a fix and a consumed token with no purchase to attach to, state the player lane has no other reason to keep. A Deno test pins the sequence (refused, nothing spent, then the staff row inserted, then the same request is `credited`).

### The fix is counted once

A fix that qualifies as a co-signal (foreground, non-simulated, from the app, bound to a challenge, accuracy at most 50 m, inside the polygon plus 50 m of a `play-verified` polygon course of the facility, attestation not `failed`; the twin of packages/rules `isQualityCoSignalFix`, kept in lock-step by a drift test over a grid of fixes) becomes **one** facility-level `foreground_checkin` evidence row (`source_ref = fix:<fixId>`, no course), the same as the check-in endpoint writes. The purchase never scores as a play: not one `app.play` row is written (pgTAP section 11 and the Deno suite). A `failed` grade is no co-signal (the check-in token already opened `fraud_signal(attestation_failed)`); an `unattestable` grade gives `held_review`; a fix that does not qualify gives `pending`.

### Course QR token format

The formats S2b must **mint** and S2a **verifies** (`_shared/course-qr/format.ts` is the definition; `supabase/tests/unit/course-qr-test-keys.ts` is a test-only minter that S2b can be proven against).

**Q1, the rotating token** (a compact JWS, `alg` EdDSA): `b64url(header).b64url(payload).b64url(signature)`, unpadded base64url.

- header `{"alg":"EdDSA","kid":"<kid>","typ":"golfraven-course-qr+jwt"}`, exactly those three members; payload `{"exp":<int>,"fac":"<facility id>","iat":<int>,"kid":"<kid>","nonce":"<b64url of 16 random bytes>"}`, exactly those five members, seconds since the epoch, `exp = iat + 120`, `kid` equal to the header's.
- signature: Ed25519 over the ASCII bytes of `b64url(header) "." b64url(payload)` (the signing input as received). `typ` makes the token useless as any other JWS.
- the **nonce hash** is `hex(SHA-256(the 16 raw nonce bytes))`, lower case: that is `app.course_qr_token.nonce_hash`. S2b writes the row (`nonce_hash, facility_id, issued_by_staff, kid, issued_at, expires_at = issued_at + 120 s`) when it mints. **The database judges the 120 s rule against the row's `issued_at`, not the `iat` claim**, so S2b must write the same instant it signs.
- link: `https://golfraven.<tld>/q/m#<token>` (a fragment, so no server or CDN log sees it).

**Q2, the printed facility QR**: link `https://golfraven.<tld>/q/f/<facility-slug>#<qr_kid>.<sig>`; `sig = b64url(Ed25519 over "golfraven/printed-qr/v1" 0x00 <facility id> 0x00 <qr_kid>)`, 64 bytes, 86 characters. The facility's catalog id is bound into the signed bytes, so the QR of facility X is useless for Y. `app.facility_qr` records the current `qr_kid`; an older kid is `qr_revoked`.

**Keys**: Ed25519 public keys in `app.course_qr_key`, purpose `rotating_token` or `printed_qr`, addressed by `kid` (`^[A-Za-z0-9_-]{1,64}$`), 32 raw bytes as 43 base64url characters. A `kid` that is unknown, revoked or fails to verify is a forgery.

**The daily PIN** (4 digits, derived in Postgres only): `pin = LPAD((first 4 bytes of HMAC-SHA256(pepper, "golfraven/course-pin/v1" 0x00 facility_id 0x00 YYYY-MM-DD 0x00 epoch as 4 bytes big-endian) as an unsigned integer) MOD 10000, 4, '0')`, with `epoch` the facility's `pin_epoch` **at the instant of the scan** (the current `max(pin_epoch)` over the facility's programme rows for a scan made now; an earlier epoch, from `app.course_pin_epoch_log`, for a back-dated one) and `pepper` the Vault secret in effect at that instant (`course_pin_pepper`, or `course_pin_pepper_previous` before the current one took effect). The encoding is pinned by an out-of-database vector (`supabase/tests/unit/course-qr-pin-vector.test.ts`, asserted against the real function in `24_course_qr_marker_scan.sql`). Five wrong PINs per user per facility per facility-local date (the sixth attempt is `locked` even with the right PIN), thirty per facility per date per epoch rotate the PIN (`pin_epoch + 1` on every programme row) and write an alarm.

### The pending-purchase seam (what S3 plugs into)

A purchase with no qualifying fix yet is `pending` with `purchase_evidence.cosignal = {"awaiting": {"from": <ISO>, "to": <ISO>, "until": <ISO>}}`: a fix whose time is in `[from, to]`, received before `until` (7 days from the scan), completes it. Q1: the window is plus or minus 120 s of the token's issue time. Q2: the facility-local day. `marker_cosignal_attach_for_actor` reads only that row (the caller's own, `status = 'pending'`, the facility, the window), never its `method`, so it completes an **S3 offline-code purchase** the same way: S3 inserts `purchase_evidence(method = 'staff_scan', offline = true, status = 'pending', ref_id = 'offline:<device>:<seed version>:<step>', cosignal = {awaiting: {from: step start - 10 min, to: step start + 20 min, until: now + 7 days}})` and the player's later fix (a prefetched-challenge fix, plus or minus 10 minutes of the step, received within 7 days) turns it `valid` and creates or credits the `marker_credit` (pgTAP section 8 uses exactly this stand-in). S3 owns writing that row and the 409 mapping of a replayed code step (0045's `offline_code_step` primary key); nothing in S2a changes when it lands. Rows that share a `ref_id` (one scan across several trails) move together.

### Departures from the plan and the earlier design text, and why

1. **No `pepper_kid` per local day** (plan §4.8). One Vault secret, `course_pin_pepper`, plus an optional `course_pin_pepper_previous` for the 7 days after a rotation (see M1 above); rotating the pepper changes every facility's PIN at once (an incident response). The per-facility epoch already gives the rotation the alarm needs; a dated pepper was more machinery than the player lane's guarantees use. Revisit if S2b wants a scheduled pepper rotation.
2. **Public keys live in a table, not Vault or config.** A public key is not a secret, a table needs no redeploy to revoke a compromised `kid`, and it is the shape `app.catalog_signing_key` (0019) already has. The private halves stay S2b's, in Vault.
3. **The PIN is derived for the date, epoch and pepper in effect at the scan's instant (the fix's capture time when the fix qualifies as a co-signal, else now); the failure counters run on the facility-local date of the attempt.** An offline scan is uploaded days later, so its PIN is that day's, under the epoch that was live then. Counting by the fix's date would hand a client a fresh five tries for each of the last seven dates it could claim. The printed-QR `ref_id` is `pin:<facility>:<local date>` with **no epoch** (a rotation must not allow a second same-day purchase by the same player); the earlier text that put the epoch in it is superseded.
4. **A qualifying fix on a purchase becomes a facility-level `foreground_checkin` evidence row, and that row IS presence-qualifying and money-eligible** (CORRECTED at the S2a re-gate; an earlier draft of this item said the opposite, and an earlier design paragraph said the marker-scan fix was no better than the evidence endpoint's check-in). The two differ in one thing the scorer reads. The **evidence endpoint's** facility-level check-in (`evidence/handler.ts`, around line 829) does no geometry match, so its fix does not satisfy `isQualityCoSignalFix` (a polygon geometry kind, a `play-verified` tier, inside the buffer) and is never a presence fact. **`marker-scan`** derives its fix with `matchFacilityFix` (`privileged.ts`, around line 726), a geometry match against the facility's play-verified polygon, so the row it writes **does** satisfy it: it is `foreground_checkin` with weight 0.3, it counts as the presence fact (`presence_signal`), and with a hard round (a sensor round of 0.85, say) on the same facility-local date it makes `money` true. That is what plan §9.2 sanctions (a purchase's fix is presence at the facility), and it is true for a round on **any** course of the facility, because the row carries no course anchor. It is by design (the fix is the fix), it means a purchase-time fix can lift a later same-day play's corroboration, and the purchase itself still never scores a play. Pinned by `packages/rules/test/marker-scan-presence.test.ts` (a marker-scan fix plus a Garmin round on another course of the same facility and date gives `money`; the same round alone does not; a fix on another date, at another facility, or with no geometry match gives nothing), so a change to the scorer that stopped honouring it fails a test instead of silently starving purchases.
5. **No per-facility daily cap on purchases is built, and nothing blocks one.** The caps are the 20 scans a user a day and the PIN caps; the rest of the abuse model is the credit rule (one credit per player per shop). Plan §8.3's cap (25 static-PIN course-QR credits per facility per day) is a **signal and an alert, not a block**, and is named for S2b below (departure 13).
6. **No purge or retention** for `course_qr_token`, `course_pin_alarm` or abandoned `pending` rows yet (a follow-up: S2b reads the alarm, and `pending` rows past their 7-day deadline stay `pending` forever today; they can no longer be completed, which is harmless but untidy).
7. **`no_pending_purchase` is 422**, not 409: it is not a state conflict the client can retry into. A repeat of an already-counted fix is the 409 (`fix_already_used`).
8. **A facility on two trails gives two purchase rows and two credits** (one per eligible trail) from one scan; `outcome` is the worst of them.
9. **The request also carries `deviceId` and `jti`** (the plan's `{facilityId, fix, jti}` shape was extended): the check-in token is bound to the device that redeemed it, and the Edge has to prove the fix is the one the token was issued for.
10. **The scan consults `app.facility_programme` (the partner programme), never the catalog roster, and the two are not forced to coincide.** A programme facility outside a trail's roster earns a credit that counts for nothing there, and a roster member with no programme row cannot be bought at. Keeping the two in step is the programme editor's job (S6), not the scan's; a pgTAP cell pins that no definer reads `catalog_roster`, so the divergence stays a visible, deliberate choice.
11. **`course_qr_token.kid` is cross-checked in the database.** The scan takes the `kid` the Edge verified the signature under and refuses (`invalid_qr`) a token row minted under a different `kid`, so a token cannot be verified under one key and consumed as another's.
12. **A revoked `kid` is a stale code, not a forgery** (a reprint after a suspected compromise leaves old QRs in the wild): `422 invalid_qr`, no `fraud_signal`, nothing committed. A **forged** signature (or an unknown `kid`) still commits one.
13. **Rate cap of plan §8.3 (25 static-PIN course-QR credits per facility per day) is not built here.** It is a signal and an alert, not a block, and it hooks in where a printed-QR purchase is written: see "What S3 and S2b must do" in `docs/security/p3-money-path-requirements.md`.

### Not built, and honest limits

Staff minting and PIN display (S2b), the offline-code staff step (S3), the mobile scanner, sender and screens (the flag stays `false`), a purge of the new tables, and a UI for the alarm. `[unverified]` on a real Supabase project: that Vault accepts the names `course_pin_pepper` and `course_pin_pepper_previous`; that the operator's rotation transaction (Vault update plus the `app.course_pin_pepper_epoch` insert) is what the hosted project's tooling allows (nothing in the database reads Vault timestamps any more) that `public.hmac` is reachable; that the hosted Edge runtime's WebCrypto verifies Ed25519 (it does under this repository's pinned Deno; the hosted runtime was not run); real PostGIS containment beyond the harness cluster. The forged-QR `fraud_signal` is bounded only by the 20-a-day request limit (an attacker with an account can write up to 20 signals a day).

### Tests and verification

Nothing from before the last edit is counted; each line is a command run on the final tree (the S2a re-gate fixes included).

- **pgTAP, both harness modes, run one at a time** (`HARNESS_MODE=restricted tools/db/test.sh`, then `HARNESS_MODE=superuser tools/db/test.sh`, each a full initdb, migrate, seed, pgTAP, teardown): `Files=33, Tests=3005, Result: PASS` in both (S2a's three files are `24_course_qr_marker_scan.sql` 126 cells, `..._edge.sql` 348, `..._rows.sql` 90). The same runs: the Deno integration suite `314 passed | 0 failed` (21 of them `marker-scan.deno.test.ts`), `verify-function-inventory` OK, `service-role-lint` clean. These are the commands the CI job "player-plane DB" runs.
- `supabase/tests` vitest (`pnpm --filter @golfraven/rules exec vitest run --config ../../supabase/tests/vitest.config.ts`): 59 files, 1197 tests passed (S2a: `marker-scan-handler`, `marker-scan-entrypoint`, `course-qr-format`, `course-qr-cosignal`, `course-qr-pin-vector`: 82 tests). `packages/rules` vitest: 24 files, 443 passed (the new `marker-scan-presence.test.ts`: 5). `apps/mobile` vitest: 65 files, 1967 passed, 6 skipped. The recorder (`record-edge-contract.vitest.config.ts`): passes; the fixture diff against the base is **additions only** (21 `markerscan_*` responses and one `_provenance` key; every existing response and `vectors` byte-identical, checked by loading both files).
- `pnpm -r typecheck` exit 0; `deno check --frozen` and `deno cache --frozen` over every Edge entrypoint exit 0 and **`supabase/tests/deno.lock` is unchanged** (WebCrypto only, no new dependency); `tools/db/check-migrations-immutable.sh --base origin/main`: all 45 existing migrations byte-identical, `0046` added.
- **Mutation proofs** (each on a world-readable `/tmp` copy, deleted afterwards; the test target run; an unmutated control passing; a search of the repository for the mutation marker prints nothing). Database: 40 mutants of 0046 (the window widened or judged against now, used-token unchecked, a pending purchase credited, an unattestable fix `valid`, the PIN unchecked, a broadened token-UPDATE `WITH CHECK`, a dropped explicit uid filter, the PIN judged under the current epoch instead of the epoch at the fix's instant (the `max` versus `min` epoch mutant), the previous pepper ignored, the proof requirement dropped, each co-signal read-back check dropped in turn, the 5-minute guard dropped, and so on): **40 of 40 killed**. Edge, mobile and recorder: 55 mutants (forgery accepted, no `fraud_signal`, a committed refusal thrown or a rolled-back one returned, the PIN gate skipped or run after the consume, the fix replay unchecked, the 120 s rule judged against now or against an unqualified fix, the 120 s boundary at 120 and 121 s, one fix completing more than one scan, the earliest-wins rule, the attempt checking the fix date's PIN, a redundant pending credit left unvoided, the evidence row given a course or another `source_ref`, a foreign facility's token counted, the outcome `some` instead of `every`, each co-signal condition removed, the limit or window constants changed, the entrypoint's order and no-store header and a log line, the PostGIS buffer 50 m changed to 0 and to 50 km, the 55000 and 23505 mappings, the client schema and status set and retry flag and bearer, the recorder's rollback emulation): **55 of 55 killed**. **Round 2** (the proof lifecycle, the qualification read-back, the future bound, the pepper epoch; the same runner, a superuser cluster, the three `24_*` files, an unmutated control passing in both modes): 29 more mutants of the final 0046, **28 killed, 1 equivalent** (no deferred expiry trigger, a non-deferred one, an expiry that deletes nothing, a scan that does not consume its proof, a proof not matched on the instant or the facility, a second gate that keeps the first, the lent EXECUTE not taken back for either trigger function, each of the twelve qualification fields dropped in turn, the accuracy ceiling at 49 and 51, the future bound removed and at 4 and 6 minutes, the pepper effective time inverted and the previous pepper always used). The survivor drops the **explicit actor filter** from the scan's proof lookup: the SELECT policy (`actor_uid = private.actor_uid()`) already scopes the same rows, so it is unobservable by construction and kept as the defence-in-depth the HARD RULE asks for. Three more survived on the first run and were fixed: two clauses made redundant by their neighbours were removed (an object check on the derived fix, subsumed by the field checks), and one was pinned by a new cell (a token marked `present: false` that still carries the claimed grade). Where a mutant turned out to be equivalent it was removed rather than counted (a grade-set clause the read-back makes redundant). The 23505 mapping is now unreachable in practice (the PIN gate's advisory lock serialises one player's same-day race), so the Deno test asserts the duplicate through the lock instead.
- Defects the suite itself found and fixed on the way: (1) the Deno suite's first draft used the shared `GRANT` / `REVOKE ... FROM current_user` helper on `app.checkin_token`, which under `restricted` strips the table owner's own privileges and made seven later account-deletion tests fail with `permission denied` (the suite now uses a POLICY-only helper); (2) `24_course_qr_marker_scan_rows.sql` did the same `REVOKE DELETE` on `course_qr_key`, which the Deno suite (a copy of that database) tripped over; the rows file now uses a policy only. Both are the same trap: a restricted-mode harness role is the table owner. (3) The rotation-log trigger first failed `restricted` at `CREATE TRIGGER` (`permission denied for function`): the migrating role needs EXECUTE on a trigger function when it creates the trigger, and the function is owned by `private_definer` with no other grantee. 0046 now has the owner lend EXECUTE to the migrating role for that one statement and take it back (a pgTAP cell pins the final ACL). The superuser run alone would not have shown it. (4) The first L5 build called `private.course_pin_proof` transaction-scoped when `UNLOGGED` only means unlogged: committed scans left rows behind and the cleanup could not reach other actors' rows on a pooled backend (the round-2 medium above). Its pgTAP cell only proved a *later transaction's* scan was refused, which would have passed with the row still there; the new cells read the table itself after real commits, with a positive control.

## 15. As built: S0

Slice S0 (supply chain, the wrapper, the software-authenticator suite, the database-side signature spike). Branch `p5-s0`, base `1a14d4c` (this document at revision 5 and gate round 5 carried items). **No migration** (`tools/db/check-migrations-immutable.sh --base origin/main`: 45 files byte-identical) and nothing in sections 3 to 6 or 8 to 13 was edited; the spike results below are evidence for the delta gate on sections 3.2, 4.4 and 11 (U3), which decides what they change. Only the "State" cells of section 7 were updated.

### 15.1 What was built

| Piece | Where | Notes |
|---|---|---|
| The two npm pins | `supabase/functions/deno.json` (`@simplewebauthn/server` and `@simplewebauthn/server/helpers`, both `npm:@simplewebauthn/server@14.0.3...`), `tools/service-role-lint/pinned-import-targets.json` (the same two strings) | 14.0.3 is still the registry's `latest` `[verified 2026-10-04: curl https://registry.npmjs.org/@simplewebauthn/server/latest]`, MIT. The service-role lint accepts both (`importMapTargetProblem` permits an exact `npm:` pin with a sub-path), and `node tools/service-role-lint/dist/cli.js supabase/functions` is clean with the wrapper in the tree |
| The lock | `supabase/tests/deno.lock` | Generated by Deno 2.5.2 (`deno cache --config supabase/functions/deno.json --lock=supabase/tests/deno.lock` over the wrapper), **201 added lines and none removed**: one `specifiers` row (`npm:@simplewebauthn/server@14.0.3` -> `14.0.3`; the `/helpers` entry resolves through the same row) and **25 new `npm` entries**, each with a `sha512` integrity and no `tarball` override. The lock now holds **30** npm entries (5 + 25), matching the count section 7 predicted. The committed-lock rules in `tools/service-role-lint` (`committedLockProblems`: version 5, integrity on every entry, no dangling or orphan entry, no specifier downgrade) pass unchanged: 401 tests |
| CI lists | `.github/workflows/ci.yml` | `supabase/functions/_shared/partner/webauthn.ts` is in all three lists (`deno check`, `deno cache --frozen`, and the esm.sh tamper test, which runs `deno cache --frozen` over the same files). `supabase/tests/unit/ci-function-lists.test.ts` now asserts the wrapper is in each, that the three lists stay identical, and that the two new steps below cannot be skipped |
| Pure Deno suite step | `.github/workflows/ci.yml`, "Run supabase/tests/deno-unit (Deno, network denied, cached packages only)" | In the existing `db-tests` job (where Deno 2.5.2 is already installed and the other Deno steps run). `deno cache --frozen` over the test file first, then `deno test --frozen --cached-only --deny-net supabase/tests/deno-unit/`. `--cached-only` proves nothing is downloaded while the tests run, `--deny-net` proves no test opens a socket, and the suite's last test fails if net access was granted. The vitest cell pins the flags and the absence of `--allow-net`, `if:` and `continue-on-error:` |
| npm tamper step (PA-0b) | `.github/workflows/ci.yml`, "deno cache --frozen npm tamper test (partner auth S0, PA-0b ...)" | For each of `@simplewebauthn/server@14.0.3` (the direct pin) and `@levischuck/tiny-cbor@0.2.11` (a transitive that the wrapper's `decodeAttestationObject` runs on client bytes): flip one character of its integrity in a copy of the lock, run `deno cache --frozen` over the wrapper with a **fresh `DENO_DIR`** (npm integrity is checked only on download, as the zod test above records), and require the specific `Tarball checksum did not match ... <package>` message. The existing esm.sh and zod tamper steps still fail on a changed hash with the new lists |
| The wrapper | `supabase/functions/_shared/partner/webauthn.ts` | Pure: no database, no network, no clock, no logging. Detail below |
| The suite | `supabase/tests/deno-unit/software-authenticator.ts` and `partner-webauthn.deno.test.ts` | A software authenticator written against Web Crypto only (ES256, RS256, Ed25519; hand-built CBOR, authenticator data and client data), and 47 Deno tests. A new directory because the two existing ones do not fit: vitest takes only `unit/**/*.test.ts` and would load a Deno test, and `integration/` is run by `tools/db/test-deno-integration.sh` against a live cluster with `--allow-net` |
| The spike | `tools/db/spikes/partner-sig/` (`partner_sig_spike.sql`, `gen-vectors.ts`, `bench.sql`, `run.sh`) | Evidence only, not under `supabase/migrations`, not run by CI or `tools/db/test.sh`. This repository has no layout allow-list file, so the spike sits with its sibling database tooling. Section 15.2 |

**The wrapper, as built.** `registrationOptions`, `authenticationOptions`, `verifyRegistration`, `verifyAssertion`; `RpConfig { rpId, origin }` comes in as a parameter and is validated (an exact `https` origin whose host is the RP ID or a subdomain, else `RpConfigError`, which is a configuration fault and never a client refusal). The challenge is **32 bytes the caller supplies** (4.4: the database issues it); the library is given bytes, not a string, because it would UTF-8 encode a string challenge before base64url, silently changing the value (a test pins this). Every refusal is a `WebAuthnRefusal` whose `message` is its closed code (`malformed`, `cross_origin`, `top_origin`, `attestation_format`, `algorithm_not_allowed`, `key_shape`, `credential_id_mismatch`, `user_handle_mismatch`, `verification_failed`, `not_verified`); the library's own message, which can quote the challenge, origin and counter, rides on `cause` and **a handler must neither log nor return it** (S1.2 maps every code to the one uniform `401`, PA-12).

| L7 rule | What the wrapper does | The control that shows it is the wrapper |
|---|---|---|
| (a) `crossOrigin` | Refuses `crossOrigin` of anything but absent or `false` (so `true`, `"true"`, `1`, `null` and `{}` are all refused), and any `topOrigin`, for **both** ceremonies, before the library runs | The library alone **verifies** a `crossOrigin: true` registration (it never reads the field) and a `crossOrigin: true` assertion with no `topOrigin` |
| (b) attestation `fmt` | Decodes the attestation object with the library's `decodeAttestationObject` and refuses any `fmt` other than `none` **before** `verifyRegistrationResponse`; then re-checks `registrationInfo.fmt` | The library alone **verifies** a `packed` self attestation (it runs its packed verifier on authenticator-chosen bytes). A second test feeds each of seven other format names with a junk `x5c`; the refusal code is `attestation_format`, not `verification_failed`, which is what proves the order |
| (c) `response.id` | Sign-in: `id` and `rawId` must equal the looked-up credential id, before anything else is read. Registration: they must equal the id inside the authenticator data the library parsed | The library alone **verifies** an assertion whose `id` names a different credential, and a registration whose `id` differs from the authenticator data |
| (d) algorithms | `supportedAlgorithmIDs: [-7, -257]` to both `generateRegistrationOptions` and `verifyRegistrationResponse`; at sign-in the **stored** key's COSE `alg` is checked against the same list, because `verifyAuthenticationResponse` has no algorithm option | The library alone **verifies** an Ed25519 registration under its default list and an Ed25519 assertion |

Two checks the design did not list, added because the S0 spike's verifier assumes them and because a stored key is attacker-influenced until S1.1's DB checks exist: the key shape (ES256: EC2, P-256, 32-byte coordinates; RS256: RSA, 256 to 512 bytes of modulus, `e` = 65537), and at sign-in a **required** `userHandle` equal to the stored one (6.1 says "the stored `userHandle` matches the response's"; a discoverable sign-in always returns it). If a real authenticator turns out to emit an RSA exponent other than 65537 or a modulus outside that range, the gate should decide between loosening the wrapper and refusing that authenticator; none was seen here.

**The suite (PA-0a), 47 Deno tests.** Registration and sign-in for ES256 and RS256; backup-eligible and backed-up flags reported (nothing enforced, R-P3). Refused, each by changing exactly one thing in a fixture the same file proves passes: wrong origin, wrong RP ID (hash of another RP ID), missing UV, missing UP, wrong challenge, wrong ceremony `type`, `crossOrigin` (seven values) and `topOrigin`, a non-`none` `fmt` (eight names), `none` with a non-empty statement, a non-CBOR attestation object, an algorithm outside the list (registration and stored key), a mismatched `response.id` (registration, sign-in, and `rawId`), a bad key shape (three variants), a different or absent `userHandle`, an equal counter, lower counters (3 and 4 against 5; 0 against 1 and 5), and a tampered signature, a foreign-key signature and signed-over-different-authenticator-data, each for both algorithms. Accepted: `0` against a stored `0`, `1` against `0`, `6` against `5`, a large jump. The options tests pin `[-7, -257]`, `attestation: none`, a required discoverable credential, required UV, a 120,000 ms timeout, an empty `allowCredentials` and the issued challenge emitted unchanged. Mutation check (done by hand, not committed): removing each of the six wrapper checks above, one at a time, makes between 1 and 4 tests fail.

### 15.2 S0 spike results

**Question (PA-0c, section 12).** Can PL/pgSQL with `numeric` arithmetic and **no extension** verify an ES256 and an RS256 signature in under 200 ms each?

**Answer on this host: yes for both. ES256: PASS, worst warm call of a valid signature 35.5 ms. RS256: PASS, worst warm call 3.7 ms (9.5 ms at a 4096-bit modulus).** Nothing was installed beyond the core server (`pg_extension` holds only `plpgsql`).

| Item | Value |
|---|---|
| Method | `bash tools/db/spikes/partner-sig/run.sh` (`RUNS=30`): a throwaway PostgreSQL cluster (`initdb` under `/tmp/gr-s0-pg`, removed on exit), `partner_sig_spike.sql` loaded, `gen-vectors.ts` generating fresh signatures, `bench.sql` timing each call with `clock_timestamp()` around the whole verify (bytes to integers, checks, arithmetic, comparison), one warm-up call per vector excluded from the statistics |
| Host `[verified: this run]` | PostgreSQL 17.11 (the repo's pinned major), `jit = on`, 4 vCPU Intel Xeon @ 2.80 GHz container, Deno 2.5.2 for vector generation. One backend does the work, so core count does not enter. **Not a Supabase-hosted instance** (see the limits below) |
| Vectors | 50 (28 ES256, 22 RS256), 1,550 calls (868 and 682), of which 1,500 are timed after one warm-up call per vector. **0 wrong verdicts** in all 1,550. Valid signatures come from the software authenticator's real WebAuthn assertions (message = `authenticatorData` ‖ SHA-256(`clientDataJSON`)) and from Web Crypto; one is the RFC 6979 A.2.5 known answer (`sample`, SHA-256), which does not depend on Web Crypto |
| Refused (each one fault from a valid vector, all refused) | ES256: a flipped signature bit, a flipped message bit, another key, `r = 0`, `s = 0`, `s = n`, `r = n`, non-minimal DER, trailing bytes, a wrong outer tag, raw `r‖s` instead of DER, an off-curve key, `x = p`, an empty signature. RS256: a flipped bit, a flipped message bit, another key, a signature one byte short, equal to the modulus, all `0xff`, `1`, `0`, exponent 3, a **short padding string with four trailing bytes after the hash** (the lenient-parser forgery shape), a `0x00` inside the `0xff` run, block type `0x02`, and a valid PKCS#1 v1.5 signature over a **SHA-384** DigestInfo |
| Degenerate keys | Signed with an independent BigInt ECDSA written for the test: public key = G (`d = 1`, so G + Q is a *doubling*) and public key = -G (`d = n - 1`, so G + Q is the *point at infinity*). Both verify, so those two branches of the add routine (`P = Q` and `P = -Q`) are exercised on purpose rather than by luck |

| Algorithm | Warm calls | min | median | p95 | **max** | Cold first call (compilation included) | Criterion (< 200 ms) |
|---|---|---|---|---|---|---|---|
| ES256, signatures that verify | 420 (14 vectors x 30) | 16.1 ms | 21.0 ms | 28.5 ms | **35.5 ms** | 26.3 ms | **PASS** (5.6x headroom on the max) |
| ES256, forged signatures that reach the arithmetic | 90 | 20.4 ms | 21.8 ms | n/a | 31.5 ms | | what a forged sign-in costs the database |
| ES256, synthetic worst case: both scalars all-ones (256 doublings and 256 additions) | 30 | 23.5 ms | 23.6 ms | n/a | 24.2 ms | | **PASS** |
| RS256 2048-bit, signatures that verify | 240 (8 vectors x 30) | 2.3 ms | 2.4 ms | 3.1 ms | **3.7 ms** | 3.5 ms | **PASS** (54x headroom) |
| RS256 4096-bit modulus (the upper bound the verifier accepts) | 30 | 9.0 ms | 9.2 ms | n/a | 9.5 ms | | **PASS** |
| Malformed input refused before the main arithmetic (bad DER, off-curve key, wrong length, `r` or `s` out of range, RSA `s >= n`) | 11 ES256 and 6 RS256 vectors | 0.0 ms | | | 1.1 ms | | negligible |

The ES256 timings range from 16 to 35 ms for the same work. Observed: the synthetic all-ones worst case (median 23.6 ms) costs about the same as a typical call (median 21.0 ms), so the spread does not follow the scalar's bit pattern. Inferred, not isolated: that the spread is scheduler noise on a shared container `[unverified]`. An earlier run of the same harness at `RUNS=2` gave an ES256 max of 34.7 ms, an RS256 max of 3.1 ms and an ES256 cold first call of 46.7 ms.

**What the spike is.** Strict verifiers, core PostgreSQL only: P-256 ECDSA in Jacobian coordinates with Shamir's trick (a single 256-step pass for u1·G + u2·Q), strict DER parsing, `0 < r, s < n`, an on-curve and coordinate-below-p check on the key; RSASSA-PKCS1-v1_5 as a modular exponentiation (`e` fixed at 65537, 17 modular squarings) compared against a freshly built EMSA-PKCS1-v1_5 message, never by parsing the padding. About 290 lines of SQL.

**"0 wrong verdicts" was not proof of strictness (S0-N2, recorded at S1.1b).** The 1,550 calls above all returned the right answer, and yet the S0 gate found by **mutation** that several of the spike's strictness checks were never exercised by any vector: deleting any one of the on-curve check, the coordinate-below-p check, `r < n` and `s >= 1`, the `r + n` branch of the `x(R)` comparison, the RSA `s < n` bound (a malleability gap: `s + n` would be accepted) or the RSA `len(sig) = k` check left every one of the 1,550 verdicts unchanged (S0-L1). A verdict count measures the vectors, not the code. The port into migration 0048 therefore expresses each strictness rule as a **named predicate** with a boundary cell on each side, and every predicate has a mutant that has to be killed (17.4). Do not cite this section's "0 wrong verdicts" as evidence that a verifier is strict.

**What it is not, and the limits the delta gate should weigh.**
1. **Not a hosted instance.** A hosted Supabase database may be several times slower than this container, and its PostgreSQL build, `numeric` implementation and CPU quota are `[unverified]`. The margin is 5.6x for ES256 and 54x for RS256. Repeating the run on the real staging database is a deploy-time step (section 15.3, R7) and needs a role that can create a scratch schema; the harness needs no extension and removes nothing but its own schema.
2. **CPU cost per sign-in.** ES256 takes about 20 to 35 ms of one backend's CPU per assertion, forged or genuine. An attacker who can present assertions for known credential ids pays the database for each one; section 8's limits and the order of the checks (the challenge HMAC and the lookup run first) decide whether that is acceptable. Not analysed here.
3. **Not constant-time**, deliberately: everything verified is public.
4. **No COSE parsing in SQL.** The spike takes the raw coordinates or modulus and exponent. S1.1 either stores the parsed columns beside the COSE bytes or parses CBOR in SQL; both are small next to the measured arithmetic, and neither was measured.
5. **Registration still has no signature to check** (R4-L2): with `attestation: none` there is nothing for a verifier to verify, so database-side verification would close the passkey half of R-P1 for sign-in only. Section 12 already says S1.6 is "skipped if the S0 spike shows database-side verification is practical"; that is the delta gate's call, not this slice's.
6. `valid-high-s` verifies (ECDSA `s` and `n - s` are both valid; WebAuthn does not require low-s). Replay is stopped by the nonce and the counter, not by signature uniqueness.

**Reproduce:** `RUNS=30 bash tools/db/spikes/partner-sig/run.sh` (needs PostgreSQL 17 binaries at `PG_BIN_DIR`, default `/usr/lib/postgresql/17/bin`, and `deno`; exits non-zero if either algorithm fails the criterion; refuses to reuse an existing `SPIKE_PG_DIR`). The functions must not be copied into a migration as they stand.

### 15.3 PA-0c checks that could not be run here

None of these was run. Each was left as a procedure rather than guessed. `not run here: needs deploy` means a Supabase project the owner can deploy to (staging is enough); `needs device` means the physical hardware named.

| # | Check (section 11) | State | Procedure |
|---|---|---|---|
| R1 | npm resolution of the 30-entry graph by the hosted Edge runtime | **not run here: needs deploy** | Deploy a **throwaway** function (not committed; delete it afterwards) whose `index.ts` imports `../_shared/partner/webauthn.ts` through `supabase/functions/deno.json` and returns `{ optionsOk, registered, signedIn }` after calling `registrationOptions`, `verifyRegistration` and `verifyAssertion` on a fixture generated locally by `software-authenticator.ts` (paste its JSON in). Call it with `curl -i`. **Pass:** `200` and all three `true`. **Fail:** a module-resolution or `npm:` error in the function logs, or a cold start slower than the platform allows, either of which sends the design to the "small in-tree verifier" option of section 7 |
| R2 | CPU time for assertion verification in the Edge | **not run here: needs deploy** | Same probe: verify the ES256 and the RS256 fixture 50 times each in one invocation and a fresh invocation each, recording `performance.now()` per call and the platform's own CPU or execution-time figure from the function logs. **Record** p50 and p95 per algorithm, cold and warm, and whether any invocation was terminated. No threshold was set in this document; `[proposed]`: pass if p95 is under 100 ms warm and nothing is terminated at 50 consecutive calls |
| R3 | `verify_jwt = false` per function | **not run here: needs deploy** | Add `[functions.<probe>] verify_jwt = false` to `supabase/config.toml` for the probe and deploy it. `curl -i -X POST .../<probe>` with **no** `Authorization`, then with `Authorization: Bearer gr_ps_0000000000000000000000000000000000000000000` (a partner-shaped token). **Pass:** both reach the function (its own body, not the gateway's `401` JWT message). **Control:** redeploy with the default and show the same calls get the gateway's `401`; without the control a pass proves nothing |
| R4 | Function CORS preflight | **not run here: needs deploy** | `curl -i -X OPTIONS .../<probe> -H 'Origin: https://<the staging partners origin>' -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: authorization,content-type,x-gr-pop'`, then the same for `PATCH` and `DELETE`, then with a foreign `Origin`. **Pass (PA-10's shape):** the allowed origin gets a `2xx` whose `Access-Control-Allow-Origin` is exactly that origin and whose allow-methods list the method asked for; the foreign origin gets no `Access-Control-Allow-Origin`; and the request reaches the function with `verify_jwt = false` rather than being answered by the gateway |
| R5 | Vault and `public.hmac` | **not run here: needs deploy** | In the SQL editor as the project's owner role on staging: `select vault.create_secret(gen_random_uuid()::text || gen_random_uuid()::text, 's0_probe_key');` then `select encode(public.hmac('golfraven/partner-challenge/v1'::text \|\| 'x', (select decrypted_secret from vault.decrypted_secrets where name = 's0_probe_key'), 'sha256'), 'hex');` (the `0045:148-152` shape). **Pass:** a 64-hex result from both. **Then delete the probe secret.** If `public.hmac` is absent, record where `hmac` lives (`extensions.hmac`) because every definer of 4.4 and 5.1 names it |
| R6 | `auth.sessions` columns for the freshness checks | **not run here: needs deploy** | `select column_name, data_type from information_schema.columns where table_schema = 'auth' and table_name = 'sessions' order by ordinal_position;` and, as the role the definers run as (`private_definer`, once the owner has applied 0041), `select id, user_id, created_at from auth.sessions limit 1;`. **Pass:** `id`, `user_id` and `created_at` exist and are selectable (0041's `[unverified]` line). **Record** every other column (for example anything resembling a factor, AAL or `amr` entry), because 3.3's revisit trigger depends on whether a session can prove how it was created |
| R7 | The spike on the hosted database | **not run here: needs deploy** | Section 15.2 measured a local PostgreSQL 17.11. On staging, run `partner_sig_spike.sql` in a **scratch schema it creates and drops** (it already uses only `spike_sig`), load vectors from `gen-vectors.ts`, run `bench.sql` with `-v runs=15`. **Pass:** the same VERDICT table, every row `PASS`. **Record** the max against the 200 ms criterion; this is the number that decides whether the local result carries over |
| R8 | An installed-PWA passkey ceremony | **not run here: needs device** | An iPad (record the iPadOS and Safari version) with a throwaway page on the staging partners origin, installed to the Home Screen (Share, Add to Home Screen). In the installed app run `navigator.credentials.create` with `rp.id` the staging RP ID, `residentKey: 'required'`, `userVerification: 'required'`, `attestation: 'none'`, `pubKeyCredParams` `[-7, -257]`, then `navigator.credentials.get` with an empty `allowCredentials`. Send both results to a script that calls `verifyRegistration` and `verifyAssertion` from the committed wrapper with the origin and challenge the page used. **Pass:** both ceremonies complete inside the installed app and verify. **Record** which authenticator the iPad offered and whether the same page in plain Safari behaves differently |
| R9 | The shared-iPad chooser | **not run here: needs device** | On one shop iPad, register passkeys for **two** test identities under the same RP ID (R8's page, two user handles), then run `get` with an empty `allowCredentials`. **Pass:** the system chooser lists both, each selectable by name. **Record** whether it lists them with the display names given, and what a person sees when there are five (6.2 step 2 assumes they pick their own) |
| R10 | Passkey sync on a shop iPad (R-P3) | **not run here: needs device** | With the R9 credentials: (1) read the registration's backup flags through `verifyRegistration` (`backupEligible`, `backupState`); (2) on a **second** device signed in to the same Apple ID, attempt `get` for the same RP ID, with iCloud Keychain on and then off on the shop iPad; (3) repeat on an iPad signed in to a **dedicated shop Apple ID** with Keychain off, and record whether the passkey still works after a restart. **Record** for each configuration: `backupEligible`/`backupState`, whether the second device can use the credential, and whether the sign count is `0`. The onboarding checklist wording (R-P3: "a dedicated shop Apple ID with iCloud Keychain off is the likely rule") depends on the third row |
| R11 | PBKDF2 time on a low-end iPad | **not run here: needs device** | On the oldest, slowest iPad a shop would use, in Safari (not the installed app, to remove one variable; repeat in the installed app if the numbers are close to the limit), run the snippet below. **Record** the three timings per count. `[proposed]` reading: choose the largest count whose slowest run stays under 1.5 s; the floor in 6.3 is 210,000 rounds. The container measured 57, 115, 323 and 555 ms (section 14); the iPad is expected to be several times slower and that expectation is `[unverified]` |
| R12 | A60: `navigator.credentials.get` against a stored challenge offline in an installed PWA | **not run here: needs device** | Out of S0's scope by the slice table (S7e), recorded so it is not lost: with R8's installed page and a challenge cached before going offline, put the iPad in airplane mode and call `get`. **Pass:** the assertion completes with no network |

```js
// R11: paste into a script on a throwaway page and write the result to the page (an iPad has no console)
const out = [];
for (const iterations of [100000, 210000, 600000, 1000000]) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode("1234"), "PBKDF2", false, ["deriveBits"]);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const ms = [];
  for (let i = 0; i < 3; i++) {
    const t0 = performance.now();
    await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
    ms.push(Math.round(performance.now() - t0));
  }
  out.push(`${iterations}: ${ms.join(" / ")} ms`);
}
document.body.textContent = out.join("\n");
```

The results of R1 to R12 go into this section as a dated "S0 device and deploy results" subsection when they exist, each with its pass or fail, and the delta gate on 3.2, 4.4 and 11 reads that subsection together with the spike above. Until then PA-0c is **partly** satisfied: the signature spike is recorded with a pass, and the rest is recorded as not run, with the reason.

### 15.4 Verification run for this slice

| Check | Command | Result |
|---|---|---|
| Pure Deno suite, network denied | `deno test --config supabase/functions/deno.json --lock=supabase/tests/deno.lock --frozen --cached-only --deny-net supabase/tests/deno-unit/` (after a `deno cache` of the test file, from an empty `DENO_DIR`, which is the CI shape) | 47 passed, 0 failed |
| `deno check` and `deno cache --frozen` over the CI lists | the two CI steps' `run:` blocks, extracted from `ci.yml` and executed | exit 0, exit 0 |
| Tamper steps | the esm.sh, zod and new partner steps' `run:` blocks, executed | all three PASS; the partner one for both targets, "Tarball checksum did not match" naming the package |
| Spike | `RUNS=30 bash tools/db/spikes/partner-sig/run.sh` | both PASS, 0 wrong verdicts |
| `supabase/tests/unit/ci-function-lists.test.ts` | vitest, from `@golfraven/rules` | 17 passed |
| Service-role lint and lock tests | `pnpm --filter @golfraven/service-role-lint test`, and `node tools/service-role-lint/dist/cli.js supabase/functions` | 401 passed; "clean" |
| Migrations immutable | `tools/db/check-migrations-immutable.sh --base origin/main` | OK, 45 files byte-identical |

A forward note for S1.2: the wrapper returns the library's `credential.counter` unchanged; the compare-and-set that advances it is the database's (PA-9), and `verifyAssertion` is deliberately told the stored count rather than reading it.


## 16. As built: S1.1a

Slice S1.1a (the partner-auth **database spine**: roles, binding, tables, the authorization seam, session protection, invariants, the D12 revocations, X9, the registries and checks). Branch `p5-s11a`, base `91351c3`. **One migration, `0047_partner_auth_spine.sql`**; `0001`-`0045` are byte-identical (`tools/db/check-migrations-immutable.sh --base origin/main`) and `0046` belongs to a parallel slice and is not created. **Not built here:** the mint, `register_first`, the invite and enrolment accept definers, the challenge issuer and the SQL signature verifier (S1.1b), `partner_pin` and `partner_totp` (S1.3, S1.4), and every `_for_partner` definer (S1.5 onward). The migration's header is the reading guide; this section is the record of what differs from sections 4 to 6 and what the next slice may rely on.

### 16.1 What was built

| Area | As built |
|---|---|
| Roles | `edge_partner` (the lane: no privilege on any table or schema `app`; `EXECUTE` on exactly `bind_partner_session`, `partner_binding()`, `partner_binding_kind()`) and `edge_partner_minter` (`USAGE` on `private` and nothing else until S1.1b); `edge_gateway` is the only member of each (`SET TRUE`, `INHERIT FALSE`). Five owner roles, all `NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS`, members of nothing **with no member**: `partner_session_toucher`, `_issuer`, `partner_pin_verifier`, `_totp_verifier`, `_reauth_verifier` (the sixth, `_flagger`, was removed at the S1.1a gate). The migrating role holds membership in two of them (`toucher`, `pin_verifier`: the only two that own functions in this slice) for the length of the file and loses `SET` and `INHERIT` again at the end, keeping only the PG16+ creator `ADMIN` (R5-L3) |
| Binding | `private.actor_binding.kind` gains `'partner'` and the table gains `session_id` (`CHECK ((kind = 'partner') = (session_id IS NOT NULL))`). `private.actor_uid()` returns NULL for `partner`; `bind_actor_internal` is redefined only to clear `session_id` on a pooled re-bind. `private.bind_partner_session(hash)` is the only producer; every refusal is `RAISE EXCEPTION 'partner_session_refused' USING ERRCODE = '28000'` (unknown, malformed or NULL hash, idle- or absolute-expired, revoked, revoked credential, demo account, sponsor-only member, no active membership, a second bind in the transaction) |
| Tables (FORCE RLS, no privilege for `anon`, `authenticated`, any edge role or `service_role`) | `partner_credential`, `partner_auth_challenge` (used nonces), `partner_session` (`UNIQUE` on `otp_proof_gotrue_session_id`), `partner_enrolment_token`, `partner_rp_config` (singleton), and the `partner_invite` additions (`accepted_by`, `registered_credential_id`, `revoked_at`, `revoked_by`, `attempts`; `CHECK`s `partner_invite_token_hash_hex` and `partner_invite_expiry_ceiling`). `supabase/tests/helpers.sql`'s two `partner_invite.token_hash` fixtures are now real SHA-256 hex (L4) |
| `partner_authorize(facility, trail, roles[], class)` | `SECURITY DEFINER`, `VOLATILE`, `search_path = ''`, `EXECUTE` for nobody. Needs a partner binding; **A2 and A3 fail closed first** (nothing below can relax it, PA-4b); locks only the bound session row (`FOR SHARE`, `FOR NO KEY UPDATE` when the call writes `last_seen_at` or consumes a grant); re-reads liveness, membership, scope and the policy (`aal`, idle) on every call; `aal` gates every class (M2); A1 spends a single-use PIN grant through `partner_pin_grant_consume()` (owned by `partner_pin_verifier`) only after scope has passed, so a refused call does not burn the grant |
| Session protection | The authority triggers are `SECURITY DEFINER` functions owned by the `toucher`: `partner_member` insert, update of `revoked_at` / `role` / `user_id` / `org_id` and delete, `admin_user` insert and delete (revoke the person's live sessions), `partner_scope` update and delete (**touch** the org members' sessions: `authority_touched_at`). The accepting session is exempt only on a member INSERT or a reactivation. `partner_session_guard` (BEFORE UPDATE, `SECURITY DEFINER`, `search_path = ''`) is owned by `private_definer`, which owns no table (R5-N1); it enforces the table in 4.3. `private.partner_sessions_revoke(kind, id, reason)` is subject-based, derives the sessions itself, writes one `audit_log` row per call, and is executable by `private_definer` only (R5-L2) |
| Who writes `partner_session` | `private_definer`: the one policy `pd_partner_session_action` (keyed on `private.partner_binding_session()`) plus column grants (`last_seen_at`, `revoked_at`, `revoke_reason`, `otp_proof_until`, `otp_proof_gotrue_session_id`); each verifier role owns exactly its column(s); `toucher` revokes and touches; `issuer` inserts, behind the INSERT guards (gate M2). No GUC window anywhere in a write path |
| Invariants | `partner_scope` `UNIQUE (org_id, facility_id)` plus an advisory-locked trigger: a facility org holds exactly one scope row and it is a facility scope; `partner_member` role must match the org's kind by explicit lists (never `partner_role_rank`); an org's kind is immutable (`BEFORE UPDATE OF kind` trigger), so a role check made at insert time cannot be bypassed by re-kinding the org |
| D12 / 5.5 | `REVOKE SELECT FROM authenticated` on the 14 `api` views and the 14 base tables; `api.offer` and `api.my_offers()` answer live offers with the five scope-conditional columns constant NULL **for everyone**; `offer_read` narrowed to `status = 'live'` |
| X9 | `REVOKE EXECUTE ON FUNCTION private.offline_code_record_step_for_actor(uuid, integer, bigint, text) FROM edge_actor`; the Edge wrapper `Repo#offlineCode.recordStep` and its call sites are removed; the primitive's atomic-replay proofs call it as `private_definer` after `bind_actor` (R2-L8): `23_offline_totp_seed_record.sql` and the Deno `offline-code` suite |
| Account deletion and export | `partner_credential`, `partner_session`, `partner_enrolment_token`, `partner_auth_challenge` are classified in `pii_retention_policy` and `export_my_data` gains one block (credential metadata only: never the public key, the credential id or the sign counter); `delete_my_data`'s generic pass reaches them through registered window pairs |
| Registries and checks | `function_inventory` gains `expected_edge_partner` and `expected_edge_partner_minter`; `definer_policy_allowlist` gains `role_name` (the owner roles' policies are registered and fixtured like `private_definer`'s: R5-L4); new `private.partner_owner_privilege` (the exact privileges the six owner roles may hold) with a fixture (`partner_owner_privileges.txt`); checks 9 to 12 extended, **check 14** added with its three clauses and a must-fail fixture for each (`partner_kind_readers.txt` is clause (c)'s named exception list); a vitest parity test pins that the `.mjs` and matrix 10 embed the same check SQL |

### 16.2 R5 items, resolved

- **R5-L1.** No `xmin` comparison and no artefact rows. `partner_pin_verifier`, `partner_totp_verifier` and `partner_reauth_verifier` each hold the column-level `UPDATE` on exactly their column(s) and each has its own policy keyed on the bound session; `private_definer` holds none of those columns (`PA-4d` drives each through a stub as the verifier role and shows the other roles are refused with `42501`). The guard keeps immutability, monotonicity and the now + N caps. `otp_proof_gotrue_session_id` has a `UNIQUE` index (the 0041 shape). 4.3's mechanism text and table are updated accordingly; R5-N2 is moot.
- **R5-L2.** `partner_sessions_revoke(kind, id, reason)`, subject-based, one audit row per call.
- **R5-L3.** Check 9 follows 0041's form for all five owner roles (no member, no `SET` or `INHERIT` for anyone, only the creator `ADMIN` may remain).
- **R5-L4.** Each owner role has its own `TO <role>` policies, `USAGE` on `app` and `private`, an allow-list row and a fixture line; the exact column and relation privileges are the `partner_owner_privilege` registry, diffed by check 12 in both directions.
- **R5-N1.** `partner_session_guard` is owned by a role that owns no table, so its owner cannot `DISABLE TRIGGER`; check 9 / the registry assert it.

### 16.3 Departures from sections 4 to 6, and why

1. **Five owner roles, not three** (R5-L1, above; the flagger was dropped at the gate). The three verifier roles own no function in this slice (S1.3, S1.4 and S1.5 add them); their column grants, policies and stub proofs are here so the mechanism is verified before the definers exist.
2. **`partner_pin` and `partner_totp` are not created.** They carry the verifiers and belong to S1.3 and S1.4. The PIN grant mechanism (`pin_grant_until`, the 60 s cap, single-use consumption by A1) is built and tested without them.
3. **Every GUC-keyed `private_definer` window is closed under a partner binding (S1.1a gate H1, which reversed the first version of this departure).** Design 4.3 accepted the 0016 window pairs as the registry pass requires them (check 8). The author's first fix closed them on the four new tables only and left the 0016 tables open; the gate reproduced the R3-M1 outcome live through the open ones (a partner-bound `private_definer`, with `app.delete_my_data.*` planted, un-revoked and promoted a member, deleted a membership and deleted an `admin_user` row) and found PA-4c (i) vacuous because it never planted a GUC. Section 8c of 0047 now adds `AND private.partner_binding_kind() IS DISTINCT FROM 'partner'` to the USING and WITH CHECK of **every** GUC-keyed policy of `private_definer`, discovered from the catalog (102 policies on top of the 16 written closed), because no window needs to be open under a partner binding (`delete_my_data`, the purges and the guards run under a user binding, a system delegate or none). **A slice that merges later is covered two ways:** a policy that exists when 0047 applies is closed by 8c (S2a's 0046 has no GUC-keyed policy, so there was nothing to close; the catalog-driven cell would have found it); a policy added afterwards must carry the conjunct itself, and **check 15** (`verify-function-inventory.mjs`, with its matrix twin and must-fail fixtures) fails the build until it does, naming the conjunct to add. PA-4c (i) now plants every setting, runs the gate's three probes with a no-binding control, and is **catalog-driven**: for every (table, command) a window policy covers, the rows reached with the settings planted equal the rows reached with them unset under a partner binding, with a control that the same statements differ with no binding; a setting the cell does not know fails it.
4. **`api.offer` and `api.my_offers()` are NULL-column for everyone**, not only "to a scoped member too" (PA-6's wording): a player never needed the budget or eligibility, and one constant is simpler to prove than a conditional. `offer_read` is narrowed to live offers, which also removes a scoped member's PostgREST view of drafts. Partner reads of offers return in S6 through the Edge.
5. **Check 14 (a), second half, is a text check** over the matrix files (a file that names the `_for_partner` function and expects `42501`); it makes "no cell at all" a build failure and leaves the cell's correctness to review, as the design says it would. No `_for_partner` function exists yet, so the family is empty and every clause is exercised by planted fixtures.
6. **Registries gained shape the design did not name:** the two `expected_edge_partner*` columns, `definer_policy_allowlist.role_name`, and `private.partner_owner_privilege`. They are the smallest way to make the new roles' grants and policies checkable in the same way 0041 made the minter's.
7. **`delete_my_data`'s catalog-driven matrix test (`09`)** skips a table `service_role` cannot read; the partner tables are exactly that by design, and `25_partner_auth_spine.sql` PA-1b seeds a real account's rows in every one, deletes the account through `delete_my_data` and reads the result back.
8. **The `Repo#offlineCode.recordStep` types** `OfflineStepInput` and `OfflineStepRecordResult` stay in `types.ts` (the vocabulary of the database primitive and of the unit fake); the unit fake keeps a staff-recorder model (`makeFakeStaffRecorder`) outside the `Repo` type, so the verify-then-record composition tests still run.
9. **The runtime self-check needed no change**, but `edge-role.deno.test.ts`'s assertion that `edge_gateway`'s membership closure is exactly the model's roles now lists `edge_partner` and `edge_partner_minter` (six roles, not four). The self-check walks the closure and refuses on attributes (`SUPERUSER`, `BYPASSRLS`), not on names.

### 16.4 The S0 gate ruling, applied

The S0 spike passed (15.2): **database-side signature verification is the plan of record for sign-in sessions.** Sections 3.2, 4.4 and 11 are amended in place (a dated note at each), slice **S1.6 and its re-verifier are moot** (`partner_reverify_batch`, `partner_reverify_flag`, `partner_audit`, `partner_flag_enforce`, open item U2), and S1.1b puts the SQL verifier inside the mint definer. The role `partner_session_flagger`, its two policies and the `flagged_at` / `flag_reason` columns were **removed from 0047 at the S1.1a gate**; the `mint_*` evidence columns stay (they are the record of what was verified). Registration still carries no signature (R4-L2); that residual stands.

### 16.5 Seams left for S1.1b (and later)

- **The mint.** `partner_session_issuer` already holds `INSERT` (and column `SELECT`) on `partner_session` and `partner_credential` with its `TO` policies; the mint and `register_first` definers are to be **owned by it** and executable by `edge_partner_minter` only (the minter holds `USAGE` on `private` and no `EXECUTE` yet; `function_inventory.expected_edge_partner_minter` is the registry column to set). Insert-time columns the guard treats as immutable afterwards: `mint_kind`, `mint_nonce_hash`, `mint_authenticator_data`, `mint_client_data_json`, `mint_signature`, `enrolment_until`, `pop_jkt`; the table `CHECK`s require a `sign_in` mint to carry the signature.
- **The SQL verifier.** A pure function (core PostgreSQL only; no extension) from the S0 spike's strict ES256 and RS256 routines; it needs an inventory row, a body that passes check 13, and COSE parsing in SQL (or stored parsed columns beside the COSE bytes: the spike took raw coordinates).
- **Challenges.** `partner_auth_challenge` holds only the **used** nonces (`nonce_hash` primary key, so a replay is a unique violation); the issuer is stateless; `partner_rp_config` is a singleton the mint reads for origin and RP id (no row is seeded by this migration: the deploy step does it, with the origin and RP id from the environment).
- **Accept definers.** `partner_invite` has `accepted_by`, `registered_credential_id`, `revoked_at`, `revoked_by`, `attempts` and the expiry ceiling; `partner_enrolment_token` exists. Their definers add policies on `partner_member`, `partner_scope`, `partner_session`, `admin_user` and `partner_credential`: **each must be reviewed against the union of existing policies (R3-M1) and re-run through PA-4c (i), (ii) and (iii)**; the pgTAP file's cells are written to be pointed at a new writer by adding a row.
- **The family.** Every `*_for_partner` function must call `private.partner_authorize(` as its **first executable statement** and needs a behavioural cell that expects `42501` under a partner binding with no scope (check 14 (a)); a function that must read `kind = 'partner'` outside the family goes in `supabase/tests/fixtures/partner_kind_readers.txt` or inside the family (clause (c)).
- **PIN and TOTP.** `partner_pin_grant_consume()` is the only reader of `pin_grant_until`; S1.3's PIN definer is **owned by `partner_pin_verifier`** and writes `pin_grant_until` (at most now + 60 s); S1.4's TOTP definer is owned by `partner_totp_verifier` (`aal`, `mfa_until`); the reauth definer by `partner_reauth_verifier`. The migrating role needs `SET` on whichever owner it uses for `ALTER FUNCTION ... OWNER` for the length of that migration and must drop it again (the bracket in 0047 section 1 and 9).
- **Revocation helpers.** `private.partner_sessions_revoke(kind, id, reason)` is for the reach-checked revoke, recover, revoke-all, credential-revoke and TOTP-reset definers (after their own scope checks); it is executable by `private_definer` only.
- **Classes and the "anywhere" branch (S1.1a gate).** `partner_authorize` takes `A0`, `A0_KEEPALIVE`, `A1`, `A2`, `A3` (A2 and A3 closed until S1.3 / S1.4) and the two session classes: `SESSION` (sign-out, lock: advances `last_seen_at`) and **`PEEK`** (GET session: no scope, no aal gate, **never** advances `last_seen_at`; S1.2 uses it). Check 14 (a3) requires the class to be a **string literal**, and allows `SESSION` / `PEEK` only for a function named in `supabase/tests/fixtures/partner_session_class_functions.txt` (empty today; S1.2 adds its session routes after review). **A call with BOTH the facility and the trail argument NULL means "this role anywhere"** (an active membership with a listed role, or an admin): it is for a function that acts on no object. **An object-scoped definer must never use it**: it must pass the facility or the trail it acts on.
- **READ COMMITTED.** `partner_authorize` and the facility-scope invariant refuse any other isolation level (42501 and 25000): both rely on a fresh snapshot per statement. The Edge opens its transactions at the default level.
- **Inserts.** The mint is a `BEFORE INSERT` guard's client: a session is born at aal 1 with nothing verified, on the database's clock (within a minute), with an absolute life of at most the person's ceiling (staff and manager 8 h, operator 4 h, admin 1 h; `partner_session_policy` now returns it), an enrolment window only on a `register` mint (at most 15 minutes); a credential is born live and unused. A fixture that needs a back-dated row switches the guard off for its seeding (`ALTER TABLE ... DISABLE TRIGGER partner_session_insert_guard_trg`) and back on.
- **A new GUC window** must carry `AND private.partner_binding_kind() IS DISTINCT FROM 'partner'` itself (check 15 names it) and its setting must be added to `plant_all` in PA-4c (i) (the cell fails on a setting it does not know). **S2a (0046) merged ahead of this slice and has no GUC-keyed policy**; its binding readers (`course_pin_attempt_for_actor`, `course_qr_public_key_for_actor`, `marker_cosignal_attach_for_actor`, `marker_scan_for_actor`) were reviewed (each refuses any binding kind but `user`) and listed in `partner_kind_readers.txt`.
- **Section 8c also closes windows a later slice may expect open (S1.1a LOW 3; S2b / S3 / S5).** The partner conjunct is on `pd_offline_code_step_insert` and `pd_offline_code_step_prune` (keyed on `app.offline_code.target_device_id`) and on the `app.guard.*` read windows (`pd_play_guard_read`, `pd_entitlement_guard_read`, `pd_offer_code_guard_read`, keyed on `app.guard.play_id`, `.entitlement_id`, `.offer_code_id`). Under a partner binding **none of them opens**, with any setting planted. S3's verify-and-record (design X9: it calls the 0045 primitive under a partner binding) and any S5 partner redeem that relies on the guard reads will therefore need **binding-keyed policies of their own** (a policy keyed on `private.partner_binding_session()`, not on a settable GUC: the money-doc HARD RULE); both fail closed until then, so the omission is visible as a refusal, not as a leak.
- **Two-connection proofs** are `tools/db/test-partner-serialisation.sh` (wired into `tools/db/test.sh`): a new writer of `partner_session` or a new authority trigger should get a case there.

### 16.6 Verification run for this slice

| Check | Command | Result |
|---|---|---|
| Whole database suite, both harness modes (fresh throwaway cluster each, under `/tmp`, deleted afterwards) | `HARNESS_MODE=superuser tools/db/test.sh` and `HARNESS_MODE=restricted tools/db/test.sh` | each: 34 pgTAP files, **2821 tests, PASS**; the replay, money-path, sign-in and **partner serialisation** concurrency scripts pass; the Deno integration suite 293 passed, 0 failed; the standalone function-inventory check and the service-role lint pass; the H2 "no `migration_owner` in the cluster" run passes |
| New pgTAP | `25_partner_auth_spine.sql` (291), `25_partner_auth_spine_edge.sql` (34, a real `edge_gateway` login) and `..._edge_cleanup.sql` (2), `23_offline_totp_seed_record.sql` (50), `23_offline_totp_seed_edge.sql` (47), `10_function_inventory.sql` (115: every extended check and check 14 has a must-fail fixture) | PASS in both modes |
| Two-connection proofs | `tools/db/test-partner-serialisation.sh` (member revoke, scope delete, a writing action, the revoker holding the lock first on both lock paths, the planted GUCs) | PASS in both modes; every case shows the waiting session in `pg_locks` |
| Unit suite | `pnpm --filter @golfraven/rules exec vitest run --config ../../supabase/tests/vitest.config.ts` | 55 files, 1124 tests, PASS (includes the check-parity test) |
| Mobile recorder, service-role lint, typecheck | `record-edge-contract.vitest.config.ts`; `pnpm --filter @golfraven/service-role-lint test`; `pnpm -r typecheck` after `GOLFRAVEN_DEMO=1 pnpm -r build`; `deno check` over the CI lists and the changed integration tests | 1 passed; 401 passed; clean; exit 0 |
| Migrations immutable | `tools/db/check-migrations-immutable.sh --base origin/main` | OK, 45 files byte-identical |
| Mutation pass (in a scratch copy, never the worktree; each mutant applied to the migration, the `.mjs` or matrix 10, a fresh database built, the new and the affected files run) | `actor_uid()` NULL rule; the guard's columns, caps and un-revoke rule (user id, mint signature, expiry, `aal`, PIN cap); A2 and A3 fail-closed; the `aal` gate; the lock (each of the two lock statements); the scope re-read; the revoked, expired and credential re-check; the A1 consumption; the role and scope invariants; the lock policy broadened; the authority trigger touching instead of revoking; the credential guard (key, un-revoke); D12 (a view privilege, the offer policy); X9; the demo refusal; `private_definer` granted `aal`; the delete-window conjunct (alone and with its pair); a drifted matrix copy and a drifted `.mjs` constant | **all killed.** Three survived the first pass and were closed with new cells (the write-path lock: cases 2b and 3b; the view-level D12 privilege: a PA-6 catalog cell; the `.mjs` constant: the parity test). Two mutants (removing the conjunct from only one of a DELETE policy and its SELECT companion) are behaviourally equivalent, because the pair is mutually redundant; the registry's text comparison kills them |

### 16.7 S1.1a gate response (1 HIGH, 3 MEDIUM, 8 LOW, 4 NIT)

0047 is not on main, so every fix is in place in the migration. Tests are in `supabase/tests/matrix/25_partner_auth_spine.sql` (renamed from `24_`: S2a took the `24_` prefix) unless named.

| ID | Fix | Test |
|---|---|---|
| **H1** | Section 8c: every GUC-keyed `private_definer` policy (catalog-discovered, 102 + 16) carries `AND private.partner_binding_kind() IS DISTINCT FROM 'partner'`; its stored snapshot in `definer_policy_allowlist` and the fixture are regenerated; **check 15** (+ matrix twin, 4 must-fail cells) fails the build for any later open window | PA-4c (i): the gate's three probes with every setting planted, each with a no-binding control (1 row open, 0 closed); a catalog-driven pass over every covered (table, command) pair (planted = unset under a partner binding; at least 20 pairs differ with no binding); the setting list fails on an unknown setting |
| **M1** | The `IS NULL` legs of the four set-null SELECT companions (invite x2, credential, enrolment token) apply only with the window open (setting non-empty), plus the partner conjunct | `M1` cells: 0 rows with no binding, a user binding, a partner binding, and a partner binding with every window planted; a control that the open window still shows them |
| **M2** | `BEFORE INSERT` guards on `partner_session` (aal 1; nothing verified, revoked, proved or touched; the database clock; enrolment only on `register` and at most 15 min; absolute life at most the role ceiling, which `partner_session_policy` now returns) and on `partner_credential` (live, unused, the database clock) | `M2`: one must-fail cell per rule, the ceilings at both edges for staff, operator and admin, the gate's own insert, and controls |
| **M3** | cells for the previously untested authority code | `partner_sessions_revoke` for each subject kind (count, reason, others untouched, one audit row naming the subject's table, the caller's binding), argument validation and `EXECUTE`; a role change and a re-point of `user_id` (old and new uid); the same-transaction revoke before `partner_authorize` |
| **L1** | org revoke reaches active members only | `L1`: a member revoked in org 1 and active in org 2 keeps the org-2 session |
| **L2** | check 14: comments and strings lexed in one pass; (a0) refuses dollar quotes, quoted identifiers, backslashes, E-strings and nested comments; (a2) refuses `EXCEPTION WHEN`; (a3) the class must be a literal, `SESSION` / `PEEK` only for a listed function; (b) loses its name exemptions; (c) also catches the binding table and helpers and is a documented tripwire; (d) a `*_for_partner` function is executable by no one but the lane | `10_function_inventory.sql`: a must-fail cell per case (a0 x4, a2, a3 x3, b, c x2, d x2) with controls; the dynamic-name limit is pinned as a known limit |
| **L3** | PA-3b extended | INSERT sweep (RLS refuses under a partner binding; a planted table proves the detector) and every schema, not only `app` |
| **L4** | the delete_my_data matrix skip is an explicit list | `09_delete_my_data.sql`: the skipped set equals the four partner-auth tables |
| **L5** | class `PEEK`: no scope, no aal gate, never advances `last_seen_at` | `L5`: PEEK leaves `last_seen_at`, SESSION advances it; PEEK passes at aal 1 for an operator who is refused A0 |
| **L6** | `admin_user` UPDATE fires the authority trigger; TRUNCATE of `partner_member`, `admin_user` and `partner_scope` revokes every live session (statement triggers) | `L6`: an admin re-point; the three TRUNCATEs |
| **L7** | `authenticated` keeps SELECT on the nine masked columns of `app.offer` only | `L7`: no budget / eligibility column, no whole-table privilege, the masked views still answer |
| **L8** | the scope invariant requires READ COMMITTED (so does `partner_authorize`); both reliances are stated | `tools/db/test-partner-serialisation.sh` 3c (two concurrent scope inserts for one facility org: the second waits in `pg_locks` and is refused) and 5 (REPEATABLE READ refused, READ COMMITTED passes) |
| NIT guard comment | the comment now says what the code does (only `otp_proof_until` may be cleared or shortened) | none (comment) |
| NIT audit subject | the audit row names the subject's own table (`auth.users`, `app.partner_org`, `app.partner_credential`) | the M3 audit cells |
| NIT "anywhere" | stated in 16.5: object-scoped definers must not use both-NULL | check 14 (a3) pins the class literal; the rest is review |
| NIT A2 / A4 | idle, absolute expiry and demo are re-checked by `partner_authorize`, now proven there | cells: a session that goes idle, expires or becomes the demo account after the bind is refused by the next authorize |
| Departure 10 | the flagger role, its policies and the flag columns are removed from 0047 | role lists in checks 9 and 12, the fixtures and the cells updated |
| S2a merge | 0046 merged; it has no GUC-keyed policy (nothing to close; the catalog cells cover it automatically); its four binding readers reviewed and listed; matrix files renamed `25_*` | matrix, check 14 and the Deno suite on the merged tree |

### 16.8 Verification run after the gate (on the tree merged with S2a, 0046)

| Check | Result |
|---|---|
| `HARNESS_MODE=superuser tools/db/test.sh`, then `HARNESS_MODE=restricted tools/db/test.sh` (sequentially, a fresh cluster each) | each: 37 pgTAP files, **3503 tests, PASS** (`25_partner_auth_spine.sql` 388, `_edge` 34, `_edge_cleanup` 3, `10_function_inventory.sql` 134, `09_delete_my_data.sql` 34); the replay, money-path, sign-in and **partner serialisation** scripts pass (now incl. 2b, 3b, 3c and 5); the Deno integration suite 314 passed, 0 failed; the function-inventory check, the service-role lint and the H2 run pass |
| Unit, recorder, lint, typecheck | vitest 60 files / 1207 tests; recorder verify 1 test; service-role lint 401; `pnpm -r typecheck` clean |
| Migrations immutable | `--base 7a55b03`: 45 files byte-identical; `--base origin/main` (which now holds 0046): 46 files byte-identical |
| Mutation pass (scratch copy; each mutant on a fresh database; the pgTAP files, the CLI check, the parity test and the serialisation script run) | 53 mutants: the gate's survivors (idle and demo at authorize, the member trigger's `role` column and OLD uid, the three `partner_sessions_revoke` branches and its audit row, the scope invariant's advisory lock) and the new code (insert guards, the TRUNCATE and `admin_user` UPDATE triggers, PEEK, READ COMMITTED, the `app.offer` grant, section 8c, the invite `IS NULL` leg, the check 14 / 15 clauses) plus the first pass's 28; **all killed**. One mutant (PEEK taking the write-path lock) is equivalent in behaviour (`last_seen_at` is guarded separately) and was split into the lock-only variant (equivalent) and the advance variant (killed). One (section 8c closing WITH CHECK only) is killed by the migration's own fail-loud assertion |

## 17. As built: S1.1b

Slice S1.1b (the **database side of partner sign-in minting**: the SQL signature verifiers, the stateless challenge issuer, `partner_session_mint`, the alarm, and the S1.1a and S0 items carried into it). Branch `p5-s11b`, base `8baa81d` (S1.1a, 0047, merged). **One migration, `0048_partner_signin_mint.sql`**; `0001`-`0047` are byte-identical (`tools/db/check-migrations-immutable.sh --base origin/main`: 47 files). **Not built here:** `partner_credential_register_first` and the register and reauth challenge issuers, the invite and enrolment accept definers, the Edge caller (S1.2: `privileged.ts` has no partner transaction kind yet), the eviction of the oldest session beyond three live ones (4.1), and the purge definers for `partner_auth_challenge` and `partner_auth_alarm` (section 9). The migration's header is the reading guide; this section records what differs from the earlier text and what the next slice may rely on.

### 17.1 What was built

| Area | As built |
|---|---|
| Verifiers (`private`, pure, core PostgreSQL only: `numeric`, `bytea`, `sha256`; no extension) | `partner_sig_verify(alg, cose_key, message, signature)` (SECURITY DEFINER, `search_path = ''`, `EXECUTE` for `partner_session_issuer` only, **fail closed: `false`, never an error**) over `partner_cose_parse` (a strict COSE_Key parser), `partner_sig_es256_verify` (ECDSA P-256 / SHA-256 in Jacobian coordinates with Shamir's trick), `partner_sig_rs256_verify` (RSASSA-PKCS1-v1_5 / SHA-256, `e` = 65537) and 18 owner-only helpers. **Every strictness rule is a named predicate** (S0-L1, S0-N2): `partner_sig_p256_key_ok` (both coordinates below p and the point on the curve), `partner_sig_p256_rs_ok` (r and s in [1, n-1]), `partner_sig_p256_xr_ok` (x(R) = r, including the x(R) in [n, p) branch where r + n is compared), `partner_sig_der_rs` (strict DER: one-byte lengths, exact, positive, minimal, no trailing byte), `partner_sig_rsa_key_ok` (full-length odd modulus of 2048 to 4096 bits, `e` exactly `01 00 01`), `partner_sig_rsa_sig_ok` (exactly as long as the modulus, below it), `partner_cbor_head` (shortest-form heads only, definite lengths). The RSA encoded message is built **fresh and compared as an integer**, never parsed (the Bleichenbacher shape). COSE: the map holds **exactly** the five (EC2 P-256) or four (RSA) pairs, each key once, integer keys, byte strings of the stated lengths, no trailing byte |
| Challenge | `partner_challenge_issue_sign_in()` (owner `private_definer`, `EXECUTE` for `edge_partner_minter` only): 32 random bytes (`gen_random_bytes`), an expiry **exactly 120 s** ahead, and the MAC; it takes **no purpose and no binding argument**, writes **no row**, and refuses inside any bound transaction. The MAC is HMAC-SHA256 under Vault key `partner_challenge_key` over `"golfraven/partner-challenge/v1" ‖ 0x00 ‖ purpose(1) ‖ exp(8, big-endian) ‖ nonce(32) ‖ binding(16, zeros for sign-in)`. The key is read in **one** place, `partner_challenge_core` (`EXECUTE` for nobody), which also does the comparison as `HMAC(K, presented) = HMAC(K, expected)`; `partner_challenge_verify` (issuer only) is what the mint may ask of it. The shim seeds the key with a shim-only constant; the HMAC vectors in the tests were computed **outside the database** (Python `hmac`) |
| The mint | `partner_session_mint(token_hash, credential_id, nonce, exp, mac, authenticator_data, client_data_json, signature)` returns `(status, session_id, aal, expires_at)`; owned by `partner_session_issuer`, `EXECUTE` for `edge_partner_minter` only (the minter's whole `EXECUTE` set is this and the issuer: 25_ PA-1 and 26_ PA-8). **Order, each step a status and never a RAISE** (so what must commit commits): (1) HMAC / purpose / expiry; (2) the credential **read from the table** (the key is never an argument; unknown and revoked are one answer); (3) **S0-L5: at most 60 successful sign-ins per credential per hour, before any verification**, counted **under a `FOR NO KEY UPDATE` lock on the credential row** taken immediately before the count (17.10, M-1); (4) the structural checks against `partner_rp_config` (`type`, `crossOrigin` / `topOrigin`, **exact origin**, challenge; `rpIdHash`, UP, UV, the counter); (5) the SQL signature check, last of the checks; (6) the used nonce is inserted (the primary key is the single use); (7) the counter by compare-and-set; (8) the session, with the `mint_*` evidence. Statuses: `ok`, `bad_challenge`, `expired`, `unknown_credential`, `rate_limited`, `bad_client_data`, `bad_client_type`, `cross_origin`, `bad_origin`, `challenge_mismatch`, `bad_authenticator_data`, `bad_rp_id_hash`, `user_not_present`, `user_not_verified`, `signature_invalid` (alarm), `replayed`, `counter_regression` (alarm). **Raises:** `22023` (malformed arguments), `42501` (inside a bound transaction), `55000` (no relying-party row or no Vault key: a deploy fault). A signature that fails here after the Edge verified it is an **alarm**; it does not burn the challenge |
| Alarm | `app.partner_auth_alarm` (FORCE RLS; no foreign key and no user id; `UNIQUE (kind, credential_id, minute_bucket)` so a flood writes one row a minute); `partner_mint_alarm_write` (issuer only) writes the row and, when it is new, one `audit_log` row with no actor. Both commit with the refusal (a status, not a RAISE: the 0020 lesson). Its two `private_definer` policies are keyed on the transaction's binding (`(SELECT private.partner_binding_kind()) IS NULL`), never on a GUC |
| Roles and registries | `partner_session_issuer` gains `SELECT (credential_id, mint_kind)` on `partner_session` (the limit's count; the session `INSERT` was 0047's), `SELECT (public_key, alg, sign_count)` and `UPDATE (sign_count, last_used_at)` on `partner_credential` (the key a session is verified against cannot be rewritten by the mint's owner), `SELECT (rp_id, origin)` on `partner_rp_config`, `INSERT` and `SELECT (nonce_hash)` on `partner_auth_challenge`, each behind a registered `psi_*` policy; **27 `function_inventory` rows** (`expected_edge_partner_minter` true for exactly two), the `definer_policy_allowlist` rows with their derived expressions, 16 `partner_owner_privilege` rows, and the two mint definers in the kind-reader fixture |
| Carried S1.1a items | see 17.3 |
| Carried S0 items | see 17.2 |

### 17.2 S0 gate items, carried

| ID | Fix | Test |
|---|---|---|
| **S0-L1** | The spike's verifiers ported as named predicates (17.1); the vendored Wycheproof corpora (Apache-2.0, `supabase/tests/fixtures/partner-sig/wycheproof/`, sha256 `182db4f3...` and `94a917b0...`) plus hand-built vectors for every branch Wycheproof does not isolate (`tools/db/partner-sig/gen-handbuilt-vectors.py`, pure Python, no third-party package): x(R) >= n built from a chosen R (no discrete log), an **off-curve key** built by a chord construction, `s + n`, `r + n`, non-reduced r, negative and non-minimal DER, RSA `s + n`, RSA length plus and minus one, a modulus just above 2^2047, the degenerate keys G and -G | `26_partner_sig_verifiers.sql` (191 cells): **all 484 ES256 and 259 RSA Wycheproof vectors run**; every `valid` ES256 vector verifies (174) and every `invalid` one (310) is refused; RSA by the policy stated in the file (e = 65537 only; the one `acceptable` vector is refused); 47 hand-built vectors (13 controls); a boundary cell on **each side** of every predicate; the COSE variants one field at a time |
| **S0-L2** | The wrapper's key-shape tests: a P-384 key labelled -7, 31- and 33-byte coordinates, an RSA modulus with a leading 0x00, and the rest of `assertKeyAllowed` | `partner-webauthn.deno.test.ts` (commit `6cb10bd` of this slice); mutants W1 to W9 in 17.6 |
| **S0-L3** | `tools/service-role-lint` rule `webauthn-library-import-site`: only `supabase/functions/_shared/partner/webauthn.ts` may import `@simplewebauthn/*` (static, re-export, dynamic `import()` and `require()`; alias targets via the import map; case-insensitive; the whole scope; `privileged.ts`, exempt from the general rules, is not exempt from this one; **both exemptions are anchored to the functions root**, 17.10 L-3) | three fixtures and the `S0-L3` cells in `lint.test.ts` and `index.test.ts`; lint suite 423 |
| **S0-L4** | `sanitizeTransports`: the `AuthenticatorTransport` enum only, deduplicated, at most 5 stored, at most 32 examined, anything not an array dropped | `partner-webauthn.deno.test.ts` |
| **S0-L5** | Section 8: **60 successful sign-ins per credential per hour, checked before verification**; counted from `partner_session` (`mint_kind = 'sign_in'`, `created_at` within the hour), so a revoked session still counts and nothing but time resets it | `26_partner_signin_mint.sql` section 6: 59 reach the signature check, the 60th is accepted, the 61st is `rate_limited` **before** a bad signature is looked at (no alarm, no nonce, no counter move); 61 minutes old does not count, **60.5 minutes old does not count** (kills a 61-minute window), 59.5 minutes old does; **8 concurrent mints at 58 sessions give exactly 60** (`test-partner-serialisation.sh` 6f); a `register` session does not count; the count is per credential, not per person (two cells) |
| **S0-N1** | 4.6 now says the origin may be a subdomain of the RP ID as a *configured value* and is matched **exactly** by the wrapper and by the mint | `bad_origin` cells: a subdomain, a trailing slash, `http`, another case, a port, a longer host |
| **S0-N2** | 15.2 now records that the spike's untested branches were found by mutation, and that "0 wrong verdicts" is not evidence of strictness | the mutation pass, 17.6 |

### 17.3 S1.1a items, carried

| ID | Fix | Test |
|---|---|---|
| **LOW 1** | check 14 gains clause **(e)**: the `EXECUTE` set of `edge_partner` is exactly `bind_partner_session`, `partner_binding`, `partner_binding_kind`, `hit_partner_rate_limit` and the `*_for_partner` family (functions **and procedures**; `PUBLIC` counts). **The four named functions are compared by identity (`schema.name(argument types)`), not by name** (17.10, L-1) | `10_function_inventory.sql`: clean schema; a helper granted; a helper left with `PUBLIC`; a procedure; the seam's own name; the allowed names as controls |
| **LOW 2** | **check 15 requires the conjunct as the top-level trailing `AND`** of every `USING` and `WITH CHECK` that reads a setting (the direct call or the InitPlan form), not text that merely contains it; and the **PA-4c (i) sweep seeds a row for every (table, command) pair** and asserts a difference with no binding for **every** pair, not "at least 20" | check 15: ten must-fail forms (open, WITH CHECK only, an OR-form, the conjunct in a branch, in the middle, first, inside `EXISTS`, another kind, nested inside an OR inside the AND, an UPDATE closed in USING only) and five controls (direct, InitPlan, three-term AND, a literal holding parentheses, an UPDATE closed in both clauses). Sweep, 17.4 |
| **LOW 3** | recorded in 16.5: section 8c also closes `pd_offline_code_step_*` and the `app.guard.*` read windows under a partner binding, so S3 and S5 need binding-keyed policies of their own | none (a seam note) |
| **NIT** | **Not adopted, with the measurement that decided it.** `(SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner'` makes the call an InitPlan evaluated once per statement, and the first version of 0048 converted all 118 existing conjuncts with `ALTER POLICY`. In the full harness the 0040 backlog test then ran `private.purge_signin_email_proofs()` (`DELETE ... WHERE id IN (SELECT ... LIMIT 5000)` under RLS) against 5,003 freshly inserted rows for **26.9 s instead of about 30 ms** (the harness's 10 s statement timeout cancelled it). `auto_explain` showed a Nested Loop Semi Join that re-runs the `LIMIT` subquery per outer row, with the table estimated at one row; my reading, not isolated, is that the cheaper filter tipped the cost comparison toward it. The tree before this slice passed the same suite. A plan-sensitive change to 118 policies for a performance hint is not worth that, so the existing policies keep the direct call. Check 15 accepts both forms (a control cell), and the two new alarm-table policies, on a table of at most one row per credential per minute, use the InitPlan form. If it is wanted later, rewrite the purge definers to materialise their batch first and re-run the whole Deno suite. **Tracked as a follow-up** (17.10, L-4; and in `p3-money-path-requirements.md`); **taken in 0050 once the purges no longer depended on the plan, with the new measurement (see "As built: DB hygiene")** | check 15's two tails; `definer_policy_exprs.txt` is the S1.1a text plus the six new rows |

### 17.4 The PA-4c (i) sweep, as built

`pg_temp.sweep_seed` runs as the harness role before the catalog statements and inside a savepoint that is rolled back. For every table a GUC-keyed `private_definer` policy covers (39 tables; 38 rows are inserted, one table already holds A's row) it inserts one row keyed to player A on **every column a window policy compares with a setting** (the column and setting are read from the policy text; the value is the one `plant_value` plants), after stripping, **for that savepoint only**, the table's foreign key, check and exclusion constraints, its non-key `NOT NULL`s and its user triggers (the question is what the policy set reaches, not whether the table would accept the row), and after giving the harness role back the DML privileges an earlier committed file may have revoked (`23_offline_totp_seed_edge.sql` revokes `INSERT` on `app.offline_code_step` for good; the restricted harness found it). The statements are `SELECT count`, `DELETE`, a no-op `UPDATE` and, for the three tables with an `INSERT` window, an `INSERT ... ON CONFLICT DO NOTHING`. Results:

- **Under a partner binding** planted equals unplanted for every pair (the cell is now non-vacuous: a mutant that removed the conjunct from `checkin_token`'s delete policy, an **empty** table that the old sweep read as 0 -> 0, is killed).
- **With no binding** planted differs for every pair **except exactly three**, asserted by name: `admin_user:r`, `app_review_demo_account:r` and `partner_member:r`, whose rows a second, unconditional `private_definer` read policy (`pd_read_admin_user`, `pd_read_demo_account`, `pd_read_partner_member`, `USING (true)`) already returns with nothing planted. For those the window adds nothing to observe, and a pair that joins that list or leaves it fails the cell.

### 17.5 Departures from sections 4 to 6, and why

1. **Statuses, not exceptions, for every client refusal** (4.4 allowed either): the transaction has to commit the alarm, and a RAISE rolls it back. Only a malformed argument, a bound transaction and a missing relying-party row raise, and none of those has written anything.
2. **A failed signature does not burn the challenge** (5.1): the nonce row is written after verification, so a forged attempt cannot spend a legitimate user's challenge. The cost is that the same challenge may be presented again inside its 120 s; each presentation needs a real signature and an alarm is written at most once a minute.
3. **The comparison of a presented MAC is `HMAC(K, presented) = HMAC(K, expected)`** (5.1 said constant-time compare): it never depends on a byte-by-byte equality of a secret-derived value, and needs no extension.
4. **The key is read from the table, never an argument**, and the counter is read **from the signed authenticator data** (there is no argument to differ from it).
5. **The COSE parser is stricter than the wrapper.** It refuses a key that carries any parameter beyond the exact set (WebAuthn: the credential public key "MUST NOT contain any other OPTIONAL parameters"). The wrapper (`assertKeyAllowed`) reads only the fields it needs, so **a credential with extra COSE parameters would pass registration and then never sign in.** No conforming authenticator emits them, but the registration slice must either make the wrapper refuse them or store a re-encoded canonical key. **Ruling (S1.1b gate): accepted as a seam, with a BLOCKING S1.5 condition: `partner_credential_register_first` must call `partner_cose_parse` on the key it is about to store, so a credential with extra parameters is refused at registration.** S1.5 does not pass its own gate without it.
6. **The Deno integration test speaks to the database directly** (`SET LOCAL ROLE edge_partner_minter` as `edge_gateway`): `privileged.ts` has no partner transaction kind until S1.2. It is the one suite that signs with a signer the database did not write (Web Crypto, 17.7).
7. **The 60-per-hour limit is counted from `partner_session`**, not from a counter table, so it adds no table and cannot drift from the sessions it counts. Eviction beyond three live sessions (4.1) is not built. **Ruling (S1.1b gate): eviction (S1.5) must REVOKE sessions and never DELETE them**, because the limit is counted from `partner_session` rows and a DELETE would reset the 60-per-hour count.
8. **`partner_auth_alarm` has no purge definer yet** (nor does `partner_auth_challenge`): section 9 lists both; the alarm table grows by at most one row per (kind, credential, minute).
9. **The 0040 retention backlog test (`retention-purge.deno.test.ts`, an earlier slice's file) now `ANALYZE`s the four tables it bulk-loads.** Found by the full harness, not by any single suite: once this slice's longer concurrency steps moved when autovacuum ran, a vacuum that could not truncate `private.signin_email_proof` (a concurrent session held the xmin horizon) left `pg_class` saying 148 pages and 1 tuple; the planner then estimated the test's 5,003 new rows as one row and ran `purge_signin_email_proofs()` as an O(n^2) nested loop past the 10 s statement timeout. The base tree has the same latent dependence (it passes while autovacuum happens to leave that table truncated: with autovacuum off the base passes and this tree fails; with the `ANALYZE` both pass, checked on a clone of the failing harness template). The fix is in the test, not in the purge: the definer is 0040's and a production table that has been loaded for a while has been analyzed by autovacuum.

### 17.6 Mutation pass

Every mutant was applied **only to a scratch copy** (`/tmp`, a fresh database each, the affected files run), and a grep of the worktree for the marker comment every mutant carries was empty before each commit.

| Target | Mutants | Result |
|---|---|---|
| The 0048 verifiers, COSE parser, challenge HMAC and mint | 159: every predicate removed or shifted at its boundary (each coordinate and each bound separately), each DER rule, each add-routine branch, the Shamir selects and loop bound, each RSA rule, each CBOR and COSE rule, the HMAC label, separator, purpose byte, expiry width, nonce order, binding and comparison, the 120 s expiry, **every step of the mint removed or weakened, the 60 and the 59, the window (2 hours, 30 minutes), per person instead of per credential, and every permutation of the order of the mint's steps that matters (10)** | **149 killed, 10 behaviourally equivalent** (below). The first pass left 25 survivors; each was closed with a new cell (trailing bytes inside the DER sequence; the keys G and -G; coordinate lengths on the ES256 entry; five COSE laxities; a repeated key; the exact 120 s expiry; the per-credential limit; a NULL credential on the alarm writer; **a credential revoked while a mint waits on its row** (two-connection case 6e); the order cells "limit before structure" and "structure before signature") or shown equivalent |
| Check 14 (e) and check 15 | 16 mutations, each applied to **both** copies (the `.mjs` and matrix 10's twin): 32 | **29 killed** (the matrix twin by its must-fail cells, the `.mjs` by the parity test and, where it is stricter, by the real CLI run); **3 equivalent** (below). Three survived the first pass (a procedure, the seam's own name, a literal parenthesis) and were closed |
| `service-role-lint` rule S0-L3 | 11 | 11 killed (3 needed new cells: a relative wrapper path, case, the whole scope) |
| The wrapper (S0-L2, S0-L4) | 17 | 16 killed, 1 equivalent (`typeof t === "string"` before an `includes` over strings) |

**The behaviourally equivalent mutants, and why** (an equivalent mutant is not killable by any input; each of these is a second line of defence behind another check):

- `der_total_short`, `der_rl_max`, `der_sl_max` (the redundant `total >= 128` and a 34-byte integer): the length cap of 72 bytes and the value check `r, s < n` already refuse every such signature.
- `es_infinity` (the point at infinity): the infinity the loop can produce is `(1, 1, 0)`, and `xr_ok` compares `r * 0` with `1`: false either way.
- `cose_map` (the pair count 4 or 5), `cose_len` (the 1024-byte cap), `cose_seen_ec`, `cose_bstr_fit`, `cose_rsa_n_int`: each is implied by the other checks that remain (distinct keys, the required fields being non-null, the final `pos = len`, the modulus bound).
- `mint_args` (the nonce length): the HMAC core raises the same `22023` for it.
- Check 15's `lo`, `hi` and `min` depth conditions (3): the exact-tail match already implies a root-level `AND` for any text `pg_get_expr` produces (30 shapes tried: `OR`, `NOT`, `CASE`, `coalesce`, `IS TRUE`, an array, `EXISTS`, nested `AND`, string literals holding parentheses; none distinguishes the mutant). The depth profile stays as a second line.

**Check 15 is deliberately conservative about one form**: `A AND (B AND conjunct)` is flagged (the conjunct must be the last term of **one flat** `AND`).

### 17.7 Verification run for this slice

| Check | Command | Result |
|---|---|---|
| Whole database suite, both harness modes (a fresh throwaway cluster each, under `/tmp`, deleted afterwards), **sequentially** | `HARNESS_MODE=superuser tools/db/test.sh`, then `HARNESS_MODE=restricted tools/db/test.sh` | each: 39 pgTAP files, **3947 tests, PASS** at the first gate; 3959 after the gate round, 17.10 (S1.1a ended at 37 files and 3503); the replay, money-path, sign-in-proof and **partner serialisation** scripts pass (now 6a to 6f); the Deno integration suite **324 passed, 0 failed** (314 + the 10 of `partner-signin-mint`); the function-inventory check, the service-role lint and both H2 runs pass; exit 0 |
| New and changed pgTAP | `26_partner_sig_verifiers.sql` (191), `26_partner_signin_mint.sql` (235 after the gate round, 231 before), `25_partner_auth_spine.sql` (393; 390 before the gate round, 388 in S1.1a), `10_function_inventory.sql` (159; 154 before the gate round, 134 in S1.1a) | PASS in both modes |
| Two-connection proofs | `tools/db/test-partner-serialisation.sh` cases 6a (12 concurrent mints of one challenge: 1 `ok`, 11 `replayed`), 6b and 6c (the counter race, both orders), 6d (the alarm that commits), 6e (a credential revoked while a mint waits on its row), 6f (8 concurrent mints at 58 sessions: exactly 60, gate M-1) | PASS in both modes; each waiting session is seen in `pg_locks` |
| Unit suite | `pnpm --filter @golfraven/rules exec vitest run --config ../../supabase/tests/vitest.config.ts` | 61 files, **1210 tests**, PASS (includes the check-parity test and the Wycheproof pin test) |
| Pure Deno suite, network denied | `deno test --config supabase/functions/deno.json --lock=supabase/tests/deno.lock --frozen --cached-only --deny-net supabase/tests/deno-unit/` | **52 passed**, 0 failed |
| Service-role lint | `pnpm --filter @golfraven/service-role-lint test`; `node tools/service-role-lint/dist/cli.js supabase/functions` | **423 passed** (419 before the gate round); clean |
| Mobile recorder, typecheck, `deno check` | `record-edge-contract.vitest.config.ts`; `pnpm -r typecheck` after `GOLFRAVEN_DEMO=1 pnpm -r build`; `deno check` of the changed Deno files | 1 passed; clean; exit 0 |
| Migrations immutable | `tools/db/check-migrations-immutable.sh --base origin/main` | OK, **47** files byte-identical (`origin/main` is `8baa81d`) |
| Secrets and personal data | gitleaks 8.18.4 over `8baa81d..HEAD`; a grep of every added line for emails, phone numbers, home-directory paths, keys and tokens, and of the file list for artifacts | no leaks; nothing found; nothing committed that is a test artifact |
| Mutation pass | 17.6 | 159 + 32 + 11 + 17 mutants; every one killed or shown equivalent |

**What the full harness found that no single suite did** (each fixed, none waved through): (1) the PA-4c sweep's seeding failed in `restricted` mode because an earlier committed file revokes `INSERT` on `app.offline_code_step` from the harness role (17.4); (2) two cells that count alarm rows could straddle a clock-minute boundary and failed in one of the ten harness runs (now they wait the boundary out); (3) the Deno mint test failed in `restricted` mode: the commit-time foreign-key check of `partner_session.credential_id` is a `SELECT ... FOR KEY SHARE` run with the **owner's** privileges, and the owner held no privilege on `partner_credential` in that run. **Correction (gate N-3): that was not 0047.** 0047 does not revoke the owner's privileges (after a restricted migration the owner holds `arwdDxtm`); the previous `REVOKE ALL ... FROM CURRENT_USER` in `tools/db/test-partner-serialisation.sh`'s cleanup stripped them, and the cleanup now never revokes from a role that owns the table; (4) the retention backlog test and stale statistics (17.5, item 9); (5) the InitPlan conversion (17.3, NIT).

**Verifier timing in the harness** (31 warm calls after one cold, this container, PostgreSQL 17, one backend): ES256 median 16.6 ms and worst 19.0 ms (superuser run) or 18.0 and 22.1 ms (restricted run); RS256 median 2.3 and worst 3.3 ms, or 2.4 and 3.5 ms; a whole mint **including building the assertion in SQL** (12 calls) median 34.9 and worst 41.6 ms, or 38.1 and 50.0 ms. Across the ten harness runs of this slice: ES256 median 15.7 to 18.0 ms, worst 17.0 to 31.5 ms; RS256 median 2.2 to 2.4 ms, worst 2.5 to 9.1 ms; mint median 32.9 to 39.1 ms, worst 36.4 to 50.0 ms. The S0 criterion was 200 ms (S0 measured 35.5 ms and 3.7 ms worst warm). **The hosted-database repeat (R7) is still a deploy-time step.**

### 17.8 Seams left for later slices

- **Registration** (S1.5), **BLOCKING:** `register_first` must call `partner_cose_parse`, so a COSE key with extra parameters is refused at registration (17.5, item 5), or such a credential registers and never signs in. `register_first` and the register and reauth issuers reuse `partner_challenge_core` (purposes 2 and 3 are in the encoding and in the vectors) and the same nonce table.
- **Session eviction** beyond three live sessions (4.1) is not built; the mint inserts and does not count. **When it is built it must revoke and never DELETE** (a DELETE resets the 60/h count).
- **The Edge must COMMIT on every status** (S1.2): `rate_limited`, `signature_invalid`, `counter_regression`, `replayed` and the rest all return a status row rather than raising precisely so that the alarm rows and the burned nonce commit. An Edge that rolls back on any status other than `ok` silently drops the alarm and un-burns the nonce.
- **Bound on failed verifications:** the only bound on failed verifications is section 8's "5 failures, then a 15-minute cooldown" (S1.2 implemented it, 18.2; its burst limit is stated in 18.9). The mint's own limit (60/h) counts successful sign-ins and the alarm writes one row a minute; neither bounds failed attempts.
- **Purge definers** for `partner_auth_challenge` (used nonces older than the challenge window) and `partner_auth_alarm` (section 9): to be owned by `private_definer` and registered; both tables are classified in `pii_retention_policy`.
- **The Edge caller** (S1.2): a partner transaction kind in `privileged.ts` that opens `SET LOCAL ROLE edge_partner_minter`, issues the challenge, verifies in the wrapper **first**, then calls the mint (the SQL check is the second line and its failure is an alarm), maps `55000` to a bare 503, and never returns the raw status text to a client.
- **Operator step at deploy:** insert the `partner_rp_config` row (RP ID and exact origin) and provision the Vault key `partner_challenge_key` (at least 32 bytes; generate it inside the database, `select vault.create_secret(encode(gen_random_bytes(32), 'hex'), 'partner_challenge_key')`, SQL editor only, never `psql -c`: `docs/security/edge-role-design.md` item 8). The mint refuses (`55000`) without either.
- **Every new `private_definer` policy** is still checked by check 15 (top-level trailing conjunct), by the allow-list registry and by the sweep above; a new window's setting must be added to `plant_settings` and `plant_value` or the cell fails on an unknown setting.

### 17.9 Egress and environment notes

- A lookup of the upstream commit of the Wycheproof files through `api.github.com` was **denied** ("GitHub access to this repository is not enabled for this session"); the upstream commit is therefore not recorded and the vendored files are pinned by sha256 (`NOTICE.md`). The files were fetched from `raw.githubusercontent.com`, which was allowed.
- Copying the proxy CA bundle to a world-readable path, to let the `postgres` OS user run Deno, was **denied**; it was not routed around: the Deno suites were run as the invoking user against the scratch cluster. `tools/db/test.sh` runs its Deno step the way it always has (it unsets an unreadable certificate variable itself).
- The gitleaks 8.18.4 release binary was downloaded from the project's release page and **verified against the release checksums file** before use.

### 17.10 Gate round 1: M-1, L-1 to L-4, N-1 to N-4

The S1.1b gate failed the slice on one MEDIUM and listed four LOWs and four NITs. All are addressed in new commits on `p5-s11b` (0048 is not on `main`, so it is edited in place).

| Finding | Fix | Test |
|---|---|---|
| **M-1 (MEDIUM)** the 60/h limit was exceeded by concurrent mints: the count was unlocked and the first per-credential serialisation was the counter's compare-and-set, which does not serialise at counter 0 (gate proof: 58 sessions + 8 concurrent mints = 66 `ok`) | `PERFORM 1 FROM app.partner_credential c WHERE c.id = v_cred.id FOR NO KEY UPDATE;` immediately before the count: count and insert are one critical section per credential. `FOR NO KEY UPDATE` (the `UPDATE`'s own mode) so it does not block the `FOR KEY SHARE` of the session foreign key | `test-partner-serialisation.sh` case **6f**: 58 sessions, 8 concurrent mints with distinct valid challenges and counter 0 give exactly 2 `ok` and 6 `rate_limited` (60 sessions), with a waiter seen in `pg_locks`. Mutants: lock removed (ok=8), `FOR SHARE`, `FOR KEY SHARE`, wrong row: all killed |
| **L-1** check 14 (e) compared the four named functions by name only, so an owned and granted overload passed | compares `schema.name(argument types)` identities for the four, and keeps the name pattern for the `*_for_partner` family; the same text in the matrix 10 twin | `10_function_inventory.sql`: must-fail overloads of `bind_partner_session`, `partner_binding_kind` and `hit_partner_rate_limit`, and the real signature as a control; parity test. Name-only mutant killed in both copies |
| **L-2** check 15 missed a GUC read behind a wrapper | a policy that depends (`pg_depend`, one level deep, the HIGH-1 rule) on a function whose body reads `current_setting` is treated as GUC-keyed and must carry the partner conjunct; the PA-4c sweep covers it too (`policy_is_window`, wrapper settings in `unplanted_settings`, the wrapper's key column in the seed) | `10_function_inventory.sql`: the wrapper policy without the conjunct must fail, with the conjunct passes; `25_partner_auth_spine.sql`: three wrapper cells. Mutants (clause removed in each of the three places): killed |
| **L-3** `webauthn-library-import-site` was evaded by a nested path | the wrapper and the `privileged.ts` exemptions are anchored to `functionsRoot` (exact segments relative to it); with no root, a tail match is refused when an earlier `supabase/functions` pair exists. The `privileged.ts` shape was the same and was a small change, so it is fixed too | `lint.test.ts` (nested wrapper, with and without a root; the real wrapper under a root; outside the root; nested `privileged.ts`) and `index.test.ts` (nested file through `lintDirectory`): 423 |
| **L-4** the 0040 purge plan is fragile under stale statistics | **closed by migration 0050** (see "As built: DB hygiene" at the end of this document; the `MATERIALIZED` shape proposed here was measured and rejected for an array batch). Originally: not fixed in this slice, by instruction. Tracked follow-up: materialise the batch (`WITH b AS MATERIALIZED (...) DELETE ... USING b`), then drop the test-side `ANALYZE` and re-evaluate the InitPlan NIT (17.3). Recorded in `p3-money-path-requirements.md` too | none (a follow-up) |
| **N-1** the Wycheproof sha256 pins were prose | `supabase/tests/unit/wycheproof-vendored-pin.test.ts` re-hashes both files against `NOTICE.md` and requires the pinned set to equal the vendored set | the test (3 cells); a one-byte change to a corpus kills it |
| **N-2** the limit-window and alarm-bucket cells did not kill a 61-minute window or a per-hour dedupe | `26_partner_signin_mint.sql`: 60 sessions aged 60.5 minutes are not counted; a new minute writes a new alarm row (a row at the previous minute bucket plus a fresh alarm give two) | two mutants (61-minute window, hour bucket): killed |
| **N-3** 17.7 item (3) and a test comment blamed 0047 for the owner's missing privileges | corrected here and in `partner-signin-mint.deno.test.ts`; the serialisation script's cleanup no longer revokes from a table's owner | the next harness run |
| **N-4** two S1.2 seams unrecorded | 17.8: the Edge must COMMIT on every status; section 8's per-credential failure cooldown is the only bound on failed verifications | none (seam notes) |
| Rulings | COSE strictness accepted as a seam with a blocking S1.5 condition (17.5, item 5; 17.8); eviction must revoke, never DELETE (17.5, item 7; 17.8) | none (S1.5 conditions) |

Mutation pass for this round (scratch copies only, a fresh database each; 16 mutants, **all killed**): the lock removed or weakened to `FOR SHARE` / `FOR KEY SHARE` or aimed at no row (4); the 61-minute window and the hour-wide alarm bucket (2); check 14 (e) by name only in the `.mjs` and in the twin (2); check 15's wrapper clause removed from the `.mjs`, the twin and the sweep, and the sweep's wrapper settings scan removed (4); the lint's root anchor disabled, the nested-pair refusal removed and the length test relaxed (3); a vendored corpus altered (1).

**Verification of the whole tree after this round:** both harness modes, run one after the other (`HARNESS_MODE=superuser`, then `HARNESS_MODE=restricted`): each 39 pgTAP files, **3959 tests, PASS** (3947 before this round), serialisation cases 6a to 6f pass, Deno integration **324 passed, 0 failed**, function-inventory check OK, service-role lint clean, exit 0. Unit suite 61 files, **1210 tests** (the three new Wycheproof pin cells); pure Deno suite 52 passed; service-role-lint **423 passed** and the CLI clean; recorder 1 passed; `GOLFRAVEN_DEMO=1 pnpm -r build` and `pnpm -r typecheck` exit 0; `deno check` of the changed Deno test clean; `check-migrations-immutable.sh --base origin/main` OK, 47 files; gitleaks 8.18.4 (release checksum verified) over `8baa81d..HEAD`, 22 commits, no leaks; the personal-data grep over every added line and the marker grep over the worktree empty.

**Follow-up closed in S1.2 (check 15, the PA-4c sweep and the older wrapper rule): the window is recognised from the function's deparsed definition.** The three places that decided "does this policy read a setting through a function it calls" (check 15 in `verify-function-inventory.mjs` and its matrix 10 twin; the sweep's `policy_is_window`, `unplanted_settings` and wrapper-key scan in matrix 25; the HIGH-1 wrapper rule in the `.mjs`) matched `pg_proc.prosrc ILIKE '%current_setting(%'`. That text is the body **as written**, so it missed three shapes: a `BEGIN ATOMIC` body (its `prosrc` is empty: the body lives in `prosqlbody`), a body that writes `current_setting (` with a space, and a body that reads the setting through the `pg_settings` view. All three now use `pg_get_functiondef(fp.oid)` (guarded by `prokind IN ('f', 'p')`, so an aggregate never reaches it) with `~* '\mcurrent_setting\s*\('`, and `pg_settings` is added to the policy-text pattern (`\mpg_settings\M`) and to the function-text pattern. Must-fail fixtures in `10_function_inventory.sql`: a `BEGIN ATOMIC` wrapper (W3), `current_setting (` (W4), a policy whose own text reads `pg_settings`, and a wrapper that reads `pg_settings`, each failing without the partner conjunct and the `BEGIN ATOMIC` one passing with it. Run against the old `prosrc` logic, the four must-fail cells (160, 162, 163 and 164) go red, so the fixtures do test the change.

**Stated limits (a tripwire, not a proof; recorded so nobody reads the check as more than it is):**
- **One level of wrapper.** A policy that calls `f()` which calls `g()` which reads the setting is not seen: `pg_depend` links the policy to `f` only. A two-level wrapper is a review item, not a check; the S1.1b and S1.2 policies have none.
- **Dynamic SQL.** A function that assembles the name at run time (`EXECUTE 'select current_' || 'setting(...)'`, or a `format()` that builds the call) shows neither `current_setting` nor `pg_settings` in its definition. Closing it would mean forbidding dynamic SQL in every function a `private_definer` policy depends on; it is not done.
- **Another route to the same value.** `pg_settings` and `current_setting` are the two routes the checks name. A third (`pg_show_all_settings()`, `SHOW` through a PL/pgSQL `EXECUTE`) is not matched. Each new reader of a settable value in a policy path is read by a human at review; the sweep's planted-GUC cells (matrix 25) are the behavioural backstop, because they plant the setting and count the rows reached.

## 18. As built: S1.2

### 18.1 What was built

The partner (staff) auth **Edge core**: the first Edge Function a staff member's browser talks to.

- **`0049_partner_session_edge_core.sql`** (all `CREATE`; 0001 to 0048 untouched): `app.partner_sign_in_failure` (the section 8 counter); the minter lane's three definers (`partner_rp_config_read`, `partner_credential_lookup`, `partner_sign_in_failure_record`, owner `partner_session_issuer`, EXECUTE for `edge_partner_minter` only); the reauth stack (`partner_reauth_credential_read`, `partner_reauth_check`, owner `partner_session_issuer`; `partner_reauth_apply` and `partner_reauth_clear`, owner `partner_reauth_verifier`); `hit_partner_rate_limit`; and the `_for_partner` family (`partner_whoami`, `partner_session_revoke`, `partner_session_lock`, `partner_session_reauth_options`, `partner_session_reauth_credential`, `partner_session_reauth`, owner `private_definer`, EXECUTE for `edge_partner` only, each opening with `partner_authorize` and a literal class). 14 functions, all inventoried, all check-14 compliant.
- **`privileged.ts`**: `openScopedTx` kinds `partner` (`SET LOCAL ROLE edge_partner`, `bind_partner_session(sha256(token))`, the 4.2 post-bind assertion) and `partner_mint` (`SET LOCAL ROLE edge_partner_minter`); `withPartnerMint`, `withPartnerSession`, `hitRateLimitForPartner`, `partnerDb`, `loadPartnerCorsOrigin`; `getActorFromRequest` refuses `gr_ps_` and `gr_inv_` bearers (any case) before the environment is read, so such a token is never sent to GoTrue. `privileged.ts` is still the only module that touches the database.
- **`_shared/partner/`**: `cors.ts`, `http.ts` (`readPartnerJsonBody`), `ports.ts`, `token.ts`, `session-shape.ts`, `session-handler.ts`, `webauthn-port.ts`; **`functions/partner-session/index.ts`** (`verify_jwt = false`). Routes: `POST options`, `POST verify`, `GET session`, `POST sign-out`, `POST lock`, `POST reauth/options`, `POST reauth`.
- **service-role-lint**: `edge_partner` is an ordinary lane role; `edge_partner_minter` joins `edge_signin_minter` as a minter role; the `partner_mint` kind may be named only by `openScopedTx` and `withPartnerMint` (PA-13).
- **CI**: `partner-session/index.ts` in the three function lists of `ci.yml`, and the deno-unit cache line naming the new pure Deno test, both pinned by `ci-function-lists.test.ts`.

### 18.2 Brief item, fix, test

| ID | Fix | Test |
|---|---|---|
| **PA-10** (CORS, media type) | one allowed origin, `GR_PARTNER_ORIGIN` (18.3, D2); `OPTIONS` answered before any port is touched; a foreign `Origin` is 403 before routing for every method; `Allow-Methods` GET, POST, PATCH, DELETE, OPTIONS; `readPartnerJsonBody` takes exactly `application/json` (optionally `; charset=utf-8`), else 415 before the body is read | `partner-session-handler.test.ts` (origin, preflight, media-type tables), `partner-modules.test.ts` (config pins), Deno integration "PA-10" (a counting database port sees no call on `OPTIONS`; `text/plain; x=application/json` is 415) |
| **PA-11** (no log, no foreign bearer) | no `console.*` and no environment read in any partner module; `getActorFromRequest` refuses `gr_ps_` / `gr_inv_`; the partner function never calls it; a Supabase JWT on a session route is the one 401 with no port touched | source scan in `partner-modules.test.ts`; Deno integration "PA-11" (a recording fake sees **no** GoTrue request for a partner token, with a control that it does see one for a real-shaped JWT; a JWT on every session route opens no transaction) |
| **PA-12** (verify) | S0 wrapper first, then `partner_session_mint` through the `partner_mint` kind; every refusal one uniform 401; the opaque token comes back once, in a 201; only its sha256 reaches the database | Deno integration "PA-12" (ES256 and RS256 mint; every wrong-assertion shape is the same 401; the token is not stored); `partner-session-handler.deno.test.ts` (real wrapper, software authenticator) |
| **PA-13** (mint kind scope) | lint rule `privileged-mint-scope` over `partner_mint` and `edge_partner_minter` | lint fixtures `mint-partner-kind-outside.ts`, `mint-partner-kind-wrong-caller.ts`, `mint-partner-role-outside.ts` and cells (427 pass) |
| **PA-13b** (post-bind) | the role and privilege check is a statement of its own, then `partner_binding_kind()` must read `partner` | Deno integration "PA-13b" (three cells: fails as `edge_actor` and on a wrong kind; exactly the 4.3 EXECUTE list inside a real partner transaction; unknown and malformed tokens are one error) |
| **PA-27** (reauth ownership) | `partner_reauth_credential_read` and `partner_reauth_check` find only a live credential of the **session's own user** | matrix 27 (the Edge-side read returns nothing for another person's credential; the definer called directly answers `unknown_credential`; `reauth_until` unset); Deno integration "reauth" |
| **Cooldown** (section 8) | 5 failed verifications per credential per hour start a 15 minute cooldown, returned as a status so it commits with the refusal; a failure during the cooldown is not counted; an unknown credential writes nothing | matrix 27 (counter, cooldown, fixed 15 minutes, no stretching, lookup refuses with no key material); Deno integration "section 8" (the counter persists across five real refusals, the sixth is refused even with a valid assertion) |
| **Commit on every status** (17.8) | every database refusal is a returned value; the response is built after the transaction | `partner-session-handler.test.ts` (the fake records `committed` per status; a throw is the only rollback); Deno integration "COMMIT on every status" and the counter-regression, signature-invalid and reauth cells read the rows from a second connection |
| **GET session is PEEK** | class PEEK, no scope, no aal gate, never writes `last_seen_at` | matrix 27 (six reads leave a 5-minute-idle session idle); Deno integration "PA-12" |
| **Reauth** | `partner_session_reauth_for_partner` takes the session from `partner_binding()`; `reauth_until` is written only by the `partner_reauth_verifier`-owned `partner_reauth_apply`, which runs the verification itself and writes only on `ok` | matrix 27 (replay, 5-minute window, lock clears it); Deno integration (10 reauth attempts per member per hour, then 429, the hits commit) |
| **`pop_jkt` / `X-GR-PoP`** | accepted and ignored; `x-gr-pop` is advertised in `Allow-Headers` | `partner-session-handler.test.ts` |
| **Item 9** (check 15 and friends) | 17.10, last paragraph | `10_function_inventory.sql` (four must-fail fixtures, one control), parity test |

### 18.3 Departures from sections 4 to 6, and why

- **D1. Failure counter table.** Section 8 names the limit and not the storage. `app.partner_sign_in_failure` is one row per existing credential, no user id, no foreign key, owned by the issuer role. Retention is a purge step for S1.5 (18.4).
- **D2. The allowed origin lives in the environment** (`GR_PARTNER_ORIGIN`), not in `partner_rp_config`, because `OPTIONS` must not open a database connection (PA-10). The handler compares it with `partner_rp_config.origin` on **the routes that use a challenge and so read the relying party** (`options`, `verify`, `reauth/options`, `reauth`) and answers 503 when they differ, so the two copies cannot drift apart silently. (S1.2's text said "every database path": that was wrong. `GET session`, sign-out, lock and the S1.3 PIN routes read no relying party and run no such check; the S1.3 gate cells in `partner-session-handler.test.ts` pin both halves, the mismatch refusal on `verify` and on `reauth`, and the routes that do not check.) A malformed value throws at boot; an unset one refuses every request that carries an `Origin`.
- **D3. Reauth refusals are a 403 `reauth_refused`, not a 401.** A 401 on `POST reauth` would tell the client its **session** is dead; the session is fine, the assertion was wrong. A dead session is still the one 401.
- **D4. The reauth verification is split across two owners** so that "the role that owns the column writer is the verification fact" (R5-L1): `partner_reauth_check` (issuer: the credential, the relying party, the nonce table, the SQL verifier) is executable by `partner_reauth_verifier` only, and `partner_reauth_apply` (verifier) calls it and writes `reauth_until` only on `ok`. The `_for_partner` definer writes the audit row for `signature_invalid` and `counter_regression`, because a partner-bound caller cannot write `partner_auth_alarm` (0048).
- **D5. `counterOnly`.** When the wrapper reports a genuine signature whose counter did not advance, the Edge still calls the mint, which writes the audit and alarm rows (PA-12) and answers `counter_regression`. That refusal is not counted as a guess against the credential.
- **D6. Rate limit shape.** `hit_partner_rate_limit(key, window, max)` returns the count and never raises over the cap (0020); the Edge decides, and the hit runs in its own short transaction that commits before the request transaction opens. Reauth: 10 per member per hour (hard). **The IP and global buckets are alert-only and are not built** (18.5).
- **D7. `getActorFromRequest` also refuses `gr_inv_`** (the invite token), for the same reason as `gr_ps_`, and case-insensitively.
- **D8. Shared HTTP helper.** `readCappedJsonBody` was extracted from `_shared/http.ts` and `withTimeout` exported; no behaviour change. The existing `readJsonBody` (substring match on the media type) is left alone and the partner lane never calls it.
- **D9. The Edge refuses an expired challenge itself** before the database round trip; the database re-checks the HMAC and the expiry.
- **D10. `lock`** clears the PIN grant (via `partner_pin_grant_consume`), the reauth window and the OTP proof. It does not touch `mfa_until`: nothing sets it yet (S1.4).

### 18.4 Seams left for later slices

- **S1.3 (PIN): built, 19.** `pin_grant_until` is written only by the `partner_pin_verifier`-owned definers; `lock` already clears it. The SESSION / PEEK class list (`partner_session_class_functions.txt`) must stay limited to functions that act on no object.
- **S1.4 (TOTP / `mfa_until`).** `lock` must clear `mfa_until` through a `partner_totp_verifier`-owned writer; GET session already reports it. **A3 still fails closed** (S1.3 enabled A2).
- **S1.4, the aal 1 exception for an operator or admin (S1.2 gate L5).** `partner_authorize` gates **every** class except SESSION and PEEK on the person's required assurance, so an `aal` 1 operator or admin is refused `reauth/options`, `reauth` (0049: class A0) and, since S1.3, `otp-proof/*` and `GET pin` (class A0). Section 4.1 says the opposite for a person with **no confirmed TOTP**: they must reach `totp/enrol`, `totp/confirm`, `otp-proof/*` and `reauth`, or a new operator or admin can never enrol (PA-28). The exception is **S1.4's**: a class (or a clause of A0) that admits those four routes at `aal` 1 **only while the person has no confirmed TOTP**, refuses them once TOTP is confirmed, and is covered by a cell per route and per state. Until then the routes are fail-closed, which is the safe direction, and the cell `PA-20 shape` in matrix 28 pins it.
- **S1.5.** Registration must call `partner_cose_parse` (17.8, blocking). Purge definers for `partner_sign_in_failure`, `partner_auth_challenge` and `partner_auth_alarm`. Session eviction must revoke, never DELETE. The `register_first` and reauth issuers share `partner_challenge_core`.
- **Operator steps at deploy:** `GR_PARTNER_ORIGIN` (exact https origin), the `partner_rp_config` row with the **same** origin, the Vault key `partner_challenge_key` (generated inside the database, `edge-role-design.md` item 8).
- **Proof of possession (N7)** stays reserved: the field and the header are ignored today.

### 18.5 Alert-only buckets (IP and global)

Section 8's IP and global buckets are **alert-only**: they must never refuse a request (a refusal keyed on an address is a denial-of-service lever against a shared office NAT), so they only produce a signal. The sink for such a signal is `app.partner_auth_alarm`, whose `kind` values 0048 fixed by a CHECK; a new kind is a migration change in a file that is frozen for this slice, and the Edge cannot write the table at all (no privilege; no partner-bound writer). They are therefore **not built**, and nothing in this slice pretends otherwise. The failure counter (D1) is the only bound on failed verifications, and the member-keyed reauth bucket the only rate limit that refuses. Follow-up for S1.5: add the alarm kinds, then a minter-lane writer.

### 18.6 Mutation pass

Scratch copies of the tree only (the mutation-marker grep over the worktree was empty before every commit). **35 mutants, all killed.**

- **Edge (20, by the vitest handler and module suites unless noted):** foreign Origin not refused; `OPTIONS` opens a connection; origin matched by prefix; PATCH and DELETE dropped from `Allow-Methods`; media type by substring; any media-type parameter accepted; the `gr_ps_` prefix check removed; the prefix check case-sensitive; the S0 wrapper skipped; an unknown credential answered differently; the failure counter not recorded; a refusal that rolls back (throw instead of return); the bearer shape not checked; a `console.log` of the token; a `pop_jkt` field changing the outcome; the reauth rate-limit hit skipped; reauth's ownership read dropped. **Killed only by the Deno integration suite against a real cluster (3 of the 20):** the post-bind kind assertion removed, the post-bind role check removed, the `partner_mint` bind guard removed. (The two prefix mutants in `privileged.ts` were stopped at the unit suites; the integration suite was not run against them.)
- **Database (10, by matrix 27, and 10 where noted):** the reauth credential read not tied to the session's user (PA-27); `partner_reauth_check` accepting any user's credential; `reauth_until` written without the verification status; cooldown at the sixth failure; cooldown that does not block the lookup; cooldown of 15 hours; failures counted during the cooldown; GET session on class SESSION (advances `last_seen_at`); the reauth issuer without `partner_authorize` (also check 14); a 50-minute reauth window (killed by the session guard trigger as well as the cell).
- **Lint (4):** `partner_mint` removed from the kinds; `edge_partner_minter` not a minter role; a wrong caller allowed for `partner_mint`; `edge_partner` not a lane role.
- **Check 15 (1 mutant, 4 cells):** the old `prosrc ILIKE` logic put back in the matrix 10 twin turns the four new must-fail cells red.

One weaker kill is recorded as such: the cooldown-at-sixth mutant is stopped by the table's own `CHECK (failed_count BETWEEN 0 AND 4)` before an assertion reads the status.

### 18.7 Verification run for this slice

Both harness modes, one after the other, each 40 pgTAP files, **4126 tests, PASS**, Deno integration **344 passed, 0 failed** (20 of them the new `partner-session.deno.test.ts`), function-inventory check OK, service-role lint clean, exit 0. Unit suite 63 files, **1269 tests**; pure Deno suite **75 passed** (`--cached-only --deny-net`); service-role-lint **427 passed** and the CLI clean; recorder verify 1 passed (mobile untouched); `GOLFRAVEN_DEMO=1 pnpm -r build` and `pnpm -r typecheck` exit 0; `deno check` and `deno cache --frozen` over the function lists plus the two new Deno tests exit 0; `check-migrations-immutable.sh` against `origin/main` and against `119b0dc`: OK, 48 files; gitleaks over `119b0dc..HEAD` clean (18.8); the personal-data grep over every added line shows only `example.test` values; no marker text in the tree.

### 18.8 Egress and environment notes

- No request was denied in this slice.
- gitleaks 8.18.4 was downloaded from the project's release page and **verified against the release checksums file**. It flagged two JWT-shaped test literals (a made-up subject and a dummy signature) in the first two test commits. They were replaced with a value built at run time in the next commit, and the two historical fingerprints are listed in `.gitleaksignore` with a reason, as the repository's own precedent requires (history is not rewritten).
- `origin/main` is a squash of S1.1b whose tree is identical to `119b0dc`; the branch took it with `git merge -s ours`, so the history matches and the content did not change.
- A restricted-mode run found one real defect in matrix 27: the registry cell read `private.function_inventory` as the harness role, which cannot see it (row-level security). It now reads it as `service_role`, as matrix 26 does.

### 18.9 The failure counter's burst limit (S1.2 gate L1)

The per-credential failure counter (`partner_sign_in_failure_record`, 5 failures then a 15-minute cooldown) is exact under concurrency: thirty parallel failures of one credential count **exactly four** and answer `cooldown` to the other twenty-six, because the row is locked `FOR UPDATE` (`tools/db/test-partner-serialisation.sh` case 7; with the lock removed the case fails). What the counter does **not** bound is how many forgeries are **verified before the cooldown applies**. The cooldown is read by `partner_credential_lookup`, which runs **before** the Edge's signature verification, and the failure is recorded **after** it. So **N concurrent forged assertions for one credential are all looked up while the credential is not yet cooling, and all N are verified** (and all N are recorded, which starts the cooldown at the fifth); only requests that arrive after the cooldown has started are refused without being verified. The cost of the burst is **CPU only**: N S0-wrapper verifications (the database's own verifier, measured in 17.7: ES256 about 16 ms, RS256 about 2 ms; the Edge wrapper's cost was not measured here). It buys the attacker no extra guess at anything that matters: a forged assertion has no signature that can be right, the credential's counter and session are untouched, and the mint's own checks run only for a verified assertion. It is not bounded by the cooldown, and this repository sets no other bound on it (the 64 KB body cap limits one request, not the number of requests; the platform's own request limits `[unverified - training knowledge]` are not this design's control). Accepted and stated here; closing it would mean taking the credential's lock before the verification, which makes every sign-in of that credential wait behind a verification (a lever against the legitimate user), the same trade-off 18.5 declines for the IP bucket.

## As built: DB hygiene (migration 0050)

A small follow-up slice on `main` after S1.1b and S2a: **one migration, `0050_db_hygiene.sql`** (no migration references it by file name); `0001`-`0048` are byte-identical (`tools/db/check-migrations-immutable.sh --base origin/main`). It closes the S1.1b gate's L-4 (and with it the S1.1a InitPlan NIT) and two S2a gate NITs. **Nothing is granted, no policy is added or loosened, FORCE RLS is untouched.**

| Item | Fix | Test |
|---|---|---|
| **L-4** the 0040 purges depend on the planner's statistics (`DELETE ... WHERE id IN (SELECT ... LIMIT 5000)` becomes quadratic on stale `pg_class` numbers) | Section 1 of 0050 redefines **all six** definers of that shape (`purge_consumed_nonce`, `purge_rate_limit_buckets`, `purge_signin_email_proofs`, `purge_signin_revocation_queue` from 0040/0041, plus `purge_install_link_tombstones` (0033) and `purge_fix_coords` (0032, an `UPDATE`, the same shape) so that the batch is taken **once**: a single-key table is matched with `key = ANY (ARRAY(SELECT key ... LIMIT n))` (an uncorrelated InitPlan, evaluated once); the two composite-key tables (`rate_limit_bucket`, `install_link_account`) read the batch once and delete by primary key in a loop. `CREATE OR REPLACE` with the same identity: owner, `SECURITY DEFINER`, `search_path = ''`, return type, every grant, the comment and the `function_inventory` rows are asserted unchanged inside the migration; bounds, floors, argument checks, purge windows and return values are as they were. The follow-up note's `WITH b AS MATERIALIZED (...) DELETE ... USING b` was **measured and not taken**: see below | `30_db_hygiene.sql` (posture, shape, floors, grants, registry); `20_retention_hygiene_purges.sql` and `16_edge_role.sql` unchanged and green (bounds, floors, counts); Deno `retention-purge`: the cell "0050: with STALE planner statistics" |
| The test-side `ANALYZE` | **Removed** from `seedBacklog()` (comment says why). The suite now passes without it, and the new cell builds the stale state on purpose | the same cell; the whole Deno suite |
| **InitPlan NIT** (118 policies) | **Applied** in 0050 section 2 (see the decision below): every `private_definer` policy that calls `private.partner_binding_kind()` directly now uses `(SELECT private.partner_binding_kind())`, in `USING` and `WITH CHECK`; the allow-list snapshots are re-derived and `supabase/tests/fixtures/definer_policy_exprs.txt` regenerated (118 rows change, nothing else; check 15 accepts both forms) | `30_db_hygiene.sql` (the form, the snapshot equals the live expression); matrix 10 checks 5, 6, 9, 15; `verify-function-inventory`; PA-4c sweep in 25_ |
| **S2a NIT** previous-pepper selection (mutant q09, `min` instead of `max`, survived) | pinned | `30_db_hygiene.sql` 3b: two rotations (2 h and 30 min ago), an instant between them must be judged under the **previous** pepper; the cell fails for `min` |
| **S2a NIT** `app.course_pin_pepper_epoch` | `CHECK (effective_from <= recorded_at)` (`course_pin_pepper_epoch_effective_not_future`). A future-dated rotation would send the instants between now and then to the retired pepper. **Honest limit:** `recorded_at` is the operator's to supply, so this stops the mistake (a future `effective_from` with the default `recorded_at`), not a deliberate one; the operator already holds the table | `30_db_hygiene.sql` 3a: future by a minute / a day / one second past an explicit `recorded_at` each fail with `23514`; equal, now and back-dated pass; the constraint is validated |
| **S2a NIT** compromise-rotation text | a leaked `course_pin_pepper_previous` must be **deleted from Vault** (a leftover old pepper becomes a standing second key as soon as a later rotation writes an epoch row); added to the procedure above (the S2a section, "A PIN rotation does not break a queued printed-QR scan", item 2) and to `p3-money-path-requirements.md` | prose |

**What was measured (stale statistics reproduced without `ANALYZE`).** A table is filled with 5,003 rows, emptied, `VACUUM (TRUNCATE false)`d (a vacuum that cannot truncate, made deterministic; `pg_class` then says `148 pages, 0 tuples` for the proof table, exactly the S1.1b state), and refilled. Timed as `private_definer` under RLS on a scratch cluster, one batch of 5,000:

| Statement | `consumed_nonce` | `rate_limit_bucket` | `signin_email_proof` |
|---|---|---|---|
| the 0040 / 0041 shape (`IN (SELECT ... LIMIT)`) | 5.4 s | 4.6 s | **118.8 s** |
| `WITH b AS MATERIALIZED (...) DELETE ... USING b` (the follow-up's proposal) | 4.2 s | not run | 4.4 s |
| 0050 (array batch / per-key loop) | **13 ms** | **30 ms** | **69 ms** |

`MATERIALIZED` stops the `LIMIT` subquery being re-run, but the join is still planned from a one-row estimate (a Nested Loop with the CTE as its inner side: 25 million comparisons, the same quadratic cost with a cheaper constant), so it was not taken. In the Deno cell the same recipe on a temp table gives: the 0040 shape cancelled by a 1 s statement timeout (10 s without it), the 0050 shape 67 ms; and on the four real tables the new steps remove a full batch in 99 / 71 / 295 / 55 ms (proofs / revocation queue / nonce / buckets). **How slow the old shape is on the real tables varies with the index and histogram state autovacuum left in the template database** (it was cancelled in some harness runs and finished in 22 ms in others: this nondeterminism is the dependence 0050 removes), which is why the real-table cell asserts only the new definers and the positive control lives on a temp table whose state the cell controls. A `ctid` array was not used for the composite-key tables because `private_definer` holds only column-level `SELECT` on `app.install_link_account` and `ctid` needs the table-level privilege.

**The InitPlan decision: taken.** S1.1a withdrew the conversion because, with the 0040 purges, it moved `purge_signin_email_proofs()` from about 30 ms to 26.9 s. With the 0050 definers, on the same stale-statistics tables before / after converting the 118 policies: `purge_consumed_nonce` 13 / 10 ms, `purge_rate_limit_buckets` 30 / 29 ms, `purge_signin_email_proofs` 69 / **18 ms** (the 0040 shape on the converted policies: **27.8 s**, the S1.1a figure reproduced: the conversion is safe only because of section 1). It is applied by `ALTER POLICY` over the catalog (the predicate is a regex over the stored expression, with a lookbehind so the two 0048 alarm policies, already in that form, are not touched), and the migration fails if any `private_definer` policy still calls the function directly.

**Mutation pass** (scratch copies of the migrations only, a fresh database each; 13 mutants, **12 killed, 1 equivalent**): `purge_signin_email_proofs` back to `IN (SELECT ... LIMIT)` (killed by 0050's own shape assertion); the nonce purge's `LIMIT` removed (`30_` and `20_`); the bucket purge's loop deleting by `bucket_key` alone (`30_`, the composite-key cell added for it); the tombstone purge's `LIMIT p_max_rows` removed (`16_`); `purge_fix_coords`'s `LIMIT` removed (`16_`, whose purge cell now also pins the limit); the pepper CHECK replaced by `true`, by `<` (the equal boundary) (both `30_`); `max` replaced by `min` in 0046's `course_pin_matches`, q09 (`30_`, 3b); the allow-list snapshot not re-derived, the `WITH CHECK` conjuncts not converted, the conjunct replaced by a constant (all three stopped by 0050's own assertions, so the migration does not apply). The one **equivalent** mutant: dropping `status <> 'pending'` from the revocation purge changes nothing, because a pending row has `completed_at IS NULL` and `NULL < ...` is not true.

**Verification of the whole tree** (merged with `main` at `f8a85f7`, 0049): both harness modes, run one after the other: each **41 pgTAP files, 4164 tests, PASS** (`30_db_hygiene.sql` is 38 cells; on `cbd9c2b` alone it was 40 files, 3997), Deno integration **345 passed, 0 failed**, function-inventory check OK, service-role lint clean; unit suite 63 files, **1269 tests**; `GOLFRAVEN_DEMO=1 pnpm -r build` and `pnpm -r typecheck` exit 0; `check-migrations-immutable.sh --base origin/main` OK, 49 files; gitleaks over `origin/main..HEAD` no leaks; the personal-data grep over the added lines empty. The stale-statistics cell on the merged tree: the 0040 shape on a temp table cancelled by the 1 s timeout, the 0050 shape 62 ms; a full batch on the real tables 97 / 67 / 187 / 34 ms.

**Merged with 0049 (S1.2).** 0049 adds no `private_definer` policy that calls the partner-binding function (its three new policies are `partner_session_issuer`'s), so the conversion has nothing of 0049's to convert; it still converts exactly the 118 that 0047 section 8c closed, the fail-loud assertion passes, and 120 `private_definer` policies now carry the InitPlan form (118 + 0048's two alarm policies). `definer_policy_exprs.txt` was regenerated from the live catalog after 0049 + 0050 with the query in its header (217 rows; only the 118 conjunct forms differ from `main`). The pgTAP file is `30_db_hygiene.sql` (27 is S1.2's; 28 and 29 may be taken by parallel slices).

**Seams.** A purge of the tables 0046 and 0048 mark "retention is a follow-up" is still not built. `purge_fix_coords` is an `UPDATE` and keeps its `ORDER BY created_at`.

## 19. As built: S1.3

### 19.1 What was built

The partner (staff) **step-up PIN**: the second factor for the A1 and A2 action classes, and the email proof that gates setting it.

- **migration 0052** (all `CREATE` plus two `CREATE OR REPLACE`: `partner_authorize`, and S1.2's `partner_session_reauth_for_partner` (gate round 1, LOW-1: 0049 is immutable, so its class change lives here); 0001 to 0049 untouched):
  - **`app.partner_pin`**: one row per person (`user_id` primary key, cascade), `salt` (16 bytes), `iterations` (210000 to 1000000), `pepper_kid`, `verifier` (32 bytes), `failed_count` (0 to 5), `failed_today` (0 to 20) with `failed_day`, `last_failed_at`, `next_attempt_at`, `locked_at`, `must_change`, `last_ok_at`, `set_at`. FORCE RLS; every privilege revoked from PUBLIC, `anon`, `authenticated` and `service_role`; **no Edge or client role has any grant**. The only table privileges are `partner_pin_verifier` (select, insert, update, behind policies keyed on `private.partner_binding_user()`) and `private_definer` (the `delete_my_data` window pair).
  - **The verifier.** `verifier = HMAC-SHA256(Vault secret partner_pin_pepper, "golfraven/partner-pin/v1" || 0x00 || user id (16 bytes) || derived (32 bytes))`. The browser sends only the 32 PBKDF2 bytes; the PIN never leaves the browser. `private.partner_pin_core` is the **only** reader of the pepper (EXECUTE for `partner_pin_verifier` **and its owner `private_definer`**, which holds it as the owner of the function, and nobody else: the ACL is exactly those two entries, asserted by matrix 28; no `_for_partner` wrapper calls it, so no session reaches it as `private_definer`; 55000 when the secret is missing or shorter than 32 bytes, so a missing pepper is a deploy fault and never a pass) and compares `HMAC(K, stored) = HMAC(K, computed)` so the comparison is not byte-for-byte on the secret.
  - **Definers owned by `partner_pin_verifier`** (R5-L1: the role that owns the column writer is the verification fact): `partner_pin_attempt` (the one place a derived key is evaluated: `FOR UPDATE` on the PIN row, then status `unset`, `locked`, `must_change`, `retry_after`, `ok` or `wrong`), `partner_pin_verify_apply` (calls it, and on `ok` writes `pin_grant_until = now() + 60 s` on the session), `partner_pin_set_apply` (set and change; its **first** statement is the prerequisite check), `partner_pin_params_read` and `partner_pin_grant_consume_fresh`.
  - **Refusals are returned statuses, not exceptions** (the 0020 lesson, 17.8): a wrong key, a backoff and a lock all commit, so the counters persist. Only a missing prerequisite (`42501`) and a missing pepper (`55000`) raise.
  - **Lockout.** After the 3rd consecutive failure a 30 second backoff, after the 4th 5 minutes (a failure during the backoff is not evaluated and not counted), the 5th failure locks until a manager reset (S1.5). A correct PIN on the 6th attempt is refused: a locked PIN is never evaluated. 20 failures in one UTC day lock as well, and a success does not reset the day count. `FOR UPDATE` serialises concurrent attempts: **20 concurrent wrong keys evaluate exactly three** (the third starts the backoff) and the other seventeen answer `retry_after`.
  - **The grant.** `pin_grant_until` is single use (consumed by the first A1 or A2 decision that reads it) and bound to the session row that earned it, so another session of the same person, or another person, cannot use it.
  - **Set and change need an email proof.** `partner_pin_set_apply` requires `enrolment_until > now()` (a first-time invite enrolment) or `otp_proof_until > now()` (an email proof), else `42501`: **a passkey alone is refused**, so a coworker at an unlocked tablet cannot set a PIN. Change additionally evaluates the current PIN through the same lockout. Both are refused for a person who is not a staff or manager member. **The email proof is single use for a PIN set or change (gate round 1, MEDIUM-1):** the wrapper clears `otp_proof_until` in the same transaction as the write, on the `ok` outcome only, so one email proof buys one PIN write and not ten minutes of them. A refused outcome (`locked`, `already_set`, a wrong current PIN, a backoff) writes no PIN and keeps the proof: a wrong current key is bounded by the lockout (five wrong keys lock the PIN), not by spending the proof. The GoTrue session id stays on the row, so one GoTrue session still proves one proof. **S1.4's TOTP enrolment must consume the proof the same way** (19.5).
  - **`partner_authorize`** (`CREATE OR REPLACE`, owner and grants unchanged): a new class **`A0_WRITE`** is A0 in every respect except that it locks the session row `FOR NO KEY UPDATE` up front (gate round 1, LOW-1: 19.9); the PIN verify, set, change, the email proof and the S1.2 reauth use it, and the two session classes (`SESSION`: sign-out, lock) now take the same lock. **A1** (consumes the PIN grant) and **A2** are enabled. **A2** needs `reauth_until > now()` (a passkey re-assertion in the last 5 minutes) **and** a PIN grant with more than 30 seconds of its 60 left (`partner_pin_grant_consume_fresh(30)`); **A3 stays fail-closed** (S1.4).
  - **`_for_partner` wrappers** (owner `private_definer`, EXECUTE for `edge_partner` only, each opening with `partner_authorize` and a literal class: check 14): `partner_pin_params_for_partner`, `partner_pin_verify_for_partner`, `partner_pin_set_for_partner`, `partner_pin_change_for_partner`, `partner_session_otp_target_for_partner`, `partner_session_otp_proof_for_partner`. The wrappers write the audit rows (`partner.pin.wrong`, `partner.pin.locked` once per lock, `partner.pin.set`, `partner.pin.change`) because a partner-bound caller cannot write `partner_audit` itself.
  - **Registries**: 13 `function_inventory` rows, 5 `definer_policy_allowlist` rows with their derived expressions, 7 `partner_owner_privilege` rows (fixtures regenerated), `pii_retention` (delete the row) and `pii_export` (excluded: a verifier is not exportable), and a grants assertion at the end of the migration. `private.partner_binding_user()` is the binding-keyed policy key: no settable GUC keys any policy an edge role can reach.
- **Edge**, `_shared/partner/`: **`pin-contract.ts`** (the browser-derivation contract), `pin-vectors.ts`, `pin-deny-list.ts`; `ports.ts`, `session-shape.ts`, `session-handler.ts` and `privileged.ts` carry the new routes; `partner-session/index.ts` wires the email-OTP port. `privileged.ts` is still the only module that touches the database.
- **Routes** on `partner-session` (all POST except `GET pin`; a dead session is the one 401 before any work; the class column is the *wire* class, `A0`: the four routes that write the session row run as database class `A0_WRITE`, which differs only in its lock):

| Route | Class | Body | Answers |
|---|---|---|---|
| `GET pin` | A0 | none | 200 `{ state: "unset" }`, `{ state: "must_change" }` or `{ state: "locked" }` (no salt), else `{ state: "ok", salt, iterations, retryAfterSeconds }` (the salt is returned while a backoff runs, so the browser can derive; `retryAfterSeconds` is 0 when none) |
| `POST step-up/pin` | A0 | `{ derived }` | 200 `{ grantExpiresAt }`; 403 `pin_wrong`, 403 `pin_locked`; 409 `pin_not_set`, 409 `pin_must_change`; 429 `pin_backoff` with `Retry-After` |
| `POST pin/set` | A0 | `{ derived, salt, iterations }` | 200; 403 `forbidden` when there is no email proof or enrolment window, or the proof was already spent by an earlier set or change (the database's `42501`); 409 `pin_already_set`, `pin_must_change`; 403 `pin_locked` |
| `POST pin/change` | A0 | `{ currentDerived, derived, salt, iterations }` | 200; 403 `forbidden` (no email proof, or the proof was already spent); 403 `pin_wrong`, `pin_locked`; 409 `pin_not_set`, `pin_must_change`; 429 `pin_backoff` |
| `POST otp-proof/start` | A0 | none | 200 `{ sent: true }`; sends a code to the member's **own** address from the database; 409 `otp_unavailable` (no address); 429 `rate_limited` (3 a member an hour: then no mail) |
| `POST otp-proof/verify` | A0 | `{ code }` | 200 `{ otpProofUntil }` (10 minutes); 403 `otp_refused` for a bad code, a stale GoTrue session or one that already proved once; 429 `rate_limited` (5 attempts a member an hour, even for the right code) |

  Every body is validated by length and encoding only (`parseDerivedKey`: 43 characters of canonical unpadded base64url, exactly 32 bytes; `parsePinSalt`: 22 characters, 16 bytes; `parseIterations`: an integer in range) and rejects unknown keys, so **a PIN-shaped value is a 400 before any database work, whatever the route**.
- **The email proof.** The Edge reads the member's own address from the database, asks GoTrue (anon key) to send the one-time code, verifies the code, and passes the GoTrue **session id** to the database. `partner_session_otp_proof_for_partner` checks that GoTrue session is fresh (created within a minute) and **for this user**; a UNIQUE index gives **one proof per GoTrue session**. The GoTrue session is closed **after** the proof is recorded (in a `finally`), and **no vendor call happens inside a database transaction**.

### 19.2 Brief item, fix, test

| ID | Fix | Test |
|---|---|---|
| **PA-18** (PIN verification) | section 19.1: the HMAC verifier, the lockout, `FOR UPDATE`, statuses not exceptions | matrix 28 (vector computed outside the database, backoff, lock, day rule, 6th-attempt refusal); Deno integration (counters and audit rows commit across real refusals, read from a second connection); `tools/db/test-partner-serialisation.sh` case 8 (20 concurrent wrong keys: exactly 3 evaluated, 17 `retry_after`, one lock audit row) |
| **PA-19** (grant) | single use, session bound, `<= now + 60 s` (`pin_grant_until` has a guard cap) | matrix 28 (second use refused, another session and another person refused, the cap), A1/A2 class cells |
| **PA-21** (set and change prerequisite) | `partner_pin_set_apply` checks `enrolment_until` / `otp_proof_until` first | matrix 28 (a passkey alone: `42501`; the proof opens it; change needs the current key), Deno integration |
| **A1, A2 enabled; A3 closed; PA-4b** | `partner_authorize` | matrix 25 (PA-4b: A2 refuses without prerequisites, A3 still closed), matrix 28 |
| **Pepper** | `partner_pin_core` is the only reader; missing pepper is 55000 | matrix 28 (a different pepper gives a different verifier; the verifier equals an independent HMAC), Deno integration (503, counter does not move) |
| **L1** (S1.2 gate: burst limit) | stated, 18.9; the counter is exact under concurrency | serialisation case 7 (30 parallel failures: 4 counted, 26 cooldown) |
| **L4** (D2 wording) | 18.3 D2 restated: the origin check runs only on routes that read the relying party | `partner-session-handler.test.ts` (E18 verify and E19 reauth mismatch refuse; the PIN routes read no relying party) |
| **N2** (citation) | `http.ts` and `privileged.ts` cite `partner-modules.test.ts` | `partner-modules.test.ts` |
| **N3** (section 8 wording) | the section 8 row restated | doc only |
| **L6** (timing oracle) | recorded in R-P8 | doc only |
| **L5** (aal 1 exception) | recorded as S1.4's (18.4); the routes are fail-closed meanwhile | matrix 28 cell `PA-20 shape` |

### 19.3 Departures from sections 4 to 6, and why

- **D1. The deny-list is enforced in the browser, not the database.** Section 6.3 asks for a deny-list "enforced at set time". The server never sees the PIN, only 32 derived bytes, so neither the database nor the Edge can tell a denied PIN from another. A probe under a fixed salt would let them, but it is client-asserted (no stronger against a custom client) and would hand the Edge a PIN-equivalent that 10,000 hashes invert instantly. The rules (`format`, `repeated`, `run`, `year`, `date`, `common`) and the explicit list (74 entries, committed) are one pure module, `pin-deny-list.ts`, which the S7 form must call before it derives anything, and a unit test holds it to its own table. **A custom client can set any four digits; what bounds that is the lockout, the email proof to set a PIN, and the per-action grant.** The list was assembled from training knowledge: `[unverified - training knowledge]`; the owner may replace it in a PR.
- **D2. Reset is a seam.** A manager reset needs the S1.5 reach rule (which manager may reset which person's PIN), so `partner_pin_reset` is not built. The tests emulate a reset with an owner `UPDATE` (`locked_at` cleared, `must_change` set). The set path already accepts `must_change`.
- **D3. The OTP-proof routes are built here**, not left as a seam, because setting a PIN needs them.
- **D4. The pepper is a Vault secret, `partner_pin_pepper`.** It is provisioned by the operator (19.6) and never returned by any function. `pepper_kid` is stored per row for rotation; rotation itself is not built.
- **D5. The OTP-proof rate limits are member-keyed, not mailbox-keyed (S1.3 gate LOW-2).** Section 8 says `session/otp-proof/*` uses "3 sends/h; the same 5-per-target counter", that is, the 0035 `reserve_signin_otp_attempt` / `release_signin_otp_attempt` pair keyed on the mailbox. The build uses two member-keyed buckets through `hit_partner_rate_limit` (3 sends and 5 verify attempts per member per hour, `session-handler.ts`). **Why.** The mailbox here is the member's **own** address, read from the database and never chosen by the caller (`partner_session_otp_target_for_partner`), so a member key and a mailbox key name the same thing and the member key cannot be varied by an attacker; the 0035 pair exists because a sign-in OTP target is attacker-chosen. GoTrue's `/verify` is public: someone who learns the member's address can spend GoTrue's own per-address limits from outside, and that is GoTrue's to bound, not ours. What the member bucket bounds is the attempts a **live, passkey-authenticated session** can make, which is the only caller of these routes. **Effect.** A member with two sessions shares the budget (the key is the member), which is the stricter reading. The section 8 row is annotated; nothing else changes.
- **D6. The deny-list also refuses valid `DDMM` dates (S1.3 gate N4).** Section 6.3 names `MMDD`; a day-first date (`2512`, `3112`) is as guessable, so `pin-deny-list.ts` refuses both orders under the one rule `date`. This is stricter than 6.3, not looser.
- **Not departures, stated so they are not mistaken for ones:** the A2 age rule (a PIN grant at most 30 s old, with `reauth_until`) and the day rule (20 failures a UTC day lock, a success does not forgive them) are exactly 6.3's text; the table CHECK `failed_today BETWEEN 0 AND 20` and the guard's 60 s cap on `pin_grant_until` (0047) are the database's second line.

### 19.4 The browser-derivation contract (for S7)

The PWA must import `supabase/functions/_shared/partner/pin-contract.ts` and `pin-deny-list.ts` by relative path (both are Web Crypto only), or reproduce them exactly:

- `derived = PBKDF2-HMAC-SHA256(password = the 4 PIN characters as ASCII bytes, salt = the 16 stored salt bytes, iterations = the stored count, dkLen = 32 bytes)`.
- **Set and change:** the browser calls `pinRejection(pin)` first and refuses a non-null answer, picks `newPinSalt()` (16 CSPRNG bytes) and an iteration count in **[210000, 1000000]** (default **600000**, the design's figure; a low-end iPad measurement is S0's, still open), and sends `{ derived, salt, iterations }` as canonical **unpadded base64url**.
- **Verify:** `GET pin` returns the stored `salt` and `iterations`; the browser derives the same bytes and posts `{ derived }`. A locked, unset or `must_change` PIN returns no salt.
- **Vectors.** `pin-vectors.ts` holds four vectors computed outside the code (Python `hashlib.pbkdf2_hmac`), at the floor, the default and the ceiling; they are asserted by vitest (Node), by a pure Deno test and must be asserted by the PWA's own tests. A browser that derives anything else for these inputs cannot verify against a stored verifier. A change to any constant is a contract version bump, in step with the label in migration 0052's `partner_pin_core`.

### 19.5 Seams left for later slices

- **S1.4:** TOTP and `mfa_until`; **a TOTP enrolment that is gated by the email proof must spend it as the PIN set and change do (19.1, MEDIUM-1): clear `otp_proof_until` in the same transaction, on success only**, so one proof is one enrolment, not a ten-minute licence for every step-up write; **A3 stays closed**; the aal 1 exception for an operator or admin with no confirmed TOTP (18.4, L5) now also covers `otp-proof/*` and `GET pin`.
- **S1.5:** `partner_pin_reset` (the manager reach rule, and the `locked_at`, `failed_*` clear with `must_change`); purge definers; `pepper_kid` rotation. **Ship condition (S1.3 gate LOW-3): until `partner_pin_reset` exists a locked PIN cannot be cleared in the app (the only path is an owner `UPDATE`). S1.5 must therefore ship before any A1 consumer reaches pilot staff**: a staff member who locks their own PIN by mistake would otherwise be unable to act, and a coworker at a shared iPad can lock someone's PIN (R-P5, the lock lever of section 11) with no remedy. **`partner.pin.locked` must alert the member and their manager** (an S1.5 item: the audit row is written today, nothing reads it).
- **S7:** the PIN form (deny-list call, derivation, `retry_after` countdown) and the email-proof screens.
- **Operator steps at deploy:** provision the Vault secret `partner_pin_pepper` (at least 32 random bytes; **without it every PIN route answers 503**) and keep it in the secrets backup; the email provider's one-time-code template must send a numeric code of 6 to 10 digits (the proof route accepts that range).

### 19.6 Mutation pass

Scratch copies of the tree and of the migration only (the mutation-marker grep over the worktree was empty before every commit). **100 mutants: 95 killed, 5 survivors in three groups that are equivalent (stated below).** The first pass left **two real survivors in the database set** (a CHANGE that reset the day count; a SET that left a stale backoff running) and **one in the Deno set** (`Retry-After` could be the 1 second floor): each was closed with a cell (matrix 28, 179 tests; the integration test) and re-run killed.

- **Database (61, by matrix 28, plus 25, 27 and 10 where they also failed; the migration's own assertions stopped three):**
  - *lockout and counters:* lock at the 6th failure; 20 a day locking at 21; no day lock; backoff 30 s shortened to 3 s; 5 min shortened to 50 s; reported retry seconds off by one; backoff not enforced; a success not resetting the consecutive count; a success resetting the day count; no day rollover; a backoff answered `wrong` not `retry_after`; every key matching; the newly-locked flag never true; a locked PIN's salt returned by `GET pin`.
  - *serialisation:* `FOR UPDATE` removed from `partner_pin_attempt` (killed by the two-connection case 8: 20 wrong keys evaluated instead of 3, 20 lock audit rows); the same for the S1.2 sign-in failure counter (case 7: counted 10 instead of 4), and that counter's cooldown at the 6th failure (case 7).
  - *pepper:* pepper ignored; label separator dropped; the comparison always true; a pepper shorter than 32 bytes accepted; the wrong Vault secret read.
  - *set and change:* the prerequisite removed; the email-proof leg removed; the enrolment leg removed; the window expiry unchecked; the staff or manager membership check removed (two variants); a change that resets the day count; a set that leaves a backoff or `must_change` behind; the change path not evaluating the current PIN.
  - *grant:* verify ok returning no grant time; the A1 consumption removed; the A2 consumption removed (not single use); the A2 age ignored; the age 60 not 30; A2 without the reauth window; the reauth expiry unchecked; A3 opened; a grant not session-bound; a lock-ordering variant of the consumer.
  - *email proof:* the target not the member's own address; another person's GoTrue session accepted.
  - *tenancy and privilege:* a table CHECK dropped (iteration floor, salt length); the verifier's policies widened to every person's row (read, update, insert); the `delete_my_data` window open under a partner binding; the verifier granted DELETE; FORCE RLS removed.
- **Edge (39 including the Deno ones, by the vitest suites and, for the four `privileged.ts` mutants, by the Deno integration suite against a real cluster):**
  - *deny-list and contract (17):* deny-list membership unchecked; year floor and ceiling; every month 31 days; descending runs allowed; repeated pairs allowed; a 3-digit PIN passing format; PBKDF2 with SHA-1; dkLen 16; the PIN not the password as typed; iteration floor and ceiling removed; `derivePinKey` accepting any string.
  - *handler and body shape (18):* a wrong PIN answered 401; a refused PIN rolling back (counter lost); the GoTrue session closed before the proof, and never closed; the OTP send and verify buckets skipped; a vendor call inside a transaction; unknown body keys accepted on four routes; a 1-digit OTP code; `assertSameOrigin` a no-op, and removed from `verify` and from `reauth` separately (S1.2 gate L4, E18 and E19); a locked PIN falling through to the salt branch; `Retry-After` of 0; a locked PIN reported as wrong; a missing GoTrue session id.
  - *`privileged.ts` (4, Deno integration):* error 23505 not mapped (a reused GoTrue session becomes a 500); `otpTarget` always null; `set` ignoring the browser's iteration count; `verify` dropping the retry seconds.
- **The five equivalent survivors (three groups), none hidden:**
  1. **Digits all equal** (one mutant) (`pin-deny-list.ts`): removing the all-equal clause changes nothing, because the repeated-pair clause (`d0 = d2 and d1 = d3`) already refuses `1111`. The clause is kept for readability.
  2. **The length prechecks of the derived key and the salt** (three mutants, `parseDerivedKey` and `parsePinSalt`): loosening the byte-length check (`>= 31`, `>= 15`) survives because the exact 43 and 22 character precheck rejects every other length first; and removing the character precheck (the matching mutant) survives because the exact byte check follows. Each check is the other's backstop; both lengths are pinned by the unit cells for 31 and 33 bytes (derived) and 15 and 17 bytes (salt), and the 32 and 16 byte vectors pass.
  3. **`REVOKE ... service_role`** on `app.partner_pin`: removing `service_role` from the REVOKE survives in this harness because the harness grants it nothing to remove (`pg_default_acl` in the test cluster holds only the 0001 function-EXECUTE revoke, observed this session), so the statement is a no-op here. On a platform whose default ACL does grant `service_role` table privileges `[unverified - training knowledge]` it is the line that removes them. The cell that asserts no `service_role` privilege runs in both harness modes and would fail there. It is kept as defence in depth, the same line 0048 has for `partner_auth_alarm`.
- **Three weaker kills, recorded as such:** the wrong-Vault-secret mutant, the verifier-may-DELETE mutant and the lock-ordering (`FOR SHARE`) mutant were stopped by assertions inside the migration itself (the grants and function assertions at its end) before a matrix cell read the result.
- **A harness gap found and fixed during the pass:** the first serialisation mutants for 0049 (`C1`, `C2`) "survived" only because the throwaway database is cloned from a base that already has 0049 applied, so a mutated 0049 file was never applied. They were re-run by mutating the installed function in place and are killed (counted 10 instead of 4; the cooldown absent).

### 19.7 Verification run for this slice (as first built; the figures after gate round 1 are in 19.9)

Both harness modes (`HARNESS_MODE=superuser`, then `restricted`, run one after the other through the real `tools/db/test.sh`, each on its own port and temp directory), each **41 pgTAP files, 4305 tests, PASS**; matrix 28 is 179 tests. Each ran the replay, money-path, sign-in-proof and **partner serialisation** concurrency scripts (cases 7 and 8 included), the Deno integration suite (**354 passed, 0 failed**, ten of them the new `partner-pin.deno.test.ts`), `verify-function-inventory` OK and service-role lint clean, exit 0. Unit suite 65 files, **1324 tests** (the S1.2 figure was 1269); pure Deno suite **78 passed** (`--cached-only --deny-net`); service-role-lint **427 passed**; recorder verify 1 passed (mobile untouched); `GOLFRAVEN_DEMO=1 pnpm -r build` and `pnpm -r typecheck` exit 0; `deno check` and `deno cache --frozen` over the function lists, and the three pure Deno test files cached `--frozen`, exit 0; `check-migrations-immutable.sh` against `origin/main` and against `596c32f`: OK, 49 files (0050 and 0051 are not on this branch; this slice added only 0052); gitleaks 8.30.1 with `.gitleaks.toml`, `git` and `dir` modes: no leaks; the personal-data grep over every added line shows only `.test` values; no marker text in the tree. Mutation: 19.6.

### 19.8 Egress and environment notes

- No request was denied in this slice.
- gitleaks 8.30.1 is the version pinned in `.github/workflows/ci.yml`; the tarball in the shared scratch area matched the pinned SHA-256, and the release's own checksums file was fetched to confirm it for 8.18.4 as well. History and tree scans with the repository's `.gitleaks.toml`: **no leaks**. (A scan without the repository config finds 53 historical findings that exist identically at `596c32f`; none is new.)
- Test secrets are built at run time: the pepper in the matrix and the integration suite is generated by the test, and no PEM fence or JWT-shaped literal was committed.
- The shim's Vault gets a **test-only** `partner_pin_pepper` (`supabase/tests/shim.sql`); a real deploy provisions its own (19.5).
- One flake found and fixed: the PBKDF2 vector test ran eight derivations (four at up to a million iterations) inside vitest's 5 second default and timed out once under load; it has its own 120 second timeout.

### 19.9 Gate round 1: MEDIUM-1, LOW-1 to LOW-3, N1 to N6

The S1.3 security gate failed the slice on one MEDIUM and listed three LOWs and six NITs. All are addressed in new commits on `p5-s13` (0052 is not on `main`, so it is edited in place; 0001 to 0049 are untouched, and the one S1.2 function that needed a change is redefined in 0052).

| Finding | Fix | Test |
|---|---|---|
| **MEDIUM-1** one email proof allowed unlimited PIN changes for its 10 minutes: `otp_proof_until` was read by `partner_pin_set_apply` and never cleared | `partner_pin_set_for_partner` and `partner_pin_change_for_partner` clear `otp_proof_until` in the **same transaction, on the `ok` outcome only**. `private_definer` already holds `UPDATE (otp_proof_until)` (0047:329) and the guard allows a clear (0047: "cleared or shortened"); no grant was added. **Decision, as the gate asked:** a refused outcome (`locked`, `already_set`, a wrong current PIN, a backoff) does **not** spend the proof: a wrong current key is bounded by the lockout (five wrong keys lock the PIN), and spending the proof on it would let a coworker burn the member's proof by guessing. The GoTrue session id stays on the row, so one GoTrue session still proves one proof. The enrolment window (`enrolment_until`) is **not** single use (unchanged: a register session may set its PIN once and the `already_set` rule stops a second set; a change in the window still needs the current PIN). **S1.4's TOTP enrolment must spend the proof the same way** (19.5) | matrix 28 `MEDIUM-1` cells: a set spends it and a change under the spent proof is `42501` with the PIN unchanged; a wrong current key, an `already_set` set and a `locked` change each **keep** it; the successful change spends it and a second change is `42501`; only `private_definer` can write the column. `partner-pin.deno.test.ts`: the same through the real handler (a second write is a 403 `forbidden`, the PIN row unchanged) |
| **LOW-1** same-session concurrent requests deadlock: `partner_authorize(..., 'A0')` took `FOR SHARE` on the session row and a definer then `UPDATE`d it, so two holders upgrading deadlocked (the gate saw 2 or 3 of 4 parallel verifies die) | a new class **`A0_WRITE`** in `partner_authorize`: A0 in every respect (aal, role list, scope, no PIN grant, no reauth) except that it takes `FOR NO KEY UPDATE` up front. Used by exactly the five wrappers that write the session row: the PIN verify, set and change, the email proof, and **S1.2's `partner_session_reauth_for_partner`, redefined in 0052 with `CREATE OR REPLACE`** (0049 is immutable; the body is 0049's with the class changed; owner, signature, ACL and comment are preserved by `CREATE OR REPLACE`). The two session classes `SESSION` (sign-out, lock: both write the row) take the same lock. Read-only wrappers (`GET pin`, the OTP target, the reauth options and credential) stay `A0` and `FOR SHARE`: reads are not serialised. **Check 14 (a3)** accepts the literal `A0_WRITE` (`verify-function-inventory.mjs` and its mirror in `matrix/10_function_inventory.sql`); (a), the first-statement rule, is unchanged. A class was chosen over a lock-mode argument because check 14 (a3) matches the class as the **last** argument of the call | `tools/db/test-partner-serialisation.sh` **case 9** (three rounds of eight parallel correct verifies on one freshly-seen session: all `ok`, none deadlocks) and **case 9b** (three rounds of four deliberately overlapping session locks, each clearing a standing PIN grant); matrix 28: the class behaves as A0 (passes, demands a role list, enforces scope, refuses an aal 1 operator, consumes no grant) and two structural cells pin which wrappers use `A0_WRITE` and which stay `A0` |
| **LOW-2** OTP limits depart from section 8 (the 0035 mailbox counter) | recorded as **D5** in 19.3 with the rationale; the section 8 row is annotated | doc only |
| **LOW-3** until S1.5 a lock cannot be cleared in the app | recorded in 19.5 as a **ship condition**: S1.5 ships before any A1 consumer reaches pilot staff, and `partner.pin.locked` must alert the member and their manager | doc only |
| **N1** `partner_pin_core` is also executable by its owner `private_definer` | 19.1 and the 0052 comment and inventory note are exact: the ACL is two entries, `partner_pin_verifier` and the owner | matrix 28 asserts the **full ACL** (grantee, privilege, grantor) of `partner_pin_core` and `partner_binding_user` |
| **N2** the A2 boundary was tested from one side | a grant 31 s old is refused beside the 29 s (pass) and 35 s (refuse) cells | matrix 28 `PA-19 / N2` |
| **N3** the OTP send's `shouldCreateUser: false` was untested | the exported sender is exercised with a recording client | `partner-pin.deno.test.ts` `N3` |
| **N4** the deny-list covered `MMDD` only | `DDMM` is refused too (the one rule `date`), recorded as **D6** in 19.3 | `partner-pin-contract.test.ts` (ten day-first dates refused, ten non-dates not) |
| **N5** no test for an extra `pin` key on `pin/change` | covered, and on `pin/set` and `step-up/pin` | `partner-pin-handler.test.ts` |
| **N6** the derived key reaches Postgres as a bind parameter | one sentence in section 11, R-P2: statement logging with parameters must stay off; what Supabase logs by default is `[unverified - training knowledge]` | doc only |

**Mutation pass for this round** (scratch copies of the tree only, a fresh cluster each, none reached the worktree: the marker grep over it was empty; **14 mutants, all killed**):

- *LOW-1:* `A0_WRITE` and `SESSION` no longer take the lock up front: case 9 fails with **7 of 8** parallel verifies `deadlock detected`. Only `SESSION` loses it: case 9b fails (3 of 4 locks deadlock); the first version of 9b let this survive, because a lock is too quick for a plain race to overlap, so the overlap is now made (each session holds the row lock between its authorize and the lock's write). The verify wrapper reverted to `A0`; the email-proof wrapper reverted to `A0`; the reauth wrapper reverted to `A0`: each fails the two structural cells.
- *MEDIUM-1:* the set does not clear; the change does not clear (each also killed by the Deno suite run against a real cluster); the change clears on every outcome (a wrong current key spends the proof); the set clears on every outcome (`already_set` spends it).
- *N1, N2:* a grant of `EXECUTE` on the core to a role outside the list (`pg_monitor`) fails the exact-ACL cell, which the older role-list cell could not see; the A2 age moved from 30 to 35 s fails only the new 31 s cell.
- *N3 to N5:* `shouldCreateUser: true`; the `DDMM` branch removed; `pin` added to the keys `pin/change` accepts.
- **What this round does not prove.** There is no parallel-run case for the reauth wrapper (each call needs its own real assertion): it is covered by the class cells and by sharing the verify's lock path, not by its own deadlock case. `partner_session_revoke_for_partner` is not run in parallel either; it shares class `SESSION` with the lock that is. Spending the proof is tested for the PIN set and change only: no other route consumes it yet.

**Verification of the whole tree after this round:** both harness modes, run one after the other through the real `tools/db/test.sh` (`superuser` on ports 5731 and 5732, `restricted` on 5733 and 5734): each 41 pgTAP files, **4330 tests, PASS** (4305 before; matrix 28 is 204 tests, was 179), the serialisation script's cases 7 to 9b pass, the Deno integration suite **355 passed, 0 failed** (354 before), `verify-function-inventory` OK, service-role lint clean. Unit suite 65 files, **1326 tests** (1324 before); the pure Deno suite **78 passed**; `pnpm -r typecheck` exit 0; `deno check --frozen` over `partner-session/index.ts` exit 0; `check-migrations-immutable.sh --base f8a85f7`: OK, 49 files (see the note below for `origin/main`); gitleaks over `f8a85f7..HEAD`: no leaks.

**Merged with `origin/main` (`9f7c362`: 0050 DB hygiene, the Apple runbook).** A merge, not a rebase; `f8a85f7` (main's squash of S1.2) was first recorded as history with a `-s ours` merge so the merge base is proper. Two conflicts, both at the ends of files that each side appended to:

- **This document.** Both end-of-document sections are kept: main's "As built: DB hygiene (migration 0050)" sits after 18.9 (where it follows section 18 on main), then section 19. It is unnumbered on main and stays so; nothing collides and no cross-reference changed.
- **`definer_policy_exprs.txt`.** 0050 made every partner conjunct on a `private_definer` policy the InitPlan form `(SELECT private.partner_binding_kind())`. 0052's two delete-window policies on `app.partner_pin` were written in the direct-call form, so they are **converted in 0052** (0052 is not on main, so it is edited in place; no other direct call existed in it), and matrix 28's "top-level trailing AND" cell now expects the InitPlan deparse. The fixture was **regenerated from a freshly migrated cluster** with its header query (with the `role_name` addition), not hand-merged: it equals main's file plus exactly the five 0052 rows (compared as parsed objects: the older `role_name` rows carry the key last and a fresh `jsonb` puts it second, which is only an ordering difference).

**Verification of the merged tree:** both harness modes, one after the other (ports 5731/5732, then 5733/5734): each 42 pgTAP files, **4368 tests, PASS** (main's `30_db_hygiene.sql` is the new file); the serialisation script (cases 7 to 9b) passes; the Deno integration suite **360 passed, 0 failed**; `verify-function-inventory` OK; service-role lint clean. Unit suite 68 files, **1361 tests**; `pnpm -r typecheck` exit 0; the pure Deno suite 78 passed; `deno check --frozen` over `partner-session/index.ts` exit 0; `check-migrations-immutable.sh --base origin/main`: OK, **50 files** byte-identical; gitleaks over `origin/main..HEAD`: no leaks; no mutation marker in the tree.

## 20. As built: S7a

### 20.1 What was built

The first real version of `apps/partners`, the staff, operator and admin portal PWA: **the shell, passkey sign-in and the session**. It is a static bundle that talks to the S1.2 `partner-session` function and to nothing else.

- **Package.** `@golfraven/partners` with real `build`, `typecheck` and `test` scripts, wired into `pnpm -r`. Plain TypeScript bundled by esbuild into `dist/` (`index.html`, one hashed script, one hashed stylesheet, the manifest, an icon and a generated `_headers`). No service worker.
- **API client** (`src/api/client.ts`) for every S1.2 route (`options`, `verify`, `session`, `sign-out`, `lock`, `reauth/options`, `reauth`), plus `call()` for later screens' authenticated calls to other partner functions. The token is one closure variable and is never returned to a caller. Every request sends exactly `Content-Type: application/json`, uses `credentials: "omit"`, refuses redirects, is `no-store` and sends no referrer. Errors are `PartnerApiError` with a closed `kind` (the uniform 401, 403, `reauth_refused`, 415, 429 with `Retry-After` when readable, 400 and 413, 404 and 405, 503, 5xx, network, malformed response).
- **Sign-in** (`src/auth/sign-in.ts`, `src/webauthn/assertion.ts`): `POST options`, `navigator.credentials.get`, `POST verify`, then `GET session`. The page **refuses options that weaken the ceremony** (`userVerification` must be `required`, `allowCredentials` must be empty) before it calls the browser. The assertion is serialised by hand into the exact shape the server's strict parser takes; `PublicKeyCredential.toJSON()` is not used.
- **Signed-in home** (`src/ui/render.ts`): the session as the server reports it (assurance level against the required one, times, roles with facility and trail counts), refresh, **lock** and **sign-out**. A reload is a fresh controller and lands on sign-in.
- **Reauth helper** (`src/auth/reauth.ts`): exported, with no screen of its own; the Playwright suite drives it through a harness page that is built only for that suite.
- **Strict CSP** (`scripts/lib/csp.mjs`), emitted as the `_headers` response header **and** as a `<meta>` (the meta form without `frame-ancestors`): `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src <API origin>; manifest-src 'self'; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'`. The DOM is built with `textContent` only, so the page satisfies Trusted Types.
- **Build-output scan** (`scripts/lib/scan-output.mjs`), the last build step: an inline script, an event-handler attribute, a `javascript:` URL, an inline style, `eval`, `new Function`, `innerHTML` and the other markup sinks, any storage API, `console`, `credentials: include`, a service worker, a source map, a harness in a production build and any origin that is not the API's all fail the build.
- **i18n**: `en` and `fr-CA`, the same shape as apps/mobile (`MessageKey`, `{placeholders}`, plural keys, a parity test).
- **Step-up seam** (`src/auth/step-up.ts`): an interface and a fail-closed placeholder, not an implementation (20.5).
- **CI**: no new job. `pnpm -r test` already runs after the existing Chromium install, and `@playwright/test` is pinned to the same 1.56.1 as apps/site, so one browser serves both; only a comment in `ci.yml` changed.

### 20.2 The stack, and why

**Plain TypeScript and esbuild 0.27.7; no framework, no runtime dependency.** The page is a few dozen DOM nodes and a handful of fetches, and its job is to be auditable under a CSP with no inline script, no eval and Trusted Types required. A framework adds a runtime that ships to the browser, an inline-script or `new Function` risk, and a supply-chain surface the design (section 7) is trying to keep small. apps/site uses Astro 5, but Astro's value there is a content-routed multi-page site, which this is not. esbuild was **already in the lockfile** (vitest 5 uses it through Vite 8), so the lockfile gains **one importer entry and no package**. Every devDependency is pinned exactly and already resolved in the lockfile: `esbuild` 0.27.7, `typescript` 5.9.3 (as apps/site), `vitest` 5.0.1, `@playwright/test` 1.56.1, `csp_evaluator` 1.1.8, `@types/node` 26.6.2. A test fails if a `dependencies` block appears or any `src/` import is not relative. pnpm 10 prints "Ignored build scripts: esbuild"; esbuild's own postinstall is an optimisation, its binary comes from the platform optional dependency, and the build runs.

### 20.3 Brief item, fix, test

| Brief item | Fix | Test |
|---|---|---|
| **1. Package** | real `build` (esbuild + scan), `typecheck` (two tsconfigs), `test` (vitest then Playwright) | `pnpm -r build`, `pnpm -r typecheck`, `pnpm -r test` |
| **2. Strict CSP** | one generator, two carriers (header and meta); Trusted Types required with no policy allowed | `csp.test.ts` (the exact policy, no unsafe or wildcard token in any directive, header and meta forms, `csp_evaluator` with **no finding up to MEDIUM** and a control that it does flag a weak policy), `build-output.test.ts` (a real build scanned, plus 38 must-fail fixtures), `source-scan.test.ts`; Playwright: the page header equals the generated CSP |
| **2. The CSP is enforced, not just present** | a probe page served under the same header | Playwright: eval, `new Function`, a string timer, `innerHTML`, script text, a `data:` script, a foreign origin, a Trusted Types policy and an inline style attribute all fail; a second probe proves an inline `<script>`, an inline handler, a `javascript:` link and an inline `<style>` do not run |
| **3. API client** | the closure token, exact `Content-Type`, `credentials: "omit"`, typed errors | `client.test.ts` (every route's method, URL and body; every request's exact headers and credentials mode; the error table; `Retry-After` in seconds and as a date; the token never returned, in a URL or in an error; storage spies), `contract.test.ts` (the **real** handler accepts every request, behind a browser-like CORS fetch), Playwright (the server's log: exact media type, an `Origin`, a Bearer only on session routes, **no cookie on any request even with an ambient cookie set for the host**) |
| **3. API origin at build time** | `GOLFRAVEN_PARTNERS_API_BASE` (the functions root), a `.example` placeholder default, refused in a production build | `csp.test.ts` (https only, no credentials, query or fragment; loopback http for the e2e build only; production refuses the placeholder), `build-output.test.ts` |
| **4. WebAuthn sign-in** | `getAssertion` with the server's options, refusing weakened ones | `webauthn.test.ts`, `contract.test.ts` (six tampered assertions are the one 401), Playwright (a real Chromium virtual authenticator, resident key, user verification) |
| **4. Home, sign-out, lock, reload** | a DOM-free controller; the client wipes the token; a reload is a fresh closure | `controller.test.ts`; Playwright: after lock and after sign-out the token is gone from the page's **V8 heap** (with a positive control that the search finds it while signed in); a reload lands on sign-in and sends **no request** until a new tap |
| **4. The token is in no storage API** | the client imports none; the bundle names none | `client.test.ts` and `controller.test.ts` (Proxy spies on `localStorage`, `sessionStorage`, `indexedDB`, `caches`, `cookieStore`, `document.cookie`, `navigator.serviceWorker` and every `console` method: **zero calls**, with a control that the spies record), `source-scan.test.ts`, the build scan; Playwright: every store is empty after sign-in, `storageState({ indexedDB: true })` is empty and does not contain the token, and the app exposes nothing on `window` |
| **5. Reauth helper** | `reauthWithPasskey` | `contract.test.ts` (window opened; a refused assertion is 403 `reauth_refused` and the session **survives**; a dead session is 401 and wipes the token; 429), Playwright harness page |
| **6. i18n** | `en` and `fr-CA` | `i18n.test.ts` (parity, placeholders, plurals, French not copied), Playwright (toggle, `lang` attribute, zero violations) |
| **7. Out of scope, with seams** | the step-up interface; no service worker | `step-up.test.ts` (every request rejects, and the file contains no PIN handling); the build scan fails on a service worker file |

### 20.4 Departures from sections 4.6 and 12.1, and why

- **The CSP is stricter than 4.6's list in three places.** `connect-src` names **one path-scoped source per partner function** (`https://<host>/functions/v1/partner-session/`, see 20.11) and not `'self'` or the whole API origin (the page fetches nothing from its own origin; the manifest and icon load under `manifest-src` and `img-src`); `img-src` has no `data:` (nothing needs it); `worker-src` is `'none'`, not `'self'` (no service worker in S7a). Trusted Types is `require-trusted-types-for 'script'` plus `trusted-types 'none'`, so no policy can be created and none is needed.
- **Lock revokes the session (gate ruling, Opus security gate on S7a; supersedes the "as built" lock of 20.4 and 20.10).** The page's `lock()` now **sends `POST sign-out`** (sign-out alone is enough; the server's `lock` route is not called) and shows "Locked". The UI wording is unchanged; the effect on the server is a **revoke**. Precisely:
  - **Order (MEDIUM-2).** Lock and sign-out copy the token into a local variable, **wipe it and notify the listeners (the screen goes to sign-in) before anything is sent**, then send with the copy and drop the copy as soon as `fetch` has been called. The screen is therefore signed-out, and the page holds no copy of the token, while a revoking request that never answers is still hanging (Playwright: a `POST sign-out` that is received and never answered, then a V8 heap search for the token: absent, with the positive control that it was present while signed in). If the request fails or times out the plain notice is replaced by the honest "the server could not be told" one, and only if nothing newer has happened. Lock and Sign-out stay enabled while a refresh is busy, and a wipe aborts every authenticated request still in flight.
  - **Why.** The passkey proves the device, not the person (4.1), the in-memory token is stealable by a script on the page (4.6, mitigated by the CSP and not removed), and a locked-but-live session is a valid bearer for up to its idle window, which the old lock itself restarted. Revoking closes that window at the lock. The cost, accepted: **a lock is no longer cheap to undo** (resuming is a full passkey sign-in, as it already was; it now also opens a new session rather than leaving the old one idle).
  - **Cell.** After a lock the old token is refused by the real handler (`server.state.revokedSessions.size === 1`, the old bearer gets the uniform 401): `contract.test.ts`, `controller.test.ts` and the Playwright lock cell.
  - **Server follow-up, NOT in this slice (no database or migration change here):** retire `private.partner_session_lock_for_partner` (0049) **or** make it revoke with `revoke_reason = 'lock'`; and **any non-revoking lock that remains must authorize as PEEK** (a lock that clears grants but keeps a live session must not count as activity and restart the idle clock, as the 0049 function does today). Until then the `lock` route stays callable by a future client but this page does not call it.
  - What was here before (the old "wipe only" lock, its server-side effect on `pin_grant_until`, `reauth_until` and `otp_proof_until`, and the three options put to the gate) is kept in git history at `41cfbfd`; option (2) was chosen.
- **The page refuses sign-in options that weaken the ceremony.** The server sets `userVerification: "required"` and an empty `allowCredentials` (6.2); the client does not trust that blindly and never calls the browser for anything else.
- **`GET session` follows every sign-in**, so the home screen shows what the server computed rather than what the client assumed (the aal and the required aal are shown side by side).
- **Enrolment, the PIN and invite acceptance are not built**, as the brief says; the section 12.1 S7 acceptance line is met in part (20.5).

### 20.5 Seams left for later slices

- **S1.3, PIN and step-up.** `src/auth/step-up.ts` exports `StepUp.requirePin(actionClass)` and `unavailableStepUp`, which rejects every request, so a screen that needs a PIN before the derivation contract lands fails closed. The browser PBKDF2 derivation, the salt route and the prompt are S1.3's. The S7 acceptance clause "the PIN prompt appears for every A1 action and the PIN is derived in the browser (the request body never contains it)" is **not met by S7a and is carried to S7b**, where the first A1 screen exists. The other clauses (the app works under the CSP with no inline script and no eval, the token is absent from every storage API after sign-in, a reload requires a passkey tap) **are met and tested here**.
- **S1.5, enrolment and invites.** Pre-session routes, added beside `signInOptions` in the client.
- **S7b to S7d, screens.** `render.ts` draws the signed-in home; a screen is a new `AppState` branch and `api.call(...)`. `call()` accepts only a closed function-name and route shape, because it attaches the bearer.
- **S1.4, TOTP.** The home already shows when `aal` is below `requiredAal` and says most screens stay closed.
- **Service worker.** None, on purpose (README). If one is ever added it must never cache API responses or touch the token, `worker-src` must be widened, and the build scan's service-worker rule revisited on purpose.
- **Operator steps at deploy** (none is code): build with the real `GOLFRAVEN_PARTNERS_API_BASE`; serve `dist/` from the partners origin on a host that applies `_headers`; the page's origin must equal `GR_PARTNER_ORIGIN` and `partner_rp_config.origin` (18.4). The partners domain and the API host are still open question Q1.

### 20.6 Findings

- **`Retry-After` was not readable by the page; fixed in the follow-up commit.** The S1.2 server sent `Retry-After` on a 429 but no `Access-Control-Expose-Headers`, so a cross-origin page read `null` (observed in real Chromium and in the node contract test). `_shared/partner/cors.ts` now adds `Access-Control-Expose-Headers: Retry-After` (that header only) to every response for the allowed origin; a foreign or absent origin gets none. Tests: a handler unit cell (200, 401, 400, 415, 204 and 429 all carry it; foreign and no-origin do not), the Deno integration cells (`partner-session.deno.test.ts`: preflight and the reauth 429), the contract test and the Playwright harness cell (`retryAfterSeconds` is now `1800` in a real browser). The client still parses it only when present, and the UI falls back to a generic wait message otherwise.
- **A lock that does not revoke** (20.4, "Lock wipes the client's token"): worth an explicit owner or gate decision.
- **The Chromium virtual authenticator is not an iPad.** What it proves is the page's own behaviour under a real WebAuthn stack: the options pass-through, the serialisation, the real signature the real handler verified. It does not prove Safari's behaviour, a platform authenticator's passkey sync, or the shop-iPad passcode flow.

### 20.7 Verification run for this slice

Toolchain Node 24; `pnpm install --frozen-lockfile` clean after the one importer entry (no new package in `pnpm-lock.yaml`).

- `GOLFRAVEN_DEMO=1 pnpm -r build` and `pnpm -r typecheck`: exit 0 (apps/partners builds and scans its output; both of its tsconfigs are clean, the test one including the cross-imports of the real server handler).
- **apps/partners**: vitest **11 files, 295 tests, all pass**; Playwright **1 file, 22 tests, all pass** (Chromium 141 from `/opt/pw-browsers`, `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1`, no `playwright install`); the Playwright suite was run three times in a row with the same result.
- Unaffected suites: apps/site **10 files, 264 tests** (its own Playwright run exit 0); apps/mobile **65 files, 1967 passed, 6 skipped** on the first run; packages/catalog 153, matching 93, rules 443, import 150 (1 skipped), tools/catalog 378 (1 skipped), tools/p0 699, tools/service-role-lint 427, apps/signup-worker 205.
- `pnpm --filter @golfraven/rules exec vitest run --config ../../supabase/tests/vitest.config.ts` (the `ci-function-lists` pins and the rest of the server unit suite): **63 files, 1269 tests**, the same count as 18.7.
- gitleaks over `f8a85f7..HEAD`: no leaks. Personal-data grep over every added line (emails, phone numbers, home-directory paths, PEM fences, JWT-shaped strings): clean. The only values that look like secrets are built at run time (a `gr_ps_` token is assembled from a repeated character; a URL with credentials is built with `URL.username`).
- Mutation-marker grep over the worktree: empty before every commit.
- **A flake to know about, not caused by this slice**: two later runs (`pnpm -r test` in parallel, then apps/mobile alone) failed 2 to 3 apps/mobile tests in `metro-cache-version.test.ts` and `metro-guard.test.ts` with `Test timed out in 5000ms`, while the machine's load average was 15 from other sessions' Postgres jobs; the same suite passed on an earlier run with the same mobile code. Those tests spawn metro processes and are load-sensitive. Every apps/partners suite passed in both of those runs.

### 20.8 Mutation pass

Scratch copy of the tree under `/tmp` only (the mutation-marker grep over the worktree was empty before every commit). **56 effective mutants, all killed after the fixes below**; the first pass killed 51 of 55 and found four things.

| Group | Mutants (each killed) | Killed by |
|---|---|---|
| Token to storage | `localStorage.setItem`, `sessionStorage.setItem` and `document.cookie` written on verify | the storage-spy cells in `client.test.ts` and `controller.test.ts` (the spies record the write and the cell fails), `source-scan.test.ts` ("no localStorage / cookie anywhere in src/"), the build scan (the build aborts), and the Playwright storage cells |
| `credentials` mode | `credentials: "include"`; the option dropped | `client.test.ts` ("every request omits credentials"), the source scan, the build scan |
| CSP weakened | `'unsafe-inline'` and `'unsafe-eval'` added to `script-src`; `connect-src` widened to `*`; `require-trusted-types-for` dropped; `default-src 'none'` to `'self'`; the CSP dropped from `_headers` | `csp.test.ts` (the exact-policy pin, the token scan and `csp_evaluator`), `build-output.test.ts` |
| Content type | a `charset` parameter added; `text/plain`; absent on GET | `client.test.ts` (exact header, one spelling), `contract.test.ts` (the real handler answers 415) |
| Error mapping | 401 to forbidden; `reauth_refused` folded into forbidden; 429 to server; 415 to bad_request; 503 to server; `Retry-After` ignored; `Retry-After` read as milliseconds | `client.test.ts` error table and `Retry-After` cells, `messages.test.ts`, `contract.test.ts` |
| Token lifecycle | lock does not wipe; sign-out wipes only on success; a 401 does not wipe; a malformed token kept; the token returned to the caller; the token in a URL; redirects followed; the `call()` path guard removed; lock does not tell the server | `client.test.ts`, `controller.test.ts`, `contract.test.ts` |
| Ceremony | UV `preferred` accepted; a pinned credential list accepted; the request sends UV `preferred`; the challenge length unchecked; a non-canonical base64url accepted; padding kept; an empty user handle sent; `NotAllowedError` reported as a failure; reauth uses the sign-in options route; the server's challenge token dropped | `webauthn.test.ts`, `base64url.test.ts`, `contract.test.ts` |
| UI and page | `innerHTML` in the DOM builder; the client exposed on `window`; the locale persisted in `localStorage`; a `sessionStorage` read at boot; a `console.log` of an error; an inline `<script>` added to `index.html`; the harness built without the e2e flag | the source scan, the build scan (the build aborts), and Playwright (the app's `window` keys equal those of a blank same-origin page) |
| Build and config | the scanner stops looking for `eval`; for `localStorage`; the scanner allows any origin; a production build accepts the placeholder; the API base accepts plain http | the scanner's must-fail fixtures and `csp.test.ts` |

The four first-pass survivors: **(a)** `credentials: "include"` was a no-op mutant (my pattern hit the doc comment); re-run on the code line, it is killed. **(b)** *Authorization sent on options and verify while a token is held* was a **real gap** (the unit cells only ever called `signInOptions` with no token held): a cell was added. **(c)** *the sign-in path forgets the token after a failed `GET session`* was **equivalent** (a second, redundant forget in the outer catch), so the duplicate was removed; the single surviving site is killed by a new cell that fails the read with a network error and with a 500, not a 401 (a 401 wipes the token itself and would hide the mutant). **(d)** a *token field in the grant held in state* carried a dummy value and so could not match the real token: replaced by an exact-keys cell on the signed-in state. One further mutant (the `GET session` body shape, `isAdmin` unchecked) was added and killed by a field-by-field cell.

Two honest limits of the evidence. The Node and Playwright cells overlap on purpose, so most storage and CSP mutants are killed in more than one layer. And the heap-snapshot cell is a positive-control test (the token is found in the V8 heap while signed in, and absent after lock and sign-out, after a forced GC): it shows the page's JavaScript heap holds no copy, not that no copy exists anywhere in the browser process (its network stack, for one).

### 20.9 `[unverified]`

- **Trusted Types on Safari.** Chromium enforces `require-trusted-types-for`; whether the shop iPad's Safari does is `[unverified]`. An unsupporting browser ignores both directives and the rest of the policy still holds (and the code uses no string sink, so it would run either way).
- **A real passkey on a real device**, including the iPad passcode as user verification and passkey sync (R-P3), is `[unverified]`: only Chromium's virtual authenticator ran.
- **Cloudflare Pages' `_headers` handling.** The build emits the file in Pages syntax and the suite serves the bundle through its own small implementation of the documented rules (every matching block applies, a repeated name is joined with a comma, and the file has no repeated name). That it behaves identically on the real host is `[unverified]` until the first deploy.
- **The `fr-CA` strings** are drafted and not reviewed by a native speaker (the same status as the mobile catalogue).
- **`@simplewebauthn/server`'s options shape** in the fake server was read from the library source in the Deno cache (14.0.3), not produced by running it under node.
- **CI on a GitHub runner.** The Playwright suite uses the Chromium the existing job installs; that it passes there is `[unverified]` until the first CI run.

### 20.10 Pre-gate follow-up: `Retry-After` exposed, lock documented, re-verification

- **`Retry-After`** is now exposed (20.6): `_shared/partner/cors.ts` adds `Access-Control-Expose-Headers: Retry-After` (only that) to the allowed origin's responses. New cells: the handler unit cell (6 statuses carry it; a foreign origin and no origin do not), the Deno integration assertions (the preflight and the reauth 429), the node contract test, and the Playwright harness cell (the page now reads `retryAfterSeconds = 1800` in Chromium). Three mutants against it (header removed; extra headers exposed; exposed to every origin) are all killed.
- **Lock** is documented precisely in 20.4 and the README. Behaviour is unchanged; the gate rules on it.
- **Both harness modes**, sequentially, on a cluster of their own (`PGPORT=5623`, `H2_PGPORT=5624`): `HARNESS_MODE=superuser` and `HARNESS_MODE=restricted` each exit 0, 40 pgTAP files and **4126 tests PASS**, Deno integration **344 passed, 0 failed** (the 20 `partner-session` cells included), function-inventory check OK, service-role lint clean.
- **Server unit suite** (`@golfraven/rules` vitest with the supabase config): **63 files, 1270 tests** (one more than 18.7: the new CORS cell). apps/partners: vitest **11 files, 295 tests**; Playwright **22 tests**.
- **The apps/mobile flake (20.7) is load, not code.** `metro-cache-version.test.ts` and `metro-guard.test.ts` alone, with nothing else running from this session and a load average of about 2.5: **2 files, 15 tests pass**; the whole apps/mobile suite then passed too (**65 files, 1967 passed, 6 skipped**). Under a load average of 9 to 15 (other sessions' Postgres clusters) the same tests timed out at 5000 ms.
- **main** has not moved past `f8a85f7` (`git fetch origin main`, 0 commits ahead), so nothing was merged.

### 20.11 Opus security gate, round 1: 3 MEDIUM, 5 LOW, NITs (all fixed; no database or migration change)

The threat model the gate applied: **a shared shop iPad. The browser must never hold a live bearer, or show a signed-in screen, when the user believes the page is locked or gone.** `_shared/partner/cors.ts` (the one-line `Retry-After` change) had passed and is untouched.

| Finding | Fix | Cells |
|---|---|---|
| **MEDIUM-1** Chromium restored a signed-in page with a live token after Back (`pageshow.persisted`, and Refresh sent the Bearer) | `/` and `/index.html` are `Cache-Control: no-store` (not `/assets/*`); `pagehide` wipes the token and sends a keepalive sign-out; `pageshow` with `persisted` forces signed-out (`src/app/lifecycle.ts`, wired in `main.ts`) | unit: `csp.test.ts` (no-store on the page, none on assets, no request with two `Cache-Control`), `lifecycle.test.ts` (6). Playwright, in a Chromium launched **without** `--disable-back-forward-cache`: `CONTROL 1` (an unfixed page IS restored with a live token), `CONTROL 2` (no-store keeps it out), `OBSERVATION` (see below), the app is signed-out with no Bearer after Back, `DEFENCE IN DEPTH` (the app at a URL that is not no-store IS restored from the cache and is still signed-out, token-free and silent), leaving the page revokes the session |
| **MEDIUM-2** lock and sign-out not immediate; no timeouts | copy, wipe and notify **before** sending, send with the copy and drop it; `AbortSignal.any([AbortSignal.timeout(15000), caller])` on every request with fallbacks; a wipe aborts in-flight authenticated requests; Lock and Sign-out never disabled by a busy refresh | unit: `client.test.ts` (ordering, hung request, timeout, both fallbacks, abort on wipe, a late 401 of an old session), `controller.test.ts` (the screen is signed-out synchronously with a hung request; a stale refresh cannot overwrite a new session). Playwright: a `POST sign-out` that never answers leaves the screen locked and **the token out of the V8 heap at once**; a `GET session` that never answers leaves Lock and Sign-out clickable and working; the **15 s timeout fires** in a real browser |
| **MEDIUM-3** `connect-src` named the whole API origin | one **path-scoped** source per partner function, `https://<host>/functions/v1/partner-session/`, from `src/api/partner-functions.json` | unit: the exact policy, the reference model of CSP3 path matching (a trailing-slash source is a prefix: every URL the client builds is allowed; the data API, another function, the bare function name, a lookalike prefix and dot segments are not). Playwright: a probe page under the real header: `partner-session/*` works, `/rest/v1/...`, `other-fn`, the bare name, `partner-sessionx` and dot-segment escapes are **blocked by the CSP and never reach the server** |
| **LOW-1** `GOLFRAVEN_PARTNERS_E2E=1` accepted in production | refused by `build.mjs` and by `resolveApiBase` | `build-output.test.ts`, `csp.test.ts` |
| **LOW-2** "every import is relative" was a regex | esbuild's `metafile.inputs`: every input under `src/` (or the e2e harness), none under `node_modules`; enforced by the build itself | `bundle-inputs.test.ts`: a side-effect `import "pkg"`, a dynamic `import("pkg")`, a re-export and a `require` each fail (and two of them are invisible to the old regex, asserted); a scratch project whose build fails |
| **LOW-3** `call()` attached the bearer to any function name | explicit allow-list, the same list as the CSP | `client.test.ts` |
| **LOW-4** Cancel after the passkey step kept the session | a cancel signal reaches `verify()`, which does **not** abort the request (a session the server already minted would be orphaned): on a late answer it revokes the new token with a copy and never holds it; `cancelSignIn` leaves `signing-in` at once and drops any held token | unit (3), Playwright: verify delayed, Cancel pressed, ends signed-out and `revokedSessions.size === 1` |
| **LOW-5** verify succeeded, `GET session` failed, token forgotten but session left live | a best-effort sign-out (wipe first) before the error is shown | unit (3), Playwright |
| **Lock ruling** | see 20.4: lock sends `POST sign-out` | `contract.test.ts`, `controller.test.ts`, Playwright (old token gets 401, `revokedSessions.size === 1`) |
| NIT 429 | the sign-in button is disabled for `retryAfterSeconds` (capped at a day) | unit (4), Playwright |
| NIT production host | rejects a trailing dot, case variants, the bare `.example` TLD, `localhost`, `*.localhost`, loopback and every bare IP (v4 and v6) | `csp.test.ts` |
| NIT `verify()` overwrite | throws `bad_request` / `session_exists` before sending; a second verify that finishes late revokes its own copy | `client.test.ts` |
| NIT HSTS | `Strict-Transport-Security: max-age=31536000; includeSubDomains` | `csp.test.ts`, Playwright |
| NIT `camera=()` | commented in `csp.mjs` and the README: it becomes `camera=(self)` with S7b | (comment) |

**Found on the way, not in the gate's list**

- **A live token stayed in the V8 heap after a cancelled or failed sign-in.** `TOKEN_RE.test(token)` leaves the matched input alive in V8's per-realm last-match info (the heap snapshot's retainer path was `NativeContext -> regexp_last_match_info -> the token string`) until some later regular expression happens to overwrite it; on a normal sign-in a later regexp did, on the new failure paths none did. The shape check no longer uses a regular expression. Cells: the Playwright heap checks of LOW-4 and LOW-5 (killed by re-introducing the regexp).
- **The bfcache observation, honestly.** In Chromium 141 (Playwright 1.56.1, `chromium-1194`) `Cache-Control: no-store` on the page **does not by itself** keep a page out of the back/forward cache: a no-store page that made no API call IS restored (the `OBSERVATION` cell pins that). What keeps `CONTROL 2` (and the real app) out is the combination: the page is no-store **and** it received no-store API responses (every `partner-session` response is no-store). That is a browser heuristic, not a guarantee, which is why the `pagehide`/`pageshow` handlers are the defence and the header is the second layer; the `DEFENCE IN DEPTH` cell removes the header from the picture. The default Playwright launch cannot see any of this: it passes `--disable-back-forward-cache`, **and** the headless shell build reports `BackForwardCacheDisabledForDelegate`, so the bfcache cells launch the full Chromium (`channel: "chromium"`) with that one switch removed.
- **A reload now revokes the old session** (its `pagehide` sends the keepalive sign-out). The older cell that said the old session "is still live on the server, and unreachable from this page" was updated: it is revoked.

**Not done / `[unverified]`**

- **The target device is an iPad, so Safari/WebKit matters, and no WebKit was available here.** Whether WebKit enters the page into its page cache, whether it honours `Cache-Control: no-store` for that, and whether the keepalive sign-out is delivered when the page is hidden are all `[unverified]`. What does not depend on any of that: the in-memory wipe in `pagehide` and the forced signed-out in `pageshow` are synchronous and local, so a restored page shows sign-in and holds no token; the server-side revoke is the best-effort part.
- A full second passkey sign-in after a V8 heap snapshot in the same page failed once with "The passkey could not be used" in the Playwright harness (cause not isolated), so the hung-lock cell does not repeat a sign-in after its heap checks; the second sign-in while an old revoke hangs is a controller unit cell instead.
- The server follow-up in 20.4 (retire or make revoking `partner_session_lock_for_partner`; any non-revoking lock authorizes as PEEK) is **not** in this slice.

**Verification (this round)**

- `pnpm install --frozen-lockfile`: lockfile up to date. `GOLFRAVEN_DEMO=1 pnpm -r build`: exit 0. `pnpm -r typecheck`: exit 0.
- `@golfraven/partners`: vitest **13 files, 369 tests**; Playwright **38 tests** (22 before this round), run three times in a row with the same result. `@golfraven/rules` with the supabase config: **63 files, 1270 tests** (unchanged).
- **Mutation pass** (each fix reverted in a scratch copy under `/tmp`, never in the worktree; the mutation marker comment was grepped for in the worktree afterwards and found nowhere): 55 mutant runs were each killed by at least one new or updated cell (unit or Playwright). Two mutants survive at one level and are killed at the other, by design: re-introducing the regexp token check survives the unit suite (only the Playwright heap cells can see V8's last-match info) and is killed by LOW-4 and LOW-5 there; and the client-level "verify ignores the cancel signal" mutant survives the Playwright LOW-4 cell (the controller drops the late session itself, so the end state is the same) and is killed by the unit cell. Four first attempts at mutants were not valid (a syntax error, an `else` branch that kept the behaviour) and were redone, not counted. The controls were mutated too: serving the no-store alias without the header turns `CONTROL 2` red, and launching the bfcache browser with the default switch or the headless shell turns `CONTROL 1` and `DEFENCE IN DEPTH` red.

### 20.12 Opus security gate, round 2: PASS, with conditions before pilot

Every finding from round 1 was re-checked against the code and holds. That covers the three MEDIUMs, LOW-1..5, the NITs and the lock ruling. The merges with main (0050, then S1.3) changed only this section's numbering, which was §19 on the branch.

The rulings:

- **The `pagehide` revoke is sound.** It fires only when the document really leaves: a reload, navigating away, closing, or entering the back/forward cache. In each of those the in-memory token is lost by design anyway. In-app actions do not fire it: the language toggle, Refresh, a hash change and `pushState` were probed, with 0 revoked. One case is best effort. A sign-out that cannot be delivered (offline, or the process killed without `pagehide`) leaves the session live until idle expiry, while no page holds the token. That is accepted.
- **LOW-4 is accepted.** Cancel does not abort the in-flight verify. Aborting cannot stop the server minting a session; it would only orphan the session. The late token is revoked with a copy, held for at most the 15 s timeout.
- **Residual LOW: encoded slashes and the CSP path scope.** In Chromium 141, literal `..`, `%2e%2e` and backslash forms are normalised before the CSP check, so they are blocked. **Encoded slashes (`%2F`) pass the CSP**, because the prefix is compared against the decoded path. Such a request reaches the server with its raw path. The partner-session handler matches a closed route map and answers 404. Whether the Supabase gateway or edge runtime decodes `%2F` and resolves dot segments before routing is `[unverified]`. The threat needs a script injection first.

**Pilot gate.** The pilot is blocked until every item below is recorded with pass/fail, the device, the iPadOS and Safari versions, the date and the tester. Run each item on a real iPad, both in a Safari tab and as the installed home-screen PWA.

| # | Check | Expected |
|---|---|---|
| 1 | Passkey sign-in with the device passcode as user verification | Signs in. The passkey sheet does **not** fire `pagehide`/`pageshow`; if it did, sign-in would cancel itself |
| 2 | Sign in, navigate away via the address bar, press Back | The sign-in screen; no Bearer request in the server log |
| 3 | Reload, tab close and navigating away | Each delivers the keepalive `POST sign-out`, including its preflight. On the server: the session is revoked and the old token gets 401 |
| 4 | App switch, sleep/wake, auto-lock, Guided Access (if used) | Record whether `pagehide` fires. If it does, every app switch signs the user out. That is fail-closed, but the owner must know |
| 5 | Lock with Wi-Fi off | "Locked" at once, then the "could not be told" notice |
| 6 | CSP | Zero violations in Web Inspector. A test page under the same header blocks inline script and `eval`. Note whether Trusted Types is enforced |
| 7 | Timeout fallback | The 15 s timeout fires even where `AbortSignal.any` or `AbortSignal.timeout` is missing |

**Named open items before pilot**

- **Staging path probe (the residual LOW above).** Against staging, send `GET` and `POST` to:
  - `/functions/v1/partner-session%2F..%2F..%2F..%2Frest%2Fv1%2F`
  - `/functions/v1/partner-session/..%2F..%2F..%2Frest/v1/`
  - one probe aimed at another function

  Each must get the partner-session handler's 404 or a gateway 400; never a PostgREST or other-function response. Record the result here.
  - The structural fix is a dedicated partners API host that proxies only `partner-*` functions, so `connect-src` can be host-scoped (ties to owner question Q1).
  - Optional hardening: the partner handlers refuse a raw path containing `%2F`, `%5C` or `%2E` with a 400.
- **Auto-lock on `visibilitychange` is a product decision.** Should the shop iPad lock after being hidden for N seconds? A backgrounded tab or an auto-locked screen keeps a signed-in page until server idle expiry. This is not a regression; it is the owner's call.
- **Server follow-up from 20.4:** retire `partner_session_lock_for_partner`, or make it revoke with `revoke_reason = 'lock'`. Any lock that does not revoke must authorize as PEEK. The page no longer calls it.
- **NIT (S1.2 server code):** `ROUTE_METHODS[route]` is a plain object lookup, so `/partner-session/constructor` gives 405 rather than 404. Use `Object.hasOwn` or a null-prototype map the next time that code is touched.
- **NIT:** `no-store` covers only `/` and `/index.html`. If the host falls back to `index.html` for unknown paths, those copies are covered only by the `pagehide`/`pageshow` handlers. Optionally use `/*` with `! Cache-Control` in the `/assets/*` block.

Gate counts, round 2:
- partners: vitest 13 files / 369; Playwright 38.
- Server unit suite: 1305.
- DB harness, both modes: 41 files / 4164 pgTAP, Deno 349 passed / 0 failed.
- gitleaks clean.
- Mutants: 21 of 22 valid killed; 1 equivalent survivor.

## 21. As built: S1.4

### 21.1 What was built

The partner (staff) **operator/admin TOTP factor**: `aal` 2, the five-minute MFA window, and class **A3** enabled.

- **migration `0053_partner_totp_aal2.sql`** (all `CREATE` plus `CREATE OR REPLACE` of `partner_authorize`, `partner_session_lock_for_partner`, and the otp-proof / reauth / `GET pin` wrappers reclassed to `A0_ENROL`; 0001–0052 untouched):
  - **`private.hotp`** (RFC 4226 over `public.hmac`, IMMUTABLE) and **`private.partner_totp_seed_derive`** (Vault secret `partner_totp_key`, fixed-width label `golfraven/partner-totp/v1` ‖ 0x00 ‖ user id ‖ `int4send(seed_version)`; the 0045 / 0052 derive shape). The seed is **derived, never stored**.
  - **`app.partner_totp`**: one row per person (`user_id` PK), `seed_version`, enrolment / confirm state, `last_step` (replay), lockout counters. FORCE RLS; every privilege revoked from PUBLIC, `anon`, `authenticated` and `service_role`; **no Edge or client grant**. Written only by definers owned by **`partner_totp_verifier`** (R5-L1: the only role that may write `aal` / `mfa_until`).
  - **Verifier-owned cores**: `partner_totp_attempt` / `verify_apply` / `enrol_apply` / `confirm_apply` / `mfa_clear` / `reset_apply`. Every counter outcome is a **returned status**, never a RAISE (0020). **`verify_apply` is the only code that sets `aal = 2` and `mfa_until = now + 5 min`.**
  - **`partner_authorize`**: classes **`A0_MFA`** (always reachable at `aal` 1 so an operator/admin can step up) and **`A0_ENROL`** (reachable at `aal` 1 **only while** the person has no confirmed TOTP — PA-20 / PA-28); **A3 enabled** (`aal` 2 and `mfa_until > now()`); A1 / A2 accept A3 as the substitute for a PIN-less elevated member (6.3).
  - **`_for_partner` family**: `totp` enrol / confirm / verify / reset; `partner_admin_enrolment_issue_for_partner` (A3); lock clears `mfa_until` through `partner_totp_mfa_clear`; otp-proof, reauth and `GET pin` reclassed to `A0_ENROL`.
  - **Admin bootstrap (M4):** `private.partner_admin_bootstrap_token` (EXECUTE for nobody: ops SQL session as owner after inserting `admin_user`) and the A3 admin-issue wrapper.
  - **`otp_proof` spend on TOTP enrol/confirm** (19.5 / MEDIUM-1 shape): each wrapper clears `otp_proof_until` in the same transaction on the `ok` outcome only.
- **Edge**, `_shared/partner/`: **`totp-contract.ts`** (HOTP-SHA-1, base32 seed, otpauth URI; Web Crypto only); `ports.ts`, `session-shape.ts` and `session-handler.ts` carry the three routes. The Edge builds the otpauth URI from the seed bytea + params the database returns once; it never sees the Vault key.
- **Routes** on `partner-session` (all POST; a dead session is the one 401 before any work):

| Route | Class | Body | Answers |
|---|---|---|---|
| `POST totp/enrol` | A0_ENROL | `{}` | 200 `{ seed` (unpadded base32), `seedVersion`, `otpauthUrl`, `issuer`, `period`, `digits`, `algo` `}`; 409 `totp_already_confirmed`; 403 without enrolment window or email proof; 503 when Vault key missing |
| `POST totp/confirm` | A0_ENROL | `{ code }` (exactly 6 digits) | 200 `{ confirmed: true }`; 403 `totp_wrong` / `totp_locked` (+ `Retry-After`); 409 `totp_not_set` / `totp_already_confirmed` / `totp_wrong_session` |
| `POST step-up/totp` | A0_MFA | `{ code }` (exactly 6 digits) | 200 `{ mfaUntil, aal: 2 }`; 403 `totp_wrong` / `totp_locked`; 429 `totp_backoff`; 409 `totp_not_set` / `totp_unconfirmed` |

  Every body is length-and-encoding only; unknown keys are 400 before any database work. Refusals the database returns **commit** (failure counters and lockout persist).
- **pgTAP** `supabase/tests/matrix/31_partner_totp_aal2.sql` (plan 84): PA-20, PA-24, PA-28 against an independent seed / HOTP oracle.

### 21.2 Brief item, fix, test

| ID | Fix | Test |
|---|---|---|
| **PA-20** (HOTP, aal, A3) | SQL `private.hotp` = RFC 4226; `verify_apply` sets aal 2 + `mfa_until`; A0_MFA always / A0_ENROL while unconfirmed; A3 needs aal2 + fresh MFA; PIN-less A1/A2 substitution | matrix 31 (RFC / independent oracle, replay, ±1 step, lockout as status, aal 1 refusals, A3 cells); unit `partner-totp-vectors.test.ts` (RFC 6238 Appendix B SHA-1 → 6-digit truncation) |
| **PA-24** (enrol / confirm / reset) | enrol refused once confirmed; first enrol needs enrolment or OTP proof; unconfirmed re-enrol bumps seed; confirm same session only; reset admin-only lite | matrix 31; unit `partner-totp-handler.test.ts` (enrol body, already_confirmed 409, confirm session statuses) |
| **PA-28** (aal 1 enrol window) | A0_ENROL at aal 1 only with no confirmed TOTP; after confirm the same calls refuse at aal 1 | matrix 31 |
| **HOTP RFC vector** | TypeScript `hotpSha1` matches node:crypto reference and the six Appendix B counters | `partner-totp-vectors.test.ts` |
| **Lock clears `mfa_until`** | `partner_session_lock_for_partner` calls `partner_totp_mfa_clear` (verifier-owned) | matrix 31 (and the migration grants assertion) |
| **`otp_proof` spend on enrol/confirm** | wrappers clear `otp_proof_until` on `ok` only (same transaction) | matrix 31 |
| **Edge routes** | strict bodies, status→HTTP map, COMMIT on every status, otpauth assembly, Origin refusal | `partner-totp-handler.test.ts` |

### 21.3 Departures from sections 4 to 6, and why

- **D1. TOTP reset reach is admin-only lite (intentional).** Section 6.4's full higher-role reach rule (which admin may reset which operator/admin, and alerts) is **S1.5**. This slice's `partner_totp_reset_for_partner` is class A3, **admin-only**, target must be a different operator or admin; sessions of the target are revoked. The Edge **port** exists; no public `members/{id}/totp-reset` route is wired on `partner-session` yet (21.4).
- **D2. The Edge assembles otpauth; the database returns seed + params.** Section 6.4's QR is a client concern. The migration returns `seed` bytea once plus issuer / period / digits / algo; `totp-contract.ts` builds the URI. No departure of substance.
- **No other intentional departures** from §4.1 (aal gates / the aal 1 enrol exception), §5.1 (`partner_totp` derived seed) or §6.3–6.4 (HOTP, confirm-in-enrolling-session, A3, admin bootstrap) for what this slice built.

### 21.4 Seams left for later slices

- **S1.5, full reach / reset alerts.** Replace the admin-lite reset with the design's higher-role reach; alert on reset (and related membership events).
- **PA-29, last-membership TOTP delete.** Revoking the last active membership of a user in `admin_user` must delete their PIN but **not** their TOTP; for a non-admin both go. Not built here.
- **Edge public `members/{id}/totp-reset` route.** The database wrapper and the session port exist; the handler has no public path yet.
- **PWA TOTP screens (S7).** Enrol QR, confirm, and step-up prompt; `apps/partners` still shows aal below required on the home and keeps screens closed — no TOTP UI in S7a.
- **Fixture regen** if check / allow-list snapshots need a fresh catalog pass after merge (same pattern as 0050 / 0052).
- **Operator steps at deploy:** provision Vault secret `partner_totp_key` (at least 32 random bytes; without it every TOTP route answers 503) and keep it in the secrets backup; first admin via `partner_admin_bootstrap_token` after `admin_user` insert.

### 21.5 Verification run for this slice

**Honest limit:** the full DB harness (`tools/db/test.sh`, both modes) and matrix 31 were **not** run end-to-end in this documentation pass. Matrix 31 (`plan(84)`) and migration 0053 are on the branch; do not treat pgTAP counts as observed here.

What **did** pass in this environment (Node 24, vitest against the supabase unit config):

| Suite | Result |
|---|---|
| `partner-totp-handler.test.ts` | pass (with `partner-totp-vectors`) |
| `partner-totp-vectors.test.ts` | pass (RFC 6238 Appendix B SHA-1 vectors + otpauth assembly) |
| **Combined** | **2 files, 22 tests, all pass** |

A later harness / Deno integration run should record file and test counts here the way 19.7 and 18.7 do; until then only the unit figures above are claimed.

## 22. As built: S1.5 (database half)

### 22.1 What was built

**Migration `0054_partner_invites_enrolment.sql`** and **matrix `32_partner_invites_enrolment.sql`** (plan 483). 0001-0053 are untouched. The Edge handlers (`partner-invites`, `partner-members`, `enrolments/*`, `credentials`) and the PWA are **not** part of this slice's database half; the seams are in 22.4.

- **Register challenge (5.1).** `partner_challenge_core` / `partner_challenge_verify` gain an 8-argument overload (`ref_kind` 1 byte, `ref_id` 16 bytes, `accepted_at_us` `int8send`, for purpose 2; refs refused for any other purpose). The 5-argument signatures are untouched. The only producer of a register challenge is `partner_challenge_issue_register` (EXECUTE for `partner_session_issuer` alone), called inside the accept definers after every check passed.
- **Reach rule (6.5).** `partner_reach_covers(actor, target)` is conditions (1) to (5) exactly; `partner_reach_covers_org(actor, target, org)` is the same rule for one membership (the member revoke). Neither is executable by any edge role. Registered policies call them: `pst_revoke_partner_member` (the toucher's `UPDATE revoked_at` ONLY, keyed on the binding and the per-membership rule), `ppv_*_partner_pin_reach` (PIN reset), `pd_*_partner_enrolment_token_recover`, `pd_read_partner_credential_bound`.
- **Minter lane** (`edge_partner_minter`, unbound; owned by `partner_session_issuer`): `partner_invite_email_for_token`, `partner_invite_accept`, `partner_enrolment_token_email_for_token`, `partner_enrolment_token_accept`, `partner_credential_register_first`. Every attempt / mismatch outcome is a **status** (PA-14); the order is 6.1's. `register_first` makes the R4-L2 checks from raw bytes (the attestation object is parsed in SQL; `partner_cose_parse` parses the key), refuses an active credential and, for an invite, any other-org membership, records one registration per acceptance, mints the first session (`mint_kind register`, no signature, `enrolment_until` now + 15 min) and evicts beyond three live sessions with `partner_sessions_evict_oldest` (a REVOKE).
- **Partner lane** (`edge_partner`): invite create / list / revoke / branch-E accept; member revoke / recover; PIN reset; org revoke-all (with "every credential created after T"); credential options / register (second) / list / revoke; and `partner_totp_reset_for_partner` under the full reach rule.
- **Last membership (PA-29).** An `AFTER UPDATE OF revoked_at` / `AFTER DELETE` trigger deletes the PIN and, unless the person is an admin, the TOTP. The rule is also in the delete policies, derived from data (no binding, no setting).
- **Purges (9).** Six `purge_partner_*` definers, the 0050 shape (`= ANY (ARRAY(SELECT key ... LIMIT 5000))`), each floor repeated in a policy closed under a partner binding, EXECUTE for `edge_system`.
- **Immutability guards.** `BEFORE UPDATE` triggers on `partner_invite` and `partner_enrolment_token` (an acceptance, a consumption and a revocation are final; the token and expiry never move; attempts never fall; one registration per acceptance). Permissive policies are OR-ed, and an UPDATE passes when the OLD row matches any policy's USING and the NEW row any policy's WITH CHECK; the matrix proved a policy-only design let an accepted invite be rewritten.

### 22.2 Departures from sections 4 to 6, and why

- **The accept definers are owned by `partner_session_issuer`, not `private_definer`.** Matrix 25 M1 (a S1.1a gate finding) says `private_definer` sees no invite without a binding, and an unbound minter transaction has no binding. Owning them as the issuer (like the 0048 mint and the 0049 minter-lane definers) keeps M1 and puts the writes under role-specific `psi_*` policies. The issuer therefore gained registered privileges on the invite, token and membership tables (columns only), the COSE parser, the register challenge verifier / issuer, the audit writer and the eviction (all in `partner_owner_privilege` and its fixture). `auth` stays unreachable for it: `partner_auth_identity` (a `private_definer` helper) reads the email, the confirmed flag, the GoTrue session's freshness and the admin flag; `private_definer` gained `SELECT (email_confirmed_at)` on `auth.users`.
- **Membership activation is the issuer's, and only against an accepted invite.** `psi_insert_partner_member` / `psi_update_partner_member` admit a row only when an invite accepted by that user for that org and role (same inviter) within the last two minutes exists. A bound `private_definer` still cannot touch a membership row (PA-4c (i)); matrix 25's "no lock policy on `partner_member`" cell now names these two policies as the only exceptions.
- **The member revoke is the toucher's** (`UPDATE (revoked_at)` ONLY, so a revoke cannot move a role or an org), keyed on the binding and the reach rule.
- **Adding a second credential uses the reauth-purpose challenge** (purpose 3, bound to the bound session id), because 5.1's register challenge carries `ref_kind` 1 or 2 only. A challenge issued for one session cannot be used from another.
- **`partner_pin_reset_apply`** (owned by `partner_pin_verifier`, policies keyed on the reach rule) also resets the PIN of the person's own row on a branch-E reactivation.
- **Two S1.4 defects were fixed here** (found by the matrix): `partner_admin_bootstrap_token` and `partner_admin_enrolment_issue_for_partner` could never insert (`INSERT ... RETURNING` met no SELECT policy for the new row, and `expires_at = clock_timestamp() + 24 h` violated `expires_at <= created_at + 24 h` against the transaction-start `created_at`). Same signatures, owners and grants; a SELECT policy and explicit `created_at` replace them.
- **Matrix 30 / 20 / 25 / 26 / 27 / 28 / 31** cells that pinned exact lists (the purge set, the `edge_partner` and minter EXECUTE sets, the policies on `partner_pin` and the failure counter, the issuer's function privileges, the `A0` wrappers, the reset message) were updated for the new objects; none was weakened.

### 22.3 Not built here, honestly

- **Single use under concurrency and counter survival after a real COMMIT** are by construction (a row lock, a status, no RAISE) and proved inside one transaction (a second accept is `not_found`; the count is there after a mismatch). A two-connection script in the style of `tools/db/test-partner-serialisation.sh` is not written.
- **Eviction beyond three live sessions runs at `register_first` only.** The sign-in mint (0048) still does not evict; that is the 0048 seam, unchanged.
- **The out-of-band notice of a credential add** (open item U1) and **the operator alert on a TOTP reset** are `audit_log` rows only.
- The create ceremony's key is checked for shape by `partner_cose_parse`, not for being a point on the curve (the sign-in verifier's check): a wrong key would fail every later sign-in, not widen access.

### 22.4 Seams left for the Edge half

`partner-invites`: `POST invites` (`partner_invite_create_for_partner`), `GET invites`, `DELETE invites/{id}`, `POST invites/accept/start` (`partner_invite_email_for_token`), `accept/verify` (`partner_invite_accept`, then close the GoTrue session AFTER it returns), `POST invites/accept` (branch E). `partner-members`: `members/{id}/revoke` (`partner_member_revoke_for_partner(target, org)`), `recover`, `pin-reset`, `totp-reset`, `orgs/{id}/sessions/revoke-all`, `credentials` (options / register / list / revoke). `enrolments/accept/*` (`partner_enrolment_token_*`), `POST credentials` in enrolment mode (`partner_credential_register_first`; the Edge passes the challenge from `accept/verify`, the attestation object and client data as raw bytes, the credential id and the COSE key). `retention-purge` gains six steps. Every status above is committed by the handler.

## 23. As built: S1.5 (Edge half)

### 23.1 What was built

The two Edge Functions and the shared modules behind them; **no migration** (0054 is untouched). `privileged.ts` stays the one database site.

- **`partner-invites`** (`_shared/partner/invites-handler.ts`): `POST invites`, `GET invites`, `DELETE invites/{id}`, `POST invites/accept/start`, `.../accept/verify`, `POST invites/accept` (branch E), `POST enrolments/accept/start`, `.../accept/verify`, and `POST credentials` in enrolment mode (the first credential and the first session).
- **`partner-members`** (`_shared/partner/members-handler.ts`): `POST members/{id}/revoke | recover | pin-reset | totp-reset`, `POST orgs/{id}/sessions/revoke-all`, `POST admin/enrolments`, `GET | POST credentials`, `POST credentials/options`, `DELETE credentials/{id}`. Every route is a session route.
- **Shared**: `handler-kit.ts` (route table with `{id}` uuid segments, the one port-error map, the registration-refusal map), `invites-shape.ts`, `members-shape.ts`, `registration-shape.ts` (strict bodies, canonical base64url, unknown keys refused), `token.ts` (`gr_inv_` and `gr_enr_` tokens beside `gr_ps_`), `ports.ts` (`PartnerInviteMintTx`, `PartnerInvitesTx`, `PartnerMembersTx`, `RegistrationVerifier`, `PartnerInvalidArgument`), `webauthn-port.ts` (`registrationVerifier` over the S0 wrapper's `verifyRegistration` / `registrationOptions`).
- **`privileged.ts`**: every new method is a `select private.*(...)` in 0054's argument order. The minter transaction and the bound transaction carry more methods, not more kinds: `withPartnerMint` and `withPartnerSession` remain the only callers of their kinds (the `privileged-mint-scope` allow-list is unchanged). `retentionPurgeSteps` gains the six `purge_partner_*` steps.
- `supabase/config.toml` (`verify_jwt = false` for both), the three CI function lists, and the unit suites that enumerate partner functions.

### 23.2 Decisions and departures

- **The invite OTP may create the account** (`shouldCreateUser: true`, `partnerInviteEmailOtp`). 6.1 branch N is for a person with no account, and `partner_auth_identity` needs an `auth.users` row, so the plain proof sender (`shouldCreateUser: false`) cannot reach them. The address sent to is always the invite row's, never a client's, so a token holder cannot make an account for an address of their choosing. Enrolment tokens use `partnerEmailOtp` (the person exists).
- **Pre-authentication buckets are `edge_system` buckets** (design 8), through a new `PartnerDb.hitSystemRateLimit` over the existing `hitSystemRateLimit`: 3 sends and 10 code attempts per token an hour, and 3 invites a day per invitee address (a hash). A bucket is hit only for a token that EXISTS, so made-up tokens cannot grow the table. A wrong emailed code never reaches the database, so the 10-attempt counter in 0054 does not see it; the verify bucket is what bounds code guessing beyond GoTrue's own limits.
- **`accept/verify` answers one 403** for an unknown or dead token, a wrong code, a limited token, a GoTrue session without an id and every refusal of the definer; only `existing_member_sign_in` and `recover_required` (reachable by the owner of the mailbox alone) are 409. `accept/start` answers one constant body, including when the mailer fails.
- **`POST credentials` lives in both functions**: enrolment mode (no bearer, minter lane) in `partner-invites`, second credential (session, A2 + reauth) in `partner-members`.
- **The relying party for a second credential is read through the minter** (`withMint(rpConfig)`), because `edge_partner` cannot execute `partner_rp_config_read`; the ceremony is verified with no session transaction open, and only then does the A2 definer run, so its 30-second PIN grant is not spent waiting on the wrapper.
- **`PartnerInvalidArgument`** (22023) maps to 422: an action on oneself or a time in the future is not a 500.
- **`credentials/options` reads the person** (`credentialSubject`: the session's user id for the WebAuthn user handle, and the address for the authenticator's label), because the definer returns neither.

### 23.3 Not built, honestly

- `PATCH credentials/{id}` (the display note): 0054 has no definer for it.
- The per-target "5 failed OTP proofs an hour" counter of 8 (the 0035 reserve / release pair): the per-token verify bucket stands in.
- Deno integration tests against a cluster for these routes (the handlers are proved with fakes; the definers by matrix 32). The retention integration test now expects twelve steps and checks the six partner ones run (`done`), not that they purged a seeded row (matrix 32 seeds those).
- The PWA screens and `apps/partners` client; the out-of-band notice of a credential add (U1) is still an `audit_log` row.
- `gr_enr_` is not on `getActorFromRequest`'s refusal list (it is never a bearer); add it if a bearer use ever appears.

## 24. As built: S7a, second half (PIN step-up, invite and enrolment acceptance; `apps/partners`)

Closes the seams 20.5 left for S1.3, S1.4 and S1.5, now that their Edge routes exist. **No server, database or migration change**: the page is the only thing that moved.

### 24.1 What was built

- **PIN step-up** (`src/auth/pin.ts`, `step-up.ts`, `pin-setup.ts`). The browser derives with the shared contract (19.4): `pin-contract.ts`, `pin-deny-list.ts` and, for the base64url helpers it imports, `token.ts` are imported **by relative path** (not copied), so the browser cannot drift from what the Edge and the database tests run. `scripts/lib/inputs.mjs` allows exactly those three files outside `src/` (an exact-path list; a fourth fails the build; `node_modules` is still refused) and `tsconfig.json` gains `allowImportingTsExtensions` for their `./token.ts` import. `createStepUp` is the real `StepUp`: `GET pin` (a locked, unset or must-change PIN ends the call before any prompt), the prompt, the rule and deny-list check **before** any derivation, PBKDF2 with the stored salt and iteration count, `POST step-up/pin { derived }`. The controller exposes it as `requirePin(actionClass)`; `unavailableStepUp` stays exported.
- **Set, change and the email proof**: `pin/set`, `pin/change`, `otp-proof/start`, `otp-proof/verify` (6.3), with a fresh CSPRNG salt and the contract's default 600,000 iterations. The first PIN after an enrolment is forced (6.1 step 5).
- **Invite and enrolment acceptance** (6.1 branch N): client methods `acceptStart`, `acceptVerify`, `registerFirst` beside `signInOptions`; `src/webauthn/registration.ts` (`navigator.credentials.create` for the server's options, refused if they weaken the ceremony; serialised into exactly the strict shape `registration-shape.ts` accepts); the enrolment flow (token, emailed code, passkey, first session, forced PIN); the invite link (`/invite#<token>`, the fragment removed from the address bar on load).
- **TOTP** (6.4), the nice-to-have: enter a code (`step-up/totp`) or add an authenticator (`totp/enrol`, `totp/confirm`) when `aal < requiredAal`. The seed is shown once as text (and the `otpauth://` link); there is no QR renderer, because no dependency may be added.
- **CSP and client allow-list**: `partner-functions.json` is now `partner-session`, `partner-invites`, `partner-members`, so `connect-src` carries three path-scoped sources (the same list is the bearer allow-list of `call()`); `_headers` marks `/invite` no-store. Error kinds `conflict` (409), `gone` (410) and `unprocessable` (422) join the client's closed set (the new routes answer them).

### 24.2 Decisions and departures

- **A PIN the rules refuse is refused at a verify too**, not only at a set. The server cannot tell a denied PIN from another (it sees derived bytes), and 19.4 puts the rules where the PIN is typed. A refused PIN at a verify cannot be a PIN this page ever set; refusing it sends nothing and costs the member no failure against the lockout of 5. The cost: a PIN set by a custom client to a denied value cannot be used through this page until a manager resets it.
- **A hostile or broken server cannot choose the work factor.** `GET pin` iterations outside `[210000, 1000000]`, or a salt that is not 16 canonical bytes, end the call with `bad_params` before anything is derived (a floor below the contract weakens the member's verifier; a ceiling above it is a denial of service on the page).
- **`GET pin` is read before the prompt**, on every loop, so a locked PIN is never asked for and the prompt can show the server's back-off; the deny-list runs before the derivation and the POST.
- **No "check my PIN" button.** A grant that nothing consumes would leave a 60-second window in which whoever holds the iPad could run an A1 action without a PIN. The prompt is reachable only from `requirePin`, i.e. from a screen that makes the action call straight after.
- **`registerFirst` holds the first session's token exactly as `verify` does** (one closure variable, never returned, revoked with a copy if the flow was cancelled while the request was on the wire); the invite token and the emailed code are in the flow's closure only, never in the state, never drawn.
- **The create ceremony starts from a button**, not automatically after the code, so Safari's user-activation rule holds and the options (good for a few minutes) are used on the person's tap.

### 24.3 Not built, honestly

- No screen consumes a PIN grant yet (S7b onward); `requirePin("A2")` does not also run the passkey reauth (`reauthWithPasskey` exists; the A2 screens compose the two).
- Invite create / list / revoke, branch E (`invites/accept` for an existing member), `members/*` and the credential screens are not built; their CSP origins and the `call()` allow-list are in place.
- No QR for the TOTP seed (text only).
- A JavaScript string cannot be wiped: the four digits stay in the page's heap until collected (measured: a V8 heap snapshot after a set still finds them; the invite token and the session token are gone once their flow ends). The guarantee is the one the design needs: the digits are in no request, URL, header, storage, console or controller state.
- `[unverified]`: PBKDF2 at 600,000 iterations on a low-end iPad (S0 owns the measurement), and the French strings (not reviewed by a native fr-CA speaker).

### 24.4 Tests

`pin.test.ts` (the four shared vectors, node's PBKDF2 as an independent oracle, every deny-list entry refused with no key derived, the work-factor and salt bounds), `step-up.test.ts` and `pin-setup.test.ts` (the real `partner-session` handler over the fake: the request body is exactly `{ derived }`, the PIN's digits in no request, wrong, back-off, lock, unset, must-change, hostile parameters), `registration.test.ts` (options strength; the serialised ceremony accepted by the server's own `parseEnrolCredentialBody`), `client-enrol.test.ts`, `enrol.test.ts` (token, code, passkey, first session, forced PIN, and the credential the page created **signs in afterwards**), `panels.test.ts` (prompt, set / change, proof, TOTP), plus source-scan, CSP, build-output and bundle-input cells. The Playwright suite adds six cells in real Chromium under the real CSP (invite link to first PIN, the PIN prompt, zero violations, nothing in storage, no PIN digits on the wire). `fake-partner-server.ts` now runs the real `partner-invites` handler with working in-memory PIN, email proof, TOTP, enrolment and a registration verifier that parses the attestation object.

## 25. As built: S2b (the staff lane of the course QR)

Slice S2b of P5.1a: the staff half of a marker purchase. The player half is S2a (`marker-scan`, migration 0046); this slice **mints** what S2a verifies, shows and rotates the PIN S2a judges, and signs and registers the printed QR. Migration `0055_course_qr_staff.sql` is the database half; `course-qr` and `qr-print` are the Edge half. Migrations 0001 to 0054 are untouched (`tools/db/check-migrations-immutable.sh`).

### 25.1 What was built

**Database (0055).** Seven `edge_partner` `_for_partner` definers (each begins with `private.partner_authorize`, check 14; none has a dollar sign, double quote or backslash in its body: check 14 (a0)) and one internal reader:

| Definer | Class | What it does |
|---|---|---|
| `course_pin_show_for_partner(facility)` | A0, staff or manager **at that facility** | Calls `private.course_pin_derive` and nothing else derives: the facility-local date of now and `private.course_pin_epoch_at(facility, now)`, exactly the arguments `course_pin_attempt_for_actor` judges a scan made now under. `ok` / `no_facility` / `no_programme` (no accepted, active, `any_purchase` row that takes the printed QR: there is no PIN to show) |
| `course_pin_rotate_for_partner(facility)` | A2, staff, manager or operator at the facility | `UPDATE app.facility_programme SET pin_epoch = pin_epoch + 1` for the facility and nothing else; the 0046 trigger writes `app.course_pin_epoch_log` (this function never names the table: a pgTAP cell reads its source). One `audit_log` row (`partner.course_pin.rotate`, the new epoch, no PIN) |
| `course_qr_mint_for_partner(facility, nonce_hash)` | A1, staff or manager | Consumes the single-use PIN grant, INSERTs `app.course_qr_token (nonce_hash, facility_id, issued_by_staff, kid, issued_at, expires_at)` with `issued_at` **truncated to the second** (so the row's instant is the token's `iat`; the player lane judges the 120 s rule against the row) and `expires_at = issued_at + 120 s`, and returns the kid, the Vault seed and the registered public key **with the row**. `no_programme` (no accepted active `any_purchase` row that takes the rotating token) is a returned status; a missing, malformed, unregistered or revoked key is `55000` |
| `course_qr_refresh_for_partner(facility, nonce_hash)` | **A0_KEEPALIVE**, staff or manager | Reads the state (`live` / `used` / `expired` / `unknown`, with the seconds left) of a token **this person's own mint** created at this facility; any other nonce is `unknown` (one answer: no oracle). Writes nothing, creates no token, and never advances `last_seen_at` (PA-26) |
| `course_qr_print_key_for_partner(facility)` | A3, operator at the facility or admin | Releases the printed-QR kid, the Vault seed and the facility slug to the authorized call. `ok` / `no_facility` / `key_revoked` |
| `course_qr_print_write_for_partner(facility, qr_kid, sig, public_key)` | A3 | Ensures the **public** key row in `app.course_qr_key` (inserted when absent, never replaced: a different key is `key_mismatch`), refuses a kid that is not the Vault key's (`kid_mismatch`) or a revoked key, then writes `app.facility_qr` (a reprint replaces the kid and signature and clears `revoked_at`; the same kid and signature is a no-op and writes no audit row). One `audit_log` row (`partner.course_qr.print`, the kid) |
| `course_qr_print_read_for_partner(facility)` | A0, operator or admin | The registered printed QR: `ok` / `no_facility` / `not_printed` |
| `private.course_qr_signing_key_read(purpose)` | **EXECUTE for nobody but its owner** | The **only** reader of the Vault secrets `course_qr_signing_key_rotating_token` and `course_qr_signing_key_printed_qr` (each `<kid>:<32-byte Ed25519 seed, base64url>`) and of the registered public key. Reached only from the A1 mint and the two A3 print definers, after `partner_authorize` |

Ten new `private_definer` policies, all keyed on `private.partner_binding_kind()` / `partner_binding_user()` (never a settable GUC, never `actor_uid()`), all registered in `private.definer_policy_allowlist` and `supabase/tests/fixtures/definer_policy_exprs.txt`; the 0046 policies (`actor_uid() IS NOT NULL`) never apply under a partner binding and the new ones never apply under a user binding. The column grants are narrow: `INSERT` of the six issue columns of a token (never `used_by_user` / `used_at`), `INSERT` of `(purpose, kid, public_key_b64url)` of a key (never `revoked_at`, no `UPDATE` at all: a revoked key stays revoked), `INSERT` and `UPDATE` of the four reprint columns of `facility_qr` (not its key). No role gained a privilege on a relation except `private_definer`; the six owner roles and `private.partner_owner_privilege` are unchanged.

**Edge.**

| Route | Class | Body or query | Answer |
|---|---|---|---|
| `GET /v1/course-qr/pin?facilityId=` | A0 | the query is strict | 200 `{ facilityId, pin, localDate, validUntil, pinEpoch }`; 403 (no scope), 404 (unknown facility, an admin's question), 409 `no_programme` |
| `POST /v1/course-qr/pin/rotate` | A2 | `{ facilityId }` | 200 `{ facilityId, pinEpoch }`; 403 without a fresh PIN **and** passkey; 409 `no_programme`; 429 (10 an hour) |
| `POST /v1/course-qr/tokens` | A1 | `{ facilityId }` | 201 `{ facilityId, token, link, nonceHash, kid, issuedAt, expiresAt }`; 403; 409 `no_programme`; 429 (**60 a member an hour**, `hit_partner_rate_limit`, before the transaction); 503 (a deploy fault) |
| `POST /v1/course-qr/tokens/refresh` | A0_KEEPALIVE | `{ facilityId, nonceHash }` | 200 `{ state, secondsLeft }`; 403; 429 (1000 an hour) |
| `GET /v1/qr-print?facilityId=` | A0 | strict | 200 `{ facilityId, qrKid, sig, printedAt, revoked, revokedAt }`; 404 `not_printed` |
| `POST /v1/qr-print` | A3 | `{ facilityId }` | 201 (written) or 200 (unchanged) `{ facilityId, qrKid, sig, link, changed }`; 403; 404; 429 (30 an hour); 503 |

`supabase/functions/course-qr/index.ts` and `qr-print/index.ts` are thin; the rules are in `_shared/partner/course-qr-handler.ts`, `qr-print-handler.ts`, `course-qr-shape.ts` (strict, unknown keys refused, no field for a PIN, key, kid or signature: the client chooses nothing the server signs) and `course-qr-signer.ts` (WebCrypto Ed25519). The ports are a **separate** `CourseQrDb` in `ports.ts` (so no existing `PartnerDb` fake changed); `privileged.ts` builds it from the same bound transaction as `withPartnerSession` (`buildCourseQrTx`, `courseQrDb`) and adds `loadCourseQrLinkOrigin()` (`GR_COURSE_QR_LINK_ORIGIN`, an exact https origin: `https://golfraven.<tld>`; unset means the responses carry `link: null`). `supabase/config.toml` has `verify_jwt = false` for both, and the three CI function lists name them.

**The mint, in order.** (1) The member's 60-an-hour bucket, in its own short transaction. (2) 16 random bytes; their SHA-256 is the nonce hash the database stores (never the nonce). (3) **One** bound transaction: the A1 definer consumes the PIN grant, INSERTs the row and releases the seed; the Edge signs the compact JWS exactly as `_shared/course-qr/format.ts` defines (header `{alg, kid, typ}` and payload `{exp, fac, iat, kid, nonce}` in alphabetical order) and **verifies its own signature under the registered public key, inside the transaction**. Any failure (no programme, a seed that is not the registered key's, a throw) rolls the row and the PIN grant back together (a unit test and a Deno test each prove it through the real driver). (4) The token goes to the client once; the seed is a local of step 3, in no response, header, error or log.

**The Vault key, and how it is provisioned.** The private key lives **only in Vault**, one secret per purpose, named `course_qr_signing_key_rotating_token` and `course_qr_signing_key_printed_qr`, value `<kid>:<seed>` (`kid` `[A-Za-z0-9_-]{1,64}`, seed the 32 raw bytes as 43 unpadded base64url characters). `tools/db/provision-course-qr-key.mjs <purpose> <kid>` generates a key pair and **prints the SQL** (`vault.create_secret` plus the `INSERT INTO app.course_qr_key` of the public half) to stdout, to be piped into `psql` as the project's owner role; it writes no file. `--rotate` uses `vault.update_secret` and a new kid. `qr-print` also ensures the printed-QR public row itself, so for `printed_qr` only the Vault secret is strictly required; for `rotating_token` the public row **must** exist before the first mint (the mint refuses with `55000`, a bare 503, otherwise). The public key is never taken from a client. A compromise revocation is `UPDATE app.course_qr_key SET revoked_at = now() WHERE purpose = ... AND kid = ...`; a revoked kid mints nothing at once and is `qr_revoked` in the player lane; after a printed-key rotation, `qr-print` registers each facility under the new kid. In tests the private key is generated at run time (`makeSeed`, never a literal) and, for the Deno suite, written to the Vault stand-in the way an operator would; no test harness injection of a key exists in production code.

### 25.2 Decisions and departures

1. **The refresh does not re-issue.** The design said "bound to a nonce that an A1 mint created, and cannot create new authority". Re-issuing a token on every 30 s heartbeat would create a new single-use authority per heartbeat from one PIN; so the refresh **reads** the state of the person's own token (live, used, expired, unknown, seconds left) and the sale screen tells the cashier when the player has scanned or the 120 s has run out. A new sale is a new A1 mint and a new PIN (X8: PIN per action). If the product wants a continuously-rotating QR, that needs a mint-chain column and a bound on its length and is a separate decision; nothing here prevents it.
2. **Roles.** Show the PIN: staff and manager of that facility (an operator does not read the shop's PIN; an admin does). Rotate: staff, manager or operator (A2: PIN in the last 30 s and a passkey in the last 5 minutes; a PIN-less operator or admin satisfies it with the A3 substitution of 6.3). Mint: staff or manager (an admin with a fresh TOTP may; an operator may not sell a marker). qr-print: operator at the facility or admin, class A3 (a manager cannot print).
3. **A returned `no_programme` rolls back.** A status that commits would spend the PIN grant on a facility that cannot sell a marker, so the handler throws inside the transaction callback and answers 409 outside it. The pgTAP cell documents that the **definer** alone does consume the grant on that path; the rollback is the handler's, proved with the real driver.
4. **The mint requires a registered rotating-token key; qr-print registers the printed-QR key.** Asymmetric on purpose: the A1 call is made by shop staff and must not be able to introduce a verification key, the A3 call is an operator's. The database never verifies an Ed25519 signature (it has none), so `course_qr_print_write_for_partner` records what the Edge signed; the Edge verifies under the public key derived from the Vault seed before calling and the database cross-checks the kid and any existing key row.
5. **Idempotent printing.** Ed25519 is deterministic, so printing again is a no-op (`changed: false`, no audit row, `printed_at` kept); only a new Vault kid replaces a registration.
6. **No change to the session or class machinery.** `partner_authorize` is untouched; `A0_KEEPALIVE` already skipped the idle bump (0047). PA-26 is proved at the database (matrix 33) and through a real commit (Deno).
7. **`service_role` keeps its 0009 DML on `course_qr_token` and `facility_qr`.** Pre-existing and not an Edge path (the Edge never holds the service-role key since PR4b); noted so the cell that says "no edge or client role can write them" is not read as covering it.
8. **The dropped explicit filter that survived mutation.** `course_qr_refresh_for_partner` filters the token by `issued_by_staff = v_uid` **and** the read policy keys on the same; removing the filter from the function is unobservable (the policy still scopes), kept as defence in depth like S2a's explicit actor filter.

### 25.3 Not built, and honest limits

- **The hand-over token** (plan 9.4, `entitlements-collect`) and everything in S5. The `typ` and the key purpose of format.ts keep it apart when it comes.
- **The plan 8.3 cap alert** (25 static-PIN credits per facility per day): still S3's hook after `Repo#markerScan.record`; nothing here reads or counts credits.
- **Scheduled pepper rotation tooling**, a **purge** for `course_qr_token` / `course_pin_alarm` (S2a departure 6 stands), and **a UI** for the PIN alarm.
- **`[unverified]` on a real Supabase project**: that Vault accepts the two new secret names and `vault.create_secret` / `vault.update_secret` as the tool prints them; that `private_definer` can read `vault.decrypted_secrets` for them as it does for the pepper (the harness proves the shim); that the hosted Edge runtime imports an Ed25519 PKCS#8 key and signs (this repository's pinned Deno 2.5.2 does, every test here runs under it); that `GR_COURSE_QR_LINK_ORIGIN` is set (the tool and the runbook do not set it).
- **The seed is on the wire between Postgres and the Edge process for the length of one call**, by the decision to sign in the Edge; it is never stored, logged or returned. A Vault-resident signer (Ed25519 in the database) was not built: PL/pgSQL has no Ed25519, and the S0 spike measured only verification.
- **The PWA screens** (S7b) and a mobile scanner/sender for the rotating token are not built; `MARKER_COSIGNAL_UI_ENABLED` stays `false`.

### 25.4 Tests and verification

Each line is a command run on the final tree.

- **pgTAP, both harness modes, one at a time** (`HARNESS_MODE=restricted tools/db/test.sh`, then `HARNESS_MODE=superuser tools/db/test.sh`, each a full initdb, migrate, seed, pgTAP, concurrency scripts, Deno integration suite, `verify-function-inventory`, `service-role-lint`, teardown): `Files=54, Tests=5262, Result: PASS` in **both**, the Deno integration suite `384 passed | 0 failed` in both (8 of them `course-qr.deno.test.ts`), exit 0. New file `supabase/tests/matrix/33_course_qr_staff.sql` (197 cells): structure and ACLs, the key reader's whole ACL, check 14 (a) behavioural cells for all seven definers (no binding and a user binding), the PIN (independent HMAC, the player lane's gate accepts it, the facility-local date on the far side of the date line, the other facility's, an operator, an admin, a missing pepper), rotation (every programme row, only `pin_epoch` changed, the trigger logged it once, no audit when nothing moved, single-use grant, too-old grant, the old PIN still right for a scan before the rotation and wrong at or after it), mint (grant consumed, rolled-back mint gives it back, `issued_at` on the second, the exact row the player lane's scan accepts then refuses a second time as `qr_used`, scope, programme, each key fault, a duplicate nonce), refresh (own, other's, other facility, used, expired, a planted delete-my-data GUC, **PA-26 with a control that an A0 call does advance idle**, an idle-expired session), qr-print (A3 window, aal 1, scope, public key insertion, reprint, `kid_mismatch`, `key_mismatch`, `key_revoked`, malformed arguments, admin on an unknown facility). Pinned lists updated: matrices 10, 25 and 28 (the `edge_partner` EXECUTE set, the A0 set), 24 (the PIN derivation now has two callers) and the Deno cell PA-13b.
- `tools/db/check-migrations-immutable.sh --base origin/main`: all 52 existing migrations byte-identical, `0055` added. `deno check --frozen` and `deno cache --frozen` over the CI entrypoint list (22 files, the two new entrypoints in all three CI lists) exit 0 and `supabase/tests/deno.lock` is unchanged (WebCrypto only, no new dependency); `deno test supabase/tests/deno-unit/` with `--cached-only --deny-net`: 78 passed. `supabase/tests` vitest: 78 files, 1556 tests, 1553 passed; the 3 failures are `rules-vendor-freshness` (it needs `pnpm -r build` for `packages/rules/dist`, absent in this checkout) and are identical with this slice stashed.
- **Mutants run against the migration** (each: rebuild, run matrix 33): `A0_KEEPALIVE` to `A0`, the mint at `A0`, `issued_at` not truncated, `pin_epoch + 2`, the kid check removed, the show roles widened to operator, a revoked key accepted, the programme check widened to the printed QR: **8 of 8 killed**; the explicit `issued_by_staff` filter removed in the refresh survived (the policy duplicates it, decision 8).
- **Unit** (`pnpm --filter @golfraven/rules exec vitest run --config ../../supabase/tests/vitest.config.ts`): `course-qr-handler` (32), `qr-print-handler` (17), `course-qr-shape` and the enumeration suites (`partner-modules`, `ci-function-lists`, `review-account-gate`). A token minted by the handler is **byte-identical** to `course-qr-test-keys.ts#mintRotatingToken` under the same key (Ed25519 is deterministic), and a printed-QR signature to `mintPrintedQrSig`; the same tokens verify in `format.ts`. A source scan proves no non-test file under `supabase/functions` carries the PIN derivation's label.
- **Deno integration** (`supabase/tests/integration/course-qr.deno.test.ts`, 8 tests, real `privileged.ts`, real sessions, real Ed25519 keys in the Vault stand-in): the committed token verifies under the database's own key row; the player lane's scan consumes the committed row; refused mints roll back through the real driver; scope at fac_y is 403 on every route; PA-26 after a real commit; the PIN equals an independent HMAC and a rotation logs the epoch; qr-print registers a signature `verifyPrintedQr` accepts under the key the database inserted.

## 26. As built: S3 (attest; the offers-redeem half is a documented seam)

Numbering: **migration `0056`, matrix `34`, this section 26.** S2b (the parallel slice, branch `cursor/p5-s2b-course-qr-staff-8ffd`) claims `0055`, matrix `33` and section 25, and S7 claims section 24; this slice takes the next free number of each so the branches merge without a rename. Nothing from 0001-0054 is edited.

### 26.1 What was built

**Migration `0056_partner_attest_redeem.sql`** (database half) and **matrix `34_partner_attest_redeem.sql`** (112 cells; both harness modes), then the Edge function **`partner-attest`**.

- **`private.partner_attest_for_partner(facility, kind, token)`**, class **A1**, roles staff and manager. The ONLINE path. The token is the player's own `checkin_token.jti` (the existing `checkin-token` endpoint issues it: server-graded, 15 minutes, challenge-bound). **The player is the owner of the token and is never named by the caller.** One attestation per token (an advisory lock on the jti, then the 0017 tombstone), a returned `replayed` for the second. `kind` is `presence` or `marker_purchase`.
- **`private.partner_offline_attest_for_partner(facility, kind, handle, code)`**, class **A1**. The money doc's **verify-and-record definer** (step 3, X9): the handle and the six typed digits go in; every candidate (the player's **5 most recently seen devices of the last 90 days**, steps -1, 0, +1: 15 codes a guess) is derived with `private.offline_seed_derive` (executable by nobody), computed with `private.hotp` (SHA-256, 600 s, 6 digits) and compared as a **double HMAC under a per-call random key**, **every candidate evaluated, no early exit**; the match is recorded with 0045's atomic `INSERT ... ON CONFLICT DO NOTHING` on `app.offline_code_step`. **It returns only `(o_status, o_attestation_id, o_held)`: never a seed, an expected code, a device or a step** (a matrix cell pins the result type; a unit test and the Deno suite scan the response). 0045's recorder stays owner-only (0047), and 0056 asserts at apply time that no edge role can execute it.
- **Failure counters (money doc step 2), written before a verdict can leak and committed**: 5 per staff member an hour, 10 per target player an hour and 30 a day across all staff (`rate_limit_bucket`, under advisory locks taken staff-then-target, so parallel guesses are counted, not raced). Every failed verification counts: malformed code or handle, unknown handle, wrong code, a replayed step. They are **statuses, never a RAISE** (the 0020 lesson); `supabase/tests/integration/partner-attest.deno.test.ts` reads them back from a second connection after a real commit.
- **Self-attest (AT(16) part one)**: `22023 self_attestation_refused`, per **account** (6.5), on both paths; the Edge maps it to 422. The `attestation` CHECK and 0045's recorder compare accounts too.
- **Same-device rule (plan A2-21)**: if a device of the staff member shares an install link, an App Attest key id or a DeviceCheck token hash with the player's device, the attest **completes**, the purchase and credit go to `held_review` (no co-signal window), a `same_device_attest` `fraud_signal` opens for the player, and the staff member's `staff_activity.anomalies` records it.
- **Cold-start cap**: a member whose earliest active membership is under 7 days old may write 30 attestations in any rolling 24 hours (`cold_start_cap`, a status, 429).
- **`partner_shift_log_for_partner(facility)`** (A0, staff or manager) and **`partner_staff_activity_for_partner(facility, days)`** (A0, manager or operator; **staff cannot**, plan line 843). These replace `api.staff_shift_log` and `api.staff_activity` now that D12 (0047) revoked the PostgREST path. The shift log returns the old view's rows (the facility's, newest first, 90 days) and **a subset of its columns** (id, facility, time, kind, player handle snapshot, staff handle): the keyed player pseudonym the old view's `SELECT *` carried is not returned.
- **Writes** (`private.partner_attest_write`, EXECUTE for nobody but its owner): `app.attestation` (both pseudonyms through `private.account_pseudonyms`), `attestation_shift_log`, `staff_activity` (upsert, the facility-local day), and for `marker_purchase` one `purchase_evidence` (`method staff_scan`, `offline` true on the offline path) plus one `marker_credit` per eligible trail (accepted programme row on a `pilot` or `live` `any_purchase` trail). **A purchase is `pending` with `cosignal.awaiting = {from, to, until}`** exactly as the S2a seam paragraph says (online: now -10 min to now +20 min; offline: the code's step start -10 min to +20 min; `until` 7 days), so `marker_cosignal_attach_for_actor` completes it unchanged. A staff scan writes no `play` (AT(4) holds). The App Store review account is never written for (the writer calls `private.is_demo_account`, as 0051 requires of every minter).
- **Binding-keyed policies (S1.1a LOW-3)**: 22 `private_definer` policies, all keyed on `private.partner_binding_kind() = 'partner'` plus `private.partner_bound_staff_at(facility)` / `_manager_at` / `_any()` (new predicates in the 14(c) reader list, the partner twins of 0045's `offline_code_bound_staff()`); **none reads a GUC**. They replace the windows 0047 8c closed: `offline_code_step` (insert, select, prune), and add the rows the writer needs (attestation, shift log, staff_activity, profile, checkin_token, device, facility, trail programme, staff_scan purchase and credit, fraud signal, the attestation nonce tombstone). Each is in `definer_policy_allowlist` and `supabase/tests/fixtures/definer_policy_exprs.txt`. A lesson recorded: `INSERT ... ON CONFLICT DO NOTHING` is checked against the SELECT policies too (the new row must be one the role may see), hence `pd_partner_offline_step_select`.

**Edge** (`supabase/functions/partner-attest/`, `_shared/partner/attest-handler.ts`, `attest-shape.ts`, `ports.ts` `PartnerAttestTx` / `PartnerDb.withAttest`, `privileged.ts` `buildPartnerAttestTx`). Routes (all session routes, `verify_jwt = false`):

| Route | Class | Body or query | Answers |
|---|---|---|---|
| `POST attest` | A1 | `{facilityId, kind, token}` | 201 `{attestationId, held}`; 409 `replayed`; 422 `token_invalid` (unknown, expired, another facility, the review account: one answer), `no_programme`, 422 for a self-attest; 429 `cold_start_cap`; 403 no scope or no PIN grant |
| `POST attest/offline` | A1 | `{facilityId, kind, handle, code}` | 201; 409 `replayed` (AT(13)); 422 `verification_failed` (one answer for every way the code can be wrong); 429 after the counters; the same refusals |
| `GET shift-log` | A0 | `?facilityId=` | 200 `{entries}` |
| `GET staff-activity` | A0 | `?facilityId=&days=` (1-90, default 7) | 200 `{activity}` |

The order is the members handler's (Origin, preflight, route and method, bearer, strict body or query, the per-member bucket `partner-attest:member` at 240 an hour `[inference]`, then the work). Every returned status commits; a 42501 and a 22023 throw and roll back. Entrypoint enumerations updated: `config.toml`, the three CI function lists, `partner-modules.test.ts`, `review-account-gate.test.ts`, the Deno and partners fakes.

### 26.2 Decisions and departures, and why

- **The online "token" is `checkin_token.jti`.** The build plan (not in this repository) names a staff-scanned player token without a definition here, and no player endpoint issues one. Reusing the existing check-in token costs the player lane nothing, and it is already server-graded and challenge-bound. A shoulder-surfed jti lets a staff member attest a player only for a facility the token allows; it cannot be used to read or spend anything of the player's. If the plan's attest token is a different object, `partner_attest_for_partner`'s token lookup is the one seam to change.
- **AT numbering.** The AT(n) list is the build plan's and is not in this repository. The mapping used here, so the cells can be re-pointed: AT(1) staff at X cannot attest at Y (and an operator cannot); AT(2) the online token path; AT(12) the offline code verified in the database, window and secrecy; AT(13) a replayed code step is 409; AT(15) the same-device rule and the cold-start cap; AT(16) part one self-attest. Each cell's message carries its AT number.
- **No `app.evidence` `staff_presence` row is written.** The money doc says "write the evidence"; the scoring union that would read a staff-created evidence row for a player's play is not wired to attestations, and an evidence row needs a matcher `input_hash`, a `local_date` and a course. The durable record is the `attestation` row (already exported to its subject, 0022) plus, for a marker purchase, the pending purchase. `cosignal_ok` stays `false` until a player fix arrives; nothing sets it yet.
- **The cold-start numbers (7 days, 30 a day) and the 240 an hour bucket are `[inference]`**: the plan's 8.3 is not in the repository. They are one literal each (`partner_attest_write`; `ATTEST_PER_MEMBER_PER_HOUR`).
- **Handles only on the offline path.** The staff member types the player's handle (money doc step 1); the database resolves it. An unknown handle, a review-account handle and a player with no recent device are the same status as a wrong code, and the handle lookup cannot be used to enumerate (the staff counter counts it).
- **The staff counter is read under a lock and written on failure** rather than reserved and released (the 0035 pair): the lock serialises one staff member's verifications, which is what makes "5 an hour" exact, and the definer knows the outcome itself, so no release is needed.

### 26.3 Not built, honestly

- **`partner-offers-redeem` and the offer-redemption attestation kind.** Redeeming an `offer_code` moves `offer.budget_reserved` into `budget_used` (0027's header: "a redeemed code's reservation was consumed into budget_used"), which is the settlement P5.1b owns, and it trips the 0017 play guards (`pd_offer_code_guard_read`, a GUC window closed under a partner binding by 0047 8c). It needs its own binding-keyed guard policies and the settlement accounting; shipping a redeem that skips either would be the half-built route this slice was told not to leave. `kind = offer_redemption` is therefore refused (22023) by both attest definers, and the offline-code redemption rules (needs the step-up PIN and the profile-card name check; `fraud_signal` / `unconfirmed` mark after 24 hours with no co-signal) are the same slice's. **Seam**: a `partner_offers_redeem_for_partner(facility, offer_code, ...)` A1 definer in the next migration, calling `partner_attest_write` with kind `offer_redemption` (the writer already takes the kind; the 0056 policy CHECK on `attestation.kind` must widen), plus `pd_*` guard-read policies keyed on the binding.
- **Special-marker hand-over** (`special_marker_handover`): S5.
- **The `staff_presence` evidence projection and `cosignal_ok`** (26.2).
- **A two-connection script in the style of `tools/db/test-partner-serialisation.sh`** for the attest race: the 4-way parallel verification is proved in the Deno suite instead.
- **No mutation pass was run for this slice.**
- **Merge notes**: `0055` / matrix `33` / section 25 belong to S2b; both slices edit `privileged.ts`, `ports.ts`, `ci.yml`, the entrypoint enumerations and the `partner_kind_readers.txt` / `definer_policy_exprs.txt` fixtures, so the merge is a textual (not semantic) conflict in those lists. The lists in matrices 10, 25 and 28 pin exact `edge_partner` and class-A0 sets and will need both slices' names.

### 26.4 Verification run for this slice

Run in this environment (PostgreSQL 16, Deno 2.5.2 from the CI-pinned release):

- `HARNESS_MODE=restricted tools/db/test.sh`: pgTAP **Files=54, Tests=5177, PASS** (baseline before this slice: 53 / 5065); the Deno integration suite **382 passed, 0 failed** (six of them are `partner-attest.deno.test.ts`: the online and offline paths through the real handler and `privileged.ts`, the failure counters read from a second connection after a real commit, four staff verifying one code at once recording it once); the replay, money-path, sign-in-proof, partner-serialisation and review-account checks pass. Deno 2.5.2 was installed from the CI-pinned release for this run.
- `HARNESS_MODE=superuser tools/db/test.sh`, run on the final tree: pgTAP **Files=54, Tests=5177, PASS**, Deno **382 passed, 0 failed**, inventory OK, lint clean.
- `tools/db/verify-function-inventory.mjs`: OK (checks 1-15, including check 14 clauses (a) to (e) and the 14 (a) behavioural-cell rule for the four new functions); `service-role-lint` clean; `tools/db/check-migrations-immutable.sh --base edc5020`: all 54 existing migrations byte-identical.
- vitest (`supabase/tests/unit`): the new `partner-attest-handler.test.ts` (shapes, route order, the status map, commit-versus-rollback, no seed or code in any response) and the updated enumerations pass; the files that fail in this environment fail for reasons outside this slice (`mint-siwa-client-secret` and `rules-vendor-freshness` need a build or network; `review-account-minters` failed on a first draft of the writer and is fixed here by the demo-account refusal). `apps/partners` typechecks (the fake `PartnerDb` gained `withAttest`).

## 27. As built: S4 (held-review queue and resolve; receipts upload is a documented seam)

Numbering: **migration `0057`, matrix `35`, this section 27.** S2b claims `0055` / matrix `33` / section 25; S3 claims `0056` / matrix `34` / section 26; S7 claims section 24. This slice takes the next free number of each so the branches merge without a rename. Nothing from 0001-0056 is edited.

### 27.1 What was built

**Migration `0057_partner_review_queue.sql`** (database half) and **matrix `35_partner_review_queue.sql`** (44 cells; both harness modes), then the Edge function **`partner-review`**.

- **`private.partner_resolve_held_offer_code_for_partner(code_id, approve)`** and **`private.partner_resolve_held_entitlement_for_partner(entitlement_id, approve)`**, class **A3**, **ADMIN only** (an operator with a fresh TOTP window still cannot). They wrap `app.resolve_held_*` (0027, E20) so the Edge never reaches those functions: `edge_partner` (and every other edge role) still has no EXECUTE on them. The bound admin is `p_resolved_by`. Outcomes are **status rows** (`ok | not_found | not_held | budget_short` for offer codes; no `budget_short` for entitlements), so an expected refusal commits; only a missing authority (`42501`) or a malformed argument (`22023`) raises. Apply helpers (`partner_resolve_held_*_apply`, EXECUTE for nobody but their owner) translate the SQLSTATEs of `resolve_held_*` (`P0002`, `55000`, `23514`) so the `_for_partner` bodies stay free of `EXCEPTION` blocks (check 14).
- **`private.partner_held_queue_for_partner()`**, class **A0**, ADMIN only. The open `held_review` offer codes and entitlements plus open `review_item` rows, with an SLA-breach flag (held / open longer than **48 hours**; `[inference]`: the plan's §9.2 SLA number is not in the repository). No plaintext code, no DeviceCheck hash, no ledger row. Newest-breach-first, capped at 500.
- **`private.partner_review_sla_for_partner()`**, class **A0**, ADMIN only. Counts of open held rewards and open review items, and of those past the SLA (the portal / ops alert surface).
- **Binding-keyed policies (S1.1a LOW-3)**: `private.partner_bound_admin()` (EXECUTE for nobody but the owner; in the 14(c) reader list) and **11** `private_definer` policies on `offer_code`, `entitlement`, `offer`, `device_reward_ledger`, `review_item` and `profile`, all keyed on that predicate — **none reads a GUC**. Each is in `definer_policy_allowlist` and `supabase/tests/fixtures/definer_policy_exprs.txt`. `GRANT EXECUTE` on `app.resolve_held_*` to `private_definer` only; apply-time asserts no edge role can execute them.

**Edge** (`supabase/functions/partner-review/`, `_shared/partner/review-handler.ts`, `review-shape.ts`, `ports.ts` `PartnerReviewTx` / `PartnerDb.withReview`, `privileged.ts` `buildPartnerReviewTx`). Routes (all session routes, `verify_jwt = false`):

| Route | Class | Body | Answers |
|---|---|---|---|
| `GET queue` | A0 | (none) | 200 `{items}`; 403 not admin |
| `GET sla` | A0 | (none) | 200 counts + `slaHours: 48`; 403 not admin |
| `POST resolve/offer-code` | A3 | `{id, approve}` | 200 `{state}`; 404 `not_found`; 409 `not_held`; 422 `budget_short`; 403 no A3 / not admin |
| `POST resolve/entitlement` | A3 | `{id, approve}` | 200 `{state}`; 404 / 409 as above |

The order is the members handler's (Origin, preflight, route and method, bearer, strict body on POST, the per-member bucket `partner-review:member` at 120 an hour `[inference]`, then the work). Entrypoint enumerations updated: `config.toml`, the three CI function lists, `partner-modules.test.ts`, `review-account-gate.test.ts`, the Deno and partners fakes. Matrices 10, 25 and 28 pin the four new `edge_partner` names and the two new class-A0 names.

### 27.2 Decisions and departures, and why

- **A3 wrappers around `app.resolve_held_*`, not a rewrite.** 0027's state machine, budget reservation, audit and ledger writes stay; S4 only makes them reachable under a partner binding with an admin and a fresh TOTP window (E20 / F7). Status translation lives in apply helpers so check 14 stays clean.
- **Admin only, not operator.** The money doc and 0027 already require `p_resolved_by` to be an admin; the wrappers re-check `private.is_admin` after `partner_authorize` with an operator role array (the same shape as `partner_admin_enrolment_issue_for_partner`).
- **48 h SLA is `[inference]`.** One literal in each of the queue and SLA definers; change both together if the plan's number lands.
- **Queue GETs take no query string.** The list is global for the admin (held rewards are not facility-scoped today); facility filtering stays a portal concern until a filter is specified.

### 27.3 Not built, honestly

- **Player-lane `POST /v1/receipts` upload** — **built in §40** (migration `0064`, matrix `42`).
- **Resolving a held PLAY** (`resolve_held_*` moves the reward row, not the play). Clearing a `fraud_signal`. The contract-reviewer staffing trigger of `roles-table.md`.
- **Partners PWA review screens** (S7d). This slice is the Edge + database half the portal will call.
- **No mutation pass was run for this slice.**
- **Merge notes**: S2b edits the same enumeration files (`privileged.ts`, `ports.ts`, `ci.yml`, `partner_kind_readers.txt`, `definer_policy_exprs.txt`, matrices 10/25/28). The lists here include S3's names and S4's; merging S2b is a textual (not semantic) conflict in those lists.

### 27.4 Verification run for this slice

Local restricted harness (`HARNESS_MODE=restricted tools/db/test.sh`) on this tip: matrix 35's **44/44** cells; all other pgTAP matrices; partner serialisation and review-account tool checks; Deno integration **382/382** (every `PartnerDb` fake implements `withReview`; PA-13b includes the four 0057 wrappers). `definer_policy_exprs.txt` matches live `pg_get_expr` for the eleven review policies (INSERT on `review_item` uses the catalog's AND-chain form). Vitest `partner-review-handler` + `partner-attest-handler` (60) and `apps/partners` typecheck pass locally. Remaining: CI on PR #68.

## 28. As built: S5 (hand-over and stock)

Numbering: **migration `0058`, matrix `36`, this section 28.** S2b claims `0055` / matrix `33` / section 25; S3–S4 claim 0056–0057 / 34–35 / 26–27. Nothing from 0001–0057 is edited.

### 28.1 What was built

**Migration `0058_partner_handover_stock.sql`** and **matrix `36_partner_stock_handover.sql`** (65 cells), then Edge functions **`stock-admin`** and **`partner-entitlements`**.

- **Stock (A0/A1, staff or manager):** `partner_stock_read_for_partner`, `partner_stock_move_for_partner` (delivered / transfer_in / transfer_out / count_adjustment / damaged; never `redeemed` / `voucher_redeemed`), `partner_stock_availability_refresh` (owner-only). Statuses `ok | no_stock_row | short | over_cap`.
- **Collect queue (A0):** `partner_entitlement_queue_for_partner` — redeemable of trails the facility stocks, and vouchered owed here; player by handle only.
- **Hand-over token:** `app.partner_handover_token` (hash only, FORCE RLS, no edge grants); `partner_handover_mint_for_partner` (A1) stores SHA-256 of an Edge-generated `gr_ho_…` token for 15 minutes.
- **Redeem (A1, AT(8)/AT(21)):** `partner_entitlement_redeem_for_partner` — `staff_scan` (check-in jti) or `hand_over_token` (hash); `offline_code` is 22023. Stock `FOR UPDATE`; `out_of_stock` changes nothing (voucher separately). Movement `redeemed` or `voucher_redeemed`; one `special_marker_handover` attestation (`token_jti` = `smh:<credential ref>` so it does not collide with the entitlement_redeem nonce). Self-redeem 22023.
- **Voucher (A1):** `partner_entitlement_voucher_for_partner` — redeemable → vouchered at this facility.
- **Binding-keyed policies:** 17 `private_definer` policies on stock, movement, availability, entitlement, play guard read, hand-over token, `consumed_nonce` (`entitlement_redeem`), and attestation (`special_marker_handover`). No GUC windows.

**Edge**

| Function | Routes |
|---|---|
| `stock-admin` | `GET stock`, `POST stock/move` |
| `partner-entitlements` | `GET collect`, `POST handover/mint` (plaintext once), `POST redeem`, `POST voucher` |

`out_of_stock` and `replayed` → 409; cold-start → 429; expected refusals → 422; missing scope/PIN → 403.

### 28.2 Decisions and departures

- **Attestation jti is `smh:` + credential ref**, not the entitlement id: the 0017 tombstone and the staff_scan `entitlement_redeem` nonce must not share a primary key, and a later redeem of a reset row must not collide.
- **Status gates read entitlements without `FOR UPDATE` first:** `SELECT FOR UPDATE` also applies UPDATE RLS, which only opens redeemable/vouchered rows, so a re-redeem of a redeemed row would otherwise look like `not_found`.
- **Race for the last unit** is proved twice: in matrix 36 by sequential redeems at `on_hand = 1` (CHECK + row lock), and with real concurrency by `tools/db/test-partner-stock-concurrency.sh` (run by `tools/db/test.sh`): two real `edge_gateway` sessions are parked on the contested row (seen waiting in `pg_locks`) and released together, six rounds each giving exactly one `ok` and one `out_of_stock`, `on_hand` 0, the loser's entitlement and hand-over token untouched; the same entitlement redeemed twice at once (one `ok`, one refusal, one unit); and a play-backed entitlement redeemed and COMMITTED (the deferred 0017 guard re-reads the play at a real commit through `pd_partner_handover_play_guard_read`). Removing `FOR UPDATE` from the redeem's stock read makes the script fail (the CHECK is the backstop that turns the lost race into an error rather than a negative stock).

- **The hand-over token is the Edge's.** `POST handover/mint` generates 32 random bytes (`gr_ho_` + 43 base64url characters), hands the port only the SHA-256 and returns the plaintext once in the 201 body. `POST redeem` with `method: "hand_over_token"` takes the plaintext as `credential` and hashes it before the port; a bare SHA-256 or a uuid is a 400 for that method, so the hash is never a credential a client can present.
- **Status map (Edge).** Every returned status commits. mint and redeem `ok` 201, voucher `ok` 200, stock move `ok` 200; `not_found` / `no_facility` 404; `not_redeemable`, `wrong_facility`, `token_invalid`, `wrong_player`, `no_stock_row`, `short`, `over_cap`, `token_exists` 422; `replayed` and `out_of_stock` 409 (`out_of_stock` is a state conflict that changed nothing: the caller vouchers next); `cold_start_cap` 429; 42501 403; 22023 (self-redeem, malformed) 422 and a rollback. `token_invalid` and `wrong_player` are one code on the wire (`token_invalid`), as in `partner-attest`.
- **Per-member bucket** (`stock-admin:member`, `partner-entitlements:member`, 240 an hour each), taken in its own transaction before the request transaction opens.

### 28.3 Not built, honestly

- **`offline_code` redemption** and **offers-redeem** (P5.1b).
- **Partners PWA hand-over/stock screens (S7c).**
- **Creating a stock row** from the partner lane (catalog/ops owns rows).
- **Paired transfer** (transfer_out here + transfer_in there are two moves).
- Merge notes: S2b still edits the same enumeration files; lists here include S3–S5 names.

### 28.4 Verification run for this slice

Local restricted harness (`HARNESS_MODE=restricted tools/db/test.sh`) on this tip: matrix 36's **65/65** cells; all other pgTAP matrices (**5286** tests PASS); partner serialisation; **partner stock concurrency** (`test-partner-stock-concurrency.sh`: six last-unit rounds, same-entitlement race, play guard at a real commit); review-account tool checks; Deno integration **382/382**; `verify-function-inventory` OK; service-role lint clean. Vitest stock + entitlements handler suites (status map, hash-only hand-over token, strict shapes, bucket order). CI on PR #69 tip `b433f81`: all three checks green.

## 29. As built: S7c (hand-over and stock screens; `apps/partners`)

Numbering: **this section 29.** S7b on this branch claims section 27; S5 (parallel Edge/DB half) claims section 28; this slice takes the next free section so the branches merge without a rename. **No server, database or migration change**: the page talks to the Edge routes S5 ships (`stock-admin`, `partner-entitlements`).

### 29.1 What was built

- **Allow-list and CSP.** `partner-functions.json` gains `stock-admin` and `partner-entitlements`; `connect-src` gains two path-scoped sources.
- **Typed work routes** (`src/api/work-routes.ts`): stock read/move; collect queue; hand-over mint (plaintext once); redeem (`staff_scan` / `hand_over_token`); voucher. Response bodies checked field-by-field.
- **Work screens** (`src/app/work.ts`, `state.work`, `ui/views-work.ts`). Signed-in home offers **Hand over a marker** and **Stock** beside attest and course-QR. Every A1 action calls `requirePin("A1")` then the action in the same turn. Hand-over token plaintext lives only in `work.minted` until dismissed.
- **Fake partner server** answers the two new functions in-memory (PIN-grant consume on A1) so the page's unit cells run without the S5 Edge tree on this branch.

### 29.2 Decisions and departures

- **Hand-over token shape is checked without a regexp** (same V8 last-match reason as the session token).
- **Queue mint/voucher buttons** sit on each collect row; redeem uses a shared form (entitlement id + credential) so a pasted id still works when the queue is empty.
- **Stock move kinds** match the Edge allow-list (never `redeemed` / `voucher_redeemed`).

### 29.3 Not built, honestly

- Camera scan into redeem credential fields.
- S7d manager/operator/admin screens (section 31).
- Offline-code redeem (P5.1b).
- Merging with S5 will conflict textually in enumeration files the way S7b notes for S2b/S3.

### 29.4 Verification run for this slice

- `pnpm --filter @golfraven/partners typecheck`: clean.
- `pnpm --filter @golfraven/partners test:unit`: **20 files, 761 tests, all pass** (extends `work.test.ts`: stock load + A1 move; hand-over mint + staff_scan redeem after PIN; request bodies contain no PIN digits).

## 30. As built: S6 (programme and sponsors)

Numbering: **migration `0059`, matrix `37`, this section 30.** S2b claims `0055` / matrix `33` / section 25; S3–S5 claim 0056–0058 / 34–36 / 26–28; **§29 is reserved for S7c UI.** Nothing from 0001–0058 is edited.

### 30.1 What was built

**Migration `0059_partner_programme_sponsors.sql`** (database half) and **matrix `37_partner_programme_sponsors.sql`** (58 cells; both harness modes when green), then Edge functions **`programme-config`**, **`offers-admin`**, and **`sponsorships-admin`**.

- **`private.partner_bound_operator_at_trail(trail)`** — policy predicate (EXECUTE for nobody but the owner; in the 14(c) reader list). True when this transaction carries a partner binding whose member is an operator of the trail (or admin via `has_trail_scope`).
- **Programme (A0/A3, operator of the trail):** `partner_trail_programme_read_for_partner`, `partner_facility_programme_list_for_partner`, `partner_trail_programme_upsert_for_partner` (`web_player_flow` true → `22023`; statuses `ok | not_found`), `partner_facility_programme_upsert_for_partner` (statuses `ok | no_trail`; never writes `pin_epoch`).
- **Offers (A0/A3):** `partner_offers_list_for_partner` (full budget / eligibility columns, every status); `partner_offer_upsert_for_partner` (draft create/edit; `ok | not_found | not_draft | bad_funder`); `partner_offer_approve_for_partner` (**admin only**, draft → live); `partner_offer_end_for_partner` (operator of the trail or admin, live → ended).
- **Sponsorships (A0/A3, AT(20)):** `partner_sponsorships_list_for_partner`; `partner_sponsorship_upsert_for_partner` (draft; sponsor_org must be `kind = sponsor`); `partner_sponsorship_approve_for_partner` (draft → live; when scope is `special_marker` or `both`, every `facility_programme` with `holds_special_marker` must have `special_marker_stock.on_hand >= 1` or the status is `stock_short` and nothing changes).
- **Rollups (A0):** `partner_operator_rollup_for_partner`, `partner_sponsor_rollup_for_partner` (scope via the sponsorship's trail).
- **Binding-keyed policies:** 14 `private_definer` policies (`pd_partner_programme_*`) on `trail_programme`, `facility_programme`, `offer`, `sponsorship`, `operator_rollup`, `sponsor_rollup`, and `special_marker_stock`. **None reads a GUC.** Existing `pd_marker_scan_*`, `pd_partner_attest_*`, `pd_partner_review_*`, and `pd_read_sponsorship` stay.

| Function | Routes |
|---|---|
| `programme-config` | `GET programme`, `POST programme/trail`, `POST programme/facility`, `GET rollups/operator`, `GET rollups/sponsor` |
| `offers-admin` | `GET offers`, `POST offers`, `POST offers/approve`, `POST offers/end` |
| `sponsorships-admin` | `GET sponsorships`, `POST sponsorships`, `POST sponsorships/approve` |

Ports: `PartnerProgrammeTx` / `withProgramme`, `PartnerOffersAdminTx` / `withOffersAdmin`, `PartnerSponsorshipsTx` / `withSponsorships` (merged into `withPartnerSession` like `withStock`). Upsert eligibility is checked with the Edge-local AT(14) schema gate in `offer-eligibility.ts` (closed money-mode aggregate names; `packages/rules` remains the full SSOT outside Edge) **before** the database. Status map: `ok` → 200; `not_found` / `no_trail` / `not_draft` / `not_live` / `bad_funder` / `bad_sponsor` / `stock_short` / `invalid_eligibility` → 422; `42501` → 403; `22023` → 422. Per-member buckets (`programme-config:member`, `offers-admin:member`, `sponsorships-admin:member`, 240 an hour each).

### 30.2 Decisions and departures, and why

- **Offer approve means draft → live in one step** (no separate `approved` stop). Keeps the portal machine simple; `approved` remains a legal enum value for other writers.
- **Admin-only offer approve** mirrors S4's held-review resolve (`partner_authorize` with an operator role array, then `is_admin` or `42501`).
- **AT(20) is a status, not a raise** — `stock_short` commits so the Edge can map it to 422 without rolling back an unrelated write in the same request transaction.
- **Column grants exclude `pin_epoch`** on facility_programme programme writers; the 0046 epoch rotation path stays the only partner write of that column.
- **Edge half built** — three functions, `verify_jwt = false`, handlers pure (PA-11). Settlement remains P5.1b.

### 30.3 Not built, honestly

- **Settlement-export AT(17)** and **offers-redeem** — moved to **§32 (P5.1b)**; not part of the S6 tip.
- **Rollups-refresh writer** (rows are read-only here; ops/catalog still seed them).
- **Issuance staff gate AT(10)** (deferred; see §32.3).
- **S7d / S7c UI** (portal screens; §29 reserved for S7c).
- **No mutation pass** was run for this slice.

### 30.4 Verification

Local restricted harness (`HARNESS_MODE=restricted tools/db/test.sh`) on tip `5782bd8`: matrix 37's **58/58** cells; all other pgTAP matrices (**5344** tests PASS across 57 files, including updated 10 / 24 / 25 / 28 inventory and grant cells); Deno integration **382/382**; `verify-function-inventory` OK; service-role lint clean. Vitest programme / offers / sponsorships handler suites plus related PartnerDb fakes (**96** focused cells; broader partner handler run **268**). `definer_policy_exprs.txt` holds the fourteen `pd_partner_programme_*` policies. CI on PR #71 tip `e2b11ac`: all three checks green.

## 31. As built: S7d (manager / operator / admin screens; `apps/partners`)

Numbering: **this section 31.** S7c on this lineage claims section 29; S6 (programme/sponsors Edge half, parallel branch) claims section 30; this PWA slice takes the next free section. **No server, database or migration change on this branch**: the page calls S6/S4 Edge paths by name (`programme-config`, `offers-admin`, `sponsorships-admin`, `partner-review`); the fake partner server stubs them so unit cells run without merging those trees.

### 31.1 What was built

- **Allow-list and CSP.** `partner-functions.json` gains `programme-config`, `offers-admin`, `sponsorships-admin`, `partner-review`; `connect-src` gains four path-scoped sources (pinned in `client-enrol.test.ts` and `csp.test.ts`).
- **Typed admin routes** (`src/api/admin-routes.ts`): programme read + trail/facility upsert; offers list/upsert/approve/end; sponsorships list/upsert/approve; review queue + SLA + resolve offer-code/entitlement; operator and sponsor rollups. Response bodies checked field-by-field (camelCase wire shapes match the S6 handlers).
- **Admin screens** (`src/app/admin.ts`, extended `WorkView` kinds, `ui/views-admin.ts`). Signed-in home gains a **Programme and ops** section: programme / offers / sponsorships / rollups for `isAdmin` or any `operator` membership; **Review queue** for `isAdmin` only. Staff keep shop-floor only. A0 reads call directly; A3 writes refuse on the client unless `aal` 2 (same gate as printed-QR write).
- **Errors and i18n.** `ErrorContext` gains programme/offers/sponsorships/review/rollups; closed codes `not_draft`, `not_live`, `bad_funder`, `bad_sponsor`, `stock_short`, `budget_short`, `no_trail`, `invalid_eligibility`, `not_held` map to catalogue keys. EN + FR-CA keys differ.
- **Fake partner server** answers the four new functions in-memory (A3 checks aal + fresh `mfaUntil`; sessions minted at aal ≥ 2 get a fresh MFA window for fixtures).

### 31.2 Decisions and departures

- **WorkView extended** with `programme | offers | sponsorships | review | rollups` rather than a parallel `AdminView` field, so one `work` slot still replaces home.
- **Invite/member admin tools** stay on the existing PIN/TOTP/enrol panels; this slice does not add invite-issue UI.
- **Eligibility** is sent as JSON from a text field; schema validation remains the Edge's AT(14) gate.

### 31.3 Not built, honestly

- Settlement UI (billing / fee settlement surfaces).
- Camera or richer editors for eligibility rules.
- Merging with S6 will conflict textually in `partner-functions.json` and the fake server's stubs (replaceable by the real handlers once that tree is present).

### 31.4 Verification run for this slice

- `pnpm --filter @golfraven/partners typecheck`: clean.
- `pnpm --filter @golfraven/partners test:unit`: **21 files, 877 tests, all pass** (adds `admin.test.ts`: open programme/offers/review/rollups, A0 load, A3 aal gate, offer approve and review resolve; request bodies contain no tokens beyond closed ids).
- CI on PR #72 tip `ec7a5cc`: all three checks green.

## 32. As built: P5.1b (offers-redeem + settlement-export + exports-purge)

Numbering: **migration `0060`, matrix `38`, this section 32.** S6 claims `0059` / matrix `37` / section 30; **§31 is reserved.** Nothing from 0001–0059 is edited.

### 32.1 What was built

**Migration `0060_partner_offers_settlement.sql`** (database half) and **matrix `38_partner_offers_settlement.sql`**, then Edge functions **`partner-offers-redeem`**, **`settlement-export`**, and **`exports-purge`**.

- **Binding-keyed policies** (never a GUC): offer_code select/update (issued→redeemed), offer budget select/update, play guard read via `offer_code.play_id`, attestation insert `kind=offer_redemption`, consumed_nonce for `offer_redemption`, settlement SELECT of redeemed codes on a trail the bound operator runs (or admin).
- **`GRANT EXECUTE` on `app.consume_offer_budget` TO `private_definer`**; `GRANT UPDATE (budget_used)` on `app.offer`.
- **`private.partner_offers_redeem_for_partner`** (A1, staff/manager): status-before-`FOR UPDATE` (0058 ordering); method `staff_scan` (player check-in jti); `offline_code` refused with `22023`. Statuses: `ok | not_found | not_issued | expired | wrong_facility | token_invalid | wrong_player | replayed | no_facility | cold_start_cap | budget_short`. Apply helper consumes budget, writes `offer_redemption` attestation via `partner_attest_write`, updates the code.
- **`private.partner_offers_queue_for_partner`** (A0): issued codes at the facility with player handle.
- **`private.partner_settlement_export_for_partner`** (A3, operator-at-trail or admin): lines with `facility_id`, `month`, `funder`, `sponsorship_id`, `redemptions`, `offline_count`, `unconfirmed_count`, `face_value_total`. Statuses `ok | empty`.

| Function | Routes |
|---|---|
| `partner-offers-redeem` | `GET queue`, `POST redeem` |
| `settlement-export` | `POST export` → CSV under `exports/`, signed URL (7 days) |
| `exports-purge` | `POST` (system lane, service-role bearer): delete `exports/` objects older than 7 days |

Ports: `PartnerOffersRedeemTx` / `withOffersRedeem`, `PartnerSettlementExportTx` / `withSettlementExport` (merged into `withPartnerSession`), `ExportsStoragePort` / `exportsStorage` (service-role `createSignedUrl` + purge). Status map: redeem `ok` → 201; settlement `ok` → 200 with `{ path, signedUrl, expiresAt, lines }`; `empty` → 404; `42501` → 403; `22023` → 422. Per-member buckets (`partner-offers-redeem:member` 240/h, `settlement-export:member` 60/h). System bucket `exports-purge` 12/h.

### 32.2 Decisions and departures, and why

- **Budget before attest** in the apply helper — avoids an orphan `offer_redemption` attestation if `consume_offer_budget` raises `check_violation` (`budget_short`).
- **`offline_code` out of this slice** — Edge shape and database both refuse with 22023 / 400; the offline PIN + profile-card path stays a later seam.
- **Settlement CSV always includes `sponsorship_id`** (empty when null) so AT(20) attribution is visible on every line.
- **`exports-purge` is the AT(17) lifecycle** when native Storage lifecycle is unavailable in the harness; signed URL expiry matches the 7-day retention.

### 32.3 Not built, honestly

- **`offline_code` offer redeem** — **built in §35** (migration `0062`, matrix `40`).
- **Rollups-refresh writer** (still out of scope; S6 seam).
- **S7 UI** (portal screens for staff_scan landed in §33; offline redeem form in §36).
- **No mutation pass** was run for this slice.

### 32.4 Verification

Branch: `cursor/p5-1b-offers-settlement-8ffd` (base S6 `ea27b80`).

- **Matrix 38** (`38_partner_offers_settlement.sql`): 32/32 PASS — foreign facility 403, A1 without PIN, happy redeem + budget consume, self-redeem 22023, A3 without TOTP refused, planted GUC, settlement line carries `sponsorship_id` for sponsor funder, export redemptions/`face_value_total` match planted redeem.
- **Edge vitest** (partner-offers-redeem, settlement-export, exports-purge + CI/module lists): **86/86** PASS.
- **`HARNESS_MODE=restricted tools/db/test.sh`**: **Files=58, Tests=5376, Result: PASS**; Deno integration **382 passed | 0 failed** (Deno 2.5.2 as CI pins); `verify-function-inventory: OK` (nine `pd_partner_offers_*` allow-list rows in `definer_policy_exprs.txt`); `service-role-lint: clean`. Helpers seed `staff_activity.day` on facility-local date so matrix 34 does not flake across the UTC/Chicago midnight boundary. Settlement policy uses `offer_code.facility_id` (bare `facility_id` deparsed as a tautology).
- Claims in-slice (0060 tip): **AT(17)** (signed URL after A3 role check + 7-day `exports-purge`), **AT(20)** (settlement lines carry `sponsorship_id`), **AT(10)** reconcile half (export matches redemptions).
- **CI on PR #73 tip `5f03f03`:** all three checks green (after PartnerDb stubs + 0061 review-account / rewards-isolation gates).

### 32.5 AT(10) issuance staff gate (0061)

Numbering: **migration `0061`, matrix `39`.** Nothing from 0001–0060 is edited.

**Built:** `private.facility_has_active_staff(facility)` (EXISTS non-revoked staff/manager with `partner_scope.facility_id`); `app.activate_offer_code` CREATE OR REPLACE holds an **earned** activate with `hold_detail.heldFor = no_active_staff` when the facility has no active staff (already-issued re-activate is not gated); `app.resolve_held_offer_code` refuses an approve that would **issue** with `23514` / partner status `no_active_staff` (return-to-earned is not gated). Both rewrites call `private.is_demo_account` (review-account ratchet).

**Matrix 39** (`39_at10_issuance_staff_gate.sql`): fac_x still issues; facility with only revoked staff → `held_review` / `no_active_staff`; issued re-activate ungated; resolve/apply refuse issue without staff.

**Verification:** on this branch, `HARNESS_MODE=restricted tools/db/test.sh` pgTAP **Files=59, Tests=5389, Result: PASS** (matrix 39 **13/13**; matrix 15 activate path still green; matrix 10 inventory includes `facility_has_active_staff`). Claims: **AT(10)** issuance half now built; reconcile half remains matrix 38. CI green with §32.4 tip.

## 33. As built: S7 offer redeem + settlement export screens (`apps/partners`)

Numbering: **this section 33.** S7d on this lineage claims section 31; S6 (programme/sponsors Edge) claims section 30; P5.1b (offers-redeem / settlement Edge half, parallel branch) claims section 32; this PWA slice takes the next free section. **No server, database or migration change on this branch**: the page calls P5.1b Edge paths by name (`partner-offers-redeem`, `settlement-export`); the fake partner server stubs them so unit cells run without merging that tree. `exports-purge` stays on the system lane and is **not** allow-listed.

### 33.1 What was built

- **Allow-list and CSP.** `partner-functions.json` gains `partner-offers-redeem` and `settlement-export`; `connect-src` gains two path-scoped sources (pinned in `client-enrol.test.ts` and `csp.test.ts`). `exports-purge` is explicitly refused by the bearer allow-list cells.
- **Typed routes.** `work-routes.ts`: `GET partner-offers-redeem/queue`, `POST …/redeem` (staff_scan only; camelCase wire matches P5.1b). `admin-routes.ts`: `POST settlement-export/export` → `{ path, signedUrl, expiresAt, lines }` (signed URL never logged).
- **Offer redeem screen** (`work.ts` / `views-work.ts`, WorkView kind `offer-redeem`). Facility-scoped like stock/handover. Home button for staff/manager (or admin). A0 queue load; A1 redeem via `requirePin("A1")` then redeem in the same turn.
- **Settlement export screen** (`admin.ts` / `views-admin.ts`, WorkView kind `settlement`). Home button with Programme and ops (operator/admin). Trail + month form; A3 aal gate (same as printed-QR / S7d writes); shows path, expiry, line count and a download link; dismiss clears the signed URL from state.
- **Errors and i18n.** `ErrorContext` gains `offer-redeem` and `settlement`; closed codes `not_issued`, `expired`, `wrong_facility`, `token_invalid`, `replayed`, `budget_short`, `cold_start_cap`, `empty` map to catalogue keys. EN + FR-CA keys differ.
- **Fake partner server** answers both functions in-memory (PIN grant for redeem; aal + fresh `mfaUntil` for export).

### 33.2 Decisions and departures

- Offer redeem stays on the shop-floor `work` slot (facility picker); settlement stays with admin ops (trail picker) — one `work` field still replaces home.
- Settlement signed URL is held only in `work.export` for display (like a hand-over token); request logs and notices never include it.
- Month inputs accept `YYYY-MM` (HTML `type=month`) or `YYYY-MM-DD` and normalize to `YYYY-MM-01` for the Edge body.

### 33.3 Not built, honestly

- Camera scan for check-in tokens.
- Offline offer redeem UI — **built in §36** (`offline_code` Edge path is §35).
- `exports-purge` UI (system lane).
- Merging with P5.1b will conflict textually in `partner-functions.json` and the fake server's stubs (replaceable by the real handlers once that tree is present).

### 33.4 Verification run for this slice

- `pnpm --filter @golfraven/partners typecheck`: clean.
- `pnpm --filter @golfraven/partners test:unit`: **21 files, 917 tests, all pass** (adds offer-redeem A1 PIN + queue/redeem body cells; settlement A3 aal gate, export path/expiry, empty month; allow-list/CSP include the two functions and refuse `exports-purge`).
- CI on PR #74 tip `fb8b5ea`: all three checks green.
## 34. As built: S7b (attest and course-QR screens; `apps/partners`)

Numbering: **this section 34.** (S7b originally claimed §27 in parallel with S4; S4 landed on main first via #73, so this UI as-built takes the next free section.) S2b (parallel) claims section 25 and S3 claims section 26; this slice takes the next free section so the branches merge without a rename. **No server, database or migration change**: the page is the only thing that moved. It talks to the Edge routes S2b and S3 ship (`partner-attest`, `course-qr`, `qr-print`).

### 34.1 What was built

- **Allow-list and CSP.** `partner-functions.json` is now `partner-session`, `partner-invites`, `partner-members`, `partner-attest`, `course-qr`, `qr-print`. `connect-src` gains three path-scoped sources; `Permissions-Policy` is `camera=(self)` (paste-only attest today; a later scan into the token field needs no header change).
- **`call()` query object.** GET routes that need `?facilityId=` take a closed `{ key: value }` map (facility-id charset), appended after the path is validated so a route string still cannot carry `?` or `#`.
- **Typed work routes** (`src/api/work-routes.ts`): online/offline attest, shift-log, staff-activity, course PIN, rotate, mint, refresh, printed QR read/write. Response bodies are checked field-by-field.
- **Work screens** (`src/app/work.ts`, `state.work`, `ui/views-work.ts`). Signed-in home offers **Attest a player** and **Course QR**. Every A1 action calls `requirePin("A1")` then the action in the same turn (24.3). Rotate PIN is A2: `reauthWithPasskey` then `requirePin("A2")` then rotate. Printed-QR write is A3: refused in the UI when `aal < 2`.
- **Fake partner server** answers the three new functions in-memory (PIN-grant consume on A1, reauth window on A2, aal/mfa on A3) so the page's unit cells run without the S2b/S3 Edge trees on this branch.

### 34.2 Decisions and departures

- **`state.work` on signed-in**, not a new top-level `AppState` screen. The PIN prompt is `state.panel`; keeping work under signed-in means `requirePin` needs no second host. Design 20.5's "new AppState branch" is met as a new view branch of signed-in.
- **Online attest token is pasted** (the check-in jti). Camera policy is open; a BarcodeDetector scan is not built.
- **Staff-activity and shift-log** are A0 reads on the attest screen (no PIN). Staff who are not managers will get 403 from the server for staff-activity; the page does not hide the button by role (the session's role list has no per-facility rank beyond membership).

### 34.3 Not built, honestly

- Camera scan of a player QR into the token field.
- S7d screens (manager/operator/admin invite and member tools). Hand-over and stock are S7c (section 29); programme/offers/sponsorships/review/rollups are section 31.
- Offers-redeem (S3 seam / P5.1b).
- Merging this branch with S2b/S3 will conflict textually in `partner-functions.json` (already complete here), CSP comments, and the fake server's work stub (replaceable by the real handlers once those trees are present).

### 34.4 Verification run for this slice

- `pnpm --filter @golfraven/partners typecheck`: clean.
- `pnpm --filter @golfraven/partners test:unit`: **20 files, 706 tests, all pass** (adds `work.test.ts`: online and offline attest after PIN, course-QR PIN load and mint; request bodies contain no PIN digits).

## 35. As built: offline_code offer redeem (0062)

Numbering: **migration `0062`, matrix `40`, this section 35.** P5.1b (0060 / matrix 38 / §32) left `offline_code` as a seam; AT(10) issuance (0061 / matrix 39 / §32.5) and S7 UI (§33–§34) took intermediate numbers. Nothing from 0001–0061 is edited.

### 35.1 What was built

**Migration `0062_partner_offers_offline_redeem.sql`** and **matrix `40_partner_offers_offline_redeem.sql`**, then Edge route **`POST partner-offers-redeem/redeem/offline`**.

- **`app.offer_code.offline_confirm_by`**: set to `now() + 24 h` on an offline redeem; NULL for staff_scan or after a player-lane cosignal clear (§37 / 0063).
- **`private.partner_offers_redeem_offline_for_partner(facility, offer_code_id, handle, code, name_confirmed)`** (A1, staff/manager): same verify-and-record counters/candidates as S3 offline attest (0056); `name_confirmed` must be true; redeems with `redeemed_offline = true` and sets `offline_confirm_by`. Statuses: `ok | not_found | not_issued | expired | wrong_facility | wrong_player | verification_failed | replayed | rate_limited | name_unconfirmed | no_facility | cold_start_cap | budget_short`.
- **`private.partner_offers_redeem_apply_offline`**: owner-only apply tail (consume, attest with `ofr-off:` jti prefix, nonce, code update). 0063 extends it with `p_offline_step` / `offline_step`.
- **`CREATE OR REPLACE private.partner_settlement_export_for_partner`**: `unconfirmed_count` uses overdue `offline_confirm_by`; inserts `fraud_signal` kind `offer_offline_unconfirmed` once per overdue code.
- **Fraud INSERT policy** widens to allow `offer_offline_unconfirmed` under a partner binding.
- **Edge**: `parseOfferRedeemOfflineBody` / `POST redeem/offline`; port `redeemOfferOffline`; privileged calls the new definer. Online `POST redeem` remains staff_scan only (0060 still refuses `offline_code` with 22023).

### 35.2 Decisions and departures, and why

- **Separate route and definer** (not a method on `partner_offers_redeem_for_partner`) — offline needs handle + six digits + `nameConfirmed`; keeping staff_scan's wire shape closed avoids a polymorphic body and matches the attest online/offline split.
- **`nameConfirmed` is boolean true on the wire** — Edge refuses anything else with 400; the database also returns `name_unconfirmed` if false (defence in depth for a non-Edge caller).
- **Settlement marks overdue once** — `NOT EXISTS` on `fraud_signal.detail.offer_code_id` so a second export does not duplicate the signal; `unconfirmed_count` still reads the deadline column every time.
- **Cosignal clear of `offline_confirm_by`** was deliberately out of this slice; **built in §37**.

### 35.3 Not built, honestly

- **Partners PWA offline redeem form** — **built in §36**.
- **Player-lane cosignal that clears `offline_confirm_by`** — **built in §37**.
- **Rollups-refresh writer** (S6 seam).
- **No mutation pass** was run for this slice.

### 35.4 Verification

Branch: `cursor/p5-offline-offer-redeem-8ffd` (base main after #74).

- **Matrix 40**: foreign facility 403, A1 without PIN, `name_unconfirmed`, wrong code, happy offline redeem + `offline_confirm_by`, replay, settlement `unconfirmed_count` + one `offer_offline_unconfirmed` fraud_signal.
- **Edge vitest** (`partner-offers-redeem-handler`): online + offline shapes and status map.
- Spine PA-1 expect list includes `partner_offers_redeem_offline_for_partner`.
- Restricted harness / CI recorded when green on the PR tip.

## 36. As built: partners offline offer redeem UI

Numbering: **this section 36.** Edge/DB offline redeem landed in §35 (0062 / matrix 40 / #75). This slice is **partners PWA only**: no migration, no Edge change. The page calls `POST partner-offers-redeem/redeem/offline` by name.

### 36.1 What was built

- **Typed route.** `work-routes.ts`: `postOfferRedeemOffline` → `POST partner-offers-redeem/redeem/offline` with `{ facilityId, offerCodeId, handle, code, nameConfirmed }`; response still `{ attestationId }`.
- **Offer-redeem screen mode.** `WorkView` kind `offer-redeem` gains `mode: "staff_scan" | "offline"`. Mode toggle on the screen (same pattern as attest online/offline). Staff-scan form unchanged; offline form collects handle, six digits, and a required `nameConfirmed` checkbox.
- **A1 path.** `submitOfferRedeemOffline` validates handle/code/`nameConfirmed === true` client-side, then `requirePin("A1")` and the offline POST in the same turn. PIN digits never appear in the request body.
- **Errors and i18n.** Closed codes `name_unconfirmed` and `verification_failed` map to catalogue keys; EN + FR-CA strings for mode, offline fields, and those errors.
- **Fake partner server** answers `redeem/offline` in-memory (PIN grant; refuses `nameConfirmed !== true`; maps a planted bad code to `verification_failed`).

### 36.2 Decisions and departures

- **Separate submit path** (not a method switch on `submitOfferRedeem`) — mirrors Edge's separate route and keeps the staff_scan body closed.
- **`nameConfirmed` must be the boolean `true` on the wire** — checkbox → `fd.get("nameConfirmed") === "on"` → client refuses false before PIN; Edge also refuses anything other than `true`.
- Hint copy switches with mode so staff are told to confirm the profile-card name before typing the offline code.

### 36.3 Not built, honestly

- Camera scan for check-in tokens (still a seam from §33).
- Player-lane cosignal that clears `offline_confirm_by` (§35 seam) — **built in §37**.
- Rollups-refresh writer (S6 seam).

### 36.4 Verification run for this slice

Branch: `cursor/p5-offline-offer-ui-8ffd` (base main after #75). Tip squash-merged to main as `dc83096` (#76).

- `pnpm --filter @golfraven/partners typecheck`: clean.
- `pnpm --filter @golfraven/partners test:unit`: **21 files, 930 tests, all pass** (adds offline offer-redeem A1 PIN + body cell — handle lower-cased, `nameConfirmed: true`, no PIN digits — and a client-side name-unconfirmed refusal that never hits the server).
- CI green on PR #76 tip before merge.

## 37. As built: player-lane offline offer cosignal clear (0063)

Numbering: **migration `0063`, matrix `41`, this section 37.** Clears the §35 seam: a qualifying player fix within the offline code's step window confirms the redeem before the 24 h deadline.

### 37.1 What was built

**Migration `0063_offer_offline_confirm.sql`** and **matrix `41_offer_offline_confirm.sql`**, plus an Edge hook on the marker-scan co-signal intake.

- **`app.offer_code.offline_step`**: HOTP step accepted at offline redeem (survives `offline_code_step` prune).
- **`private.partner_offers_redeem_apply_offline`**: DROP+CREATE with `p_offline_step`; redeem call site passes the hit step.
- **`private.offer_offline_confirm_for_actor`** (`edge_actor` only): same co-signal proof as `marker_cosignal_attach_for_actor` (`marker_cosignal_check`); clears `offline_confirm_by` on the bound player's own `redeemed_offline` codes at the facility whose step window holds the fix (`step start −10 min … +20 min`) and whose deadline is still in the future. Statuses: `confirmed | none_awaiting | cosignal_invalid | cosignal_used | review_account`.
- **Edge**: after `attachCosignal` answers `no_pending_purchase`, call `confirmOfferOffline`; `confirmed` → 200 with empty purchases (`[].every` → outcome `credited`).

### 37.2 Decisions and departures

- **Step on the code, not only on `offline_code_step`** — step rows prune after ~3 steps; the 24 h confirm window needs the step on `offer_code`.
- **Confirm does not consume the fix** — it only clears deadlines; `cosignal_used` still means a `purchase_evidence` row already referenced the evidence id. Intake order on this tip was attach first, then confirm on `no_pending_purchase`; **§38** flips to confirm-before-attach so a dual pending-purchase + offline-awaiting fix clears both.
- **No `partner_audit_write` from the actor lane** — that helper requires a partner binding and `^partner\.` action; marker attach also leaves no audit row.

### 37.3 Not built, honestly

- Rollups-refresh writer (S6 seam).
- Receipts upload / EXIF / phash player lane.
- Confirm-before-attach when both a pending marker purchase and an offline offer await the same fix — **built in §38**.

### 37.4 Verification

Branch: `cursor/p5-offline-confirm-cosignal-8ffd` (base main after #76). Tip squash-merged to main as `d51435c` (#77).

- **Matrix 41**: inventory/EXECUTE, offline redeem writes `offline_step` (partner bind isolated in SAVEPOINT), happy clear of the planted awaiting code, other player's code untouched, `none_awaiting` / `cosignal_invalid` / `cosignal_used`.
- **Edge vitest** (`marker-scan-handler`): intake with confirm override → 200 credited, empty purchases.
- CI green on PR #77 tip before merge (all three checks). Matrix 24 tip fixes on the same branch: NZ wrong-zone PIN non-vacuous when Chicago≡Auckland date; NIT same-day dedupe when `t0-2h` straddles Chicago midnight.

## 38. As built: confirm-before-attach on cosignal intake

Numbering: **this section 38.** No migration. Closes the §37.3 dual-await follow-up: when the same fix can both complete a pending marker purchase and clear an offline offer, confirm must run first.

### 38.1 What was built

- **Edge** (`scan-handler` co-signal intake): call `confirmOfferOffline` **before** `attachCosignal`. Attach still returns the purchase list when a pending row exists; when attach is `no_pending_purchase` and confirm was `confirmed`, answer 200 with empty purchases (unchanged credited outcome).
- **Vitest**: call order `confirmOfferOffline` → `attachCosignal`; dual path (pending purchase + confirm override) still credits purchases.

### 38.2 Decisions and departures

- **Confirm first is required, not optional** — `marker_cosignal_check` returns `cosignal_used` once any `purchase_evidence` row references the evidence id; attach writes that reference, so confirm-after-attach can never clear an offline offer on the same fix.
- **Confirm still does not consume the fix** — attach proceeds afterward for a pending marker purchase.

### 38.3 Not built, honestly

- Rollups-refresh writer (S6 seam).
- Receipts upload / EXIF / phash player lane.
- Camera scan for check-in tokens (§33 seam) — **built in §39**.

### 38.4 Verification

Branch: `cursor/p5-offline-confirm-order-8ffd` (base main after #77). Tip `6a3525e` CI green on PR #78 (all three checks) before merge.

- Focused vitest (`marker-scan-handler`): 47/47, including confirm-before-attach order and dual pending-purchase + confirm path.
- CI green on the PR tip (install/typecheck/build/test, player-plane DB, gitleaks).

## 39. As built: camera scan of check-in tokens (`apps/partners`)

Numbering: **this section 39.** No server, database or migration change. Closes the §33 / §34 / §38 shop-floor seam: a player check-in QR (or hand-over token QR) fills the existing paste field.

### 39.1 What was built

- **`scanCheckinQr`** (`src/ui/camera-scan.ts`): injected ports (`getUserMedia`, `BarcodeDetector`-shaped `detect`, clock, delay). QR only. First non-empty `rawValue` is trimmed to the first token and capped at 256 characters. `stopCameraScan` aborts and stops tracks.
- **`tokenScanField`**: paste input plus Scan / Stop and a muted preview. Status names only closed failure keys (`unsupported` / `denied` / `timeout`); the scanned value is never copied into status text.
- Wired on **online attest**, **offer-redeem staff_scan**, and **handover credential** (staff scan or hand-over token). Offline six-digit fields stay typed.
- **`render`** calls `stopCameraScan` before every rebuild so a PIN prompt, lock, or screen change cannot leave a live track.
- Permissions-Policy stays `camera=(self)`. Paste remains the fallback when `BarcodeDetector` or the camera is missing.

### 39.2 Decisions and departures

- **No third-party scanner.** `BarcodeDetector` is the platform API; no wasm/zxing in the bundle (every import is still relative).
- **Rebuild tears down the camera** rather than re-attaching a stream across `replaceChildren`. A scan in progress is aborted honestly; the person taps Scan again.
- **No new AppState.** The field writes the input the submit handler already reads.

### 39.3 Not built, honestly

- Rollups-refresh writer (S6 seam).
- Receipts upload / EXIF / phash player lane.
- A dedicated player-app QR payload schema beyond "the token string in a QR".

### 39.4 Verification

Branch: `cursor/p5-camera-scan-8ffd` (base main after #78).

- `pnpm --filter @golfraven/partners typecheck`: clean.
- `pnpm --filter @golfraven/partners test:unit`: **22 files, 944 tests, all pass** (adds camera-scan normalize / unsupported / denied / happy / timeout / abort).
- Restricted harness / CI recorded when green on the PR tip.

## 40. As built: player-lane receipt upload (0064)

Numbering: **migration `0064`, matrix `42`, this section 40.** Closes partner-auth-design §27.3: Storage object + `receipt_intake_for_actor` + `app.dedupe_receipt_fingerprint` on the first purchase of an upload. Nothing from 0001–0063 is edited.

### 40.1 What was built

**Migration `0064_player_receipts_upload.sql`** and **matrix `42_player_receipts_upload.sql`**, then Edge function **`receipts`** (`POST /v1/receipts`).

- **`private.receipt_intake_for_actor`**: bound player only; eligible trails = accepted `facility_programme` + `trail_programme` pilot/live + `marker_source = any_purchase` (same gate as course-QR scan, without `qr_mode`). One `purchase_evidence` (`method=receipt`, `ref_id` = Storage path) + `marker_credit` pending per trail; cosignal `awaiting` for the facility-local day + 7-day deadline. Calls **`app.dedupe_receipt_fingerprint` once** on the first purchase id (`phash` is per upload). Statuses: `ok | duplicate | review | no_facility | no_programme | review_account | bad_args`. `o_dedupe`: `clean | same_user | cross_user`. Same-user duplicate voids every purchase from the upload (`void_reason=duplicate`); cross-user leaves both pending and opens `review_item` + `fraud_signal` via dedupe.
- **Policies / grants**: `pd_receipt_*` on `receipt_fingerprint`, `fraud_signal`, `review_item`, cross-user `purchase_evidence` demotion, `marker_credit` detach; `GRANT EXECUTE` on dedupe to **`private_definer` only** (not `edge_actor`).
- **Edge**: multipart `facilityId`, `file`, optional `localDate`, optional `receiptNumberOcr`. **5 MB** max file (`0012_storage.sql` / build plan line 865; matrix TODO “6 MB” is stale — this slice uses 5 MB). Body read uses a **running stream cap** (same discipline as `readCappedJsonBody`); Content-Length is a fast-reject only. MIME sniff: JPEG/PNG/HEIC only; PDF/SVG → 415; empty/corrupt after strip → 415. EXIF strip: JPEG APP1 removed; PNG `eXIf` chunk removed (pure byte walk; no image decoder deps). **`phash` = SHA-256 of the stripped object bytes** for every kind (exact-dupe; perceptual aHash deferred — jpeg-js/pngjs trip the Edge import lint). Storage path `receipts/<uid>/<objectId>.<ext>` via service-role `receiptsStorage` (no client Storage policies); **compensating `removeObject`** when intake refuses after upload. Rate limit **`receipts:member` 60/hour** before `withOwnership`.

### 40.2 Decisions and departures

- **Dedupe once per upload**, not per trail — `phash` identifies the image; sibling trail rows follow the first purchase outcome (same-user void loops the rest).
- **phash = sha256(stripped)** for JPEG/PNG/HEIC — exact re-upload detection only. Perceptual aHash needs a reviewed decoder that does not pull `node:buffer` / banned remotes into the Edge lock.
- **5 MB not 6 MB** — `storage.buckets.file_size_limit` and Edge cap align with `0012_storage.sql` (build plan line 865), not the matrix TODO line.
- **Cross-user UPDATE policy** excludes `void`/`valid` in `USING` so a future caller cannot demote an already-accepted purchase (mirrors `dedupe_receipt_fingerprint`).

### 40.3 Not built, honestly

- OCR pipeline, mobile client, `receipt_green_fee` scoring bridge, 90-day image purge, perceptual aHash, HEIC metadata strip.
- **Rollups-refresh writer** — moved to **§41** (migration `0065`).
- JPEG ancillary markers beyond APP1 (e.g. APP13/COM) are not stripped; residual metadata risk is accepted until a re-encode path exists.

### 40.4 Verification

Branch: `cursor/p5-receipts-upload-8ffd` (base main after #79). Tip `ed6aae8` CI green on PR #80 (all three checks) before merge.

- Matrix **42**: EXECUTE/grant cells, happy intake, same-user duplicate, cross-user `review_item`, `review_account`, `no_facility`, `bad_args`, no `edge_actor` on raw dedupe.
- Vitest: `receipts-image.test.ts` (EXIF strip, MIME reject, sha256 phash stability, size constant), `receipts-handler.test.ts` (status map, Storage path, orphan remove).
- `deno check` includes `receipts/index.ts` in CI function lists; service-role-lint clean.
- CI green on the PR tip (install/typecheck/build/test, player-plane DB, gitleaks).

## 41. As built: rollups-refresh writer (0065)

Numbering: **migration `0065`, matrix `43`, this section 41.** Closes the S6 §30.3 / receipts §40.3 seam: a scheduled system job writes `operator_rollup` / `sponsor_rollup` instead of ops seed. Nothing from 0001–0064 is edited.

### 41.1 What was built

**Migration `0065_rollups_refresh.sql`** and **matrix `43_rollups_refresh.sql`**, then Edge function **`rollups-refresh`** (`POST`).

- **`app.entitlement.earned_at`**: NOT NULL DEFAULT `now()`; backfilled from `play.play_date` (UTC), then `activated_at` / `redeemed_at` / `voucher_issued_at`, then `now()`. Month bucket for `markers_earned`.
- **`private.refresh_rollups(p_month date)`** (`edge_system` only): NULL month = current UTC month. Opens GUC `app.edge.rollups_refresh = on` (never under a partner binding — policies require `partner_binding_kind() IS DISTINCT FROM 'partner'`). Recomputes:
  - **`operator_rollup` / `completions`**: non-revoked `user_achievement` with completion-family `award_key ~ '^v[0-9]+$'` on a trail-scoped `catalog_achievement_def`; `cohort_n` = distinct users; `value` = award count.
  - **`sponsor_rollup` / `markers_earned`**: non-void `entitlement` with `sponsorship_id`; bucketed by `earned_at`; same cohort/value shape.
  - **k-anonymity**: upsert only when `cohort_n >= 10` (WITH CHECK + table CHECK); remove existing rows for those metrics/month when the live cohort falls below 10. Other metric names are left alone.
- **Eleven `pd_rollups_refresh_*` policies** on `user_achievement`, `catalog_achievement_def`, `entitlement`, `operator_rollup`, `sponsor_rollup` (SELECT/INSERT/UPDATE/DELETE as needed).
- **Edge**: service-role bearer → system rate limit `rollups-refresh` 12/hour → `refreshRollups` via `openScopedTx("system")`. Empty body or `{ "month": "YYYY-MM-01" }`. Deploy schedules it; nothing in-repo does.

### 41.2 Decisions and departures

- **Closed metric set** (`completions`, `markers_earned`) matching the helpers seed and S6 reads; the build plan’s per-metric table names are already one table + `metric` column (0005 AMBIGUITY).
- **System lane, not partner A3** — rollups are aggregates over every player; a partner session must not open the writer (GUC window closed under a partner binding).
- **UTC month** — no facility TZ for programme-wide numbers; documented here.
- **Completion family = `award_key` `vN`** — matches `user_achievement.award_key` comment in 0003 (“v\<N\> for the completion family”).

### 41.3 Not built, honestly

- Additional metrics, partner-triggered refresh, sponsor portal (P6), in-repo scheduler, OCR/receipt follow-ons from §40.3.

### 41.4 Verification

Branch: `cursor/p5-rollups-refresh-8ffd` (base main after #80). Recorded when CI is green on the PR tip.

- Matrix **43**: EXECUTE matrix, sub-threshold remove of seeded completions, happy write at cohort 10, remove after revoke drops cohort, `edge_actor` / `edge_partner` 42501.
- Vitest: `rollups-refresh-handler.test.ts` (auth order, empty body, month shape, 429/500).
- `deno check` / `deno cache --frozen` lists include `rollups-refresh/index.ts`; service-role-lint clean.

