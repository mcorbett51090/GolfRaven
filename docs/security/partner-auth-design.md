# Partner (staff) authentication and authorization: design, P5.1a-0

Design only. No code and no migration is part of this change. It is the document the P5.1a security gate reads before anyone builds the staff path, and it settles the item the build plan leaves open: the staff-auth **mechanism** (plan §3.4 row "Staff auth", line 398; assumption A46, line 3247; FM-20, G-P1-05).

- Base: `main` at `eb92ee9`. Every `path:line` below is at that commit unless it says otherwise.
- "Plan" is the RavenGolf repo's `docs/golf-trails/02-build-plan.md` (linked from the root `README.md`). Plan line numbers are the ones read when this was written.
- Related, read first: `docs/security/edge-role-design.md` (the Edge database role model; "edge doc" below) and `docs/security/p3-money-path-requirements.md` ("money doc"; in particular "What P5 must do (the staff verification endpoint)", line 3831).

**How claims are marked.** Anything about a third party (Supabase, GoTrue, WebAuthn, iOS, SimpleWebAuthn, Deno) is `[unverified - training knowledge]` unless it carries `[verified 2026-10-04: <how>]`. Section 14 lists everything that was checked in the authoring session, and how. `[proposed]` marks a number or a name chosen here for the gate or the owner to challenge; it is not a fact about the repo.

## 1. Decisions at a glance

| # | Decision | Choice | Detail |
|---|---|---|---|
| D1 | Mechanism | `@simplewebauthn/server` in an Edge Function verifies passkeys; **opaque** random sessions live in Postgres. No JWT is minted, no new signing secret exists. Supabase Auth's own passkeys are rejected **for now** (revisit triggers in 3.3) | 3 |
| D2 | Staff identity | A staff member is a normal Supabase Auth user (the FKs and `bind_actor` need `auth.users`). Email OTP is used only to accept an invite, verified **server-side**, and its GoTrue session is closed at once. Partner authority never comes from a JWT claim or `user_metadata` | 6.1 |
| D3 | Relying party | RP ID `partners.golfraven.<tld>` (the narrow host, not the parent domain), one exact origin, `userVerification: required`, `residentKey: required`, `attestation: none`. Needs **no outbound host** | 4.5, 7 |
| D4 | Sessions | 256-bit random token, SHA-256 at rest, bound to member + credential, idle and absolute timeouts per role, at most 3 live per member, revocable instantly | 4.1, 5.1 |
| D5 | Resolution | The session is resolved **inside the database** into a new binding kind `partner` (`private.bind_partner_session`). Every partner definer begins with one shared `private.partner_authorize(...)` that re-reads session, role and scope **on every call** | 4.3 |
| D6 | Minting | Sessions, challenges, enrolment and invite acceptance are written only by a dedicated role `edge_partner_minter` (the `edge_signin_minter` precedent, migration 0041), never by `edge_actor` | 4.4 |
| D7 | Transport | `Authorization: Bearer gr_ps_...` header, token held **in memory only**. No cookie. Exact-origin CORS, strict CSP | 4.6 |
| D8 | Step-up PIN | 4 digits, per person. PBKDF2-SHA256 runs in the Edge, the **comparison and the pepper run in the database**, with lockout, backoff, a 90 s window and four action classes | 6.3 |
| D9 | Admin and operator | Passkey + TOTP. TOTP is our own, verified in the database (a partner session is not a GoTrue session, so GoTrue MFA cannot apply) | 6.4 |
| D10 | Invites | Hashed token in a URL fragment, email compared **in the database**, 72 h, single use, rank rule, and a new invariant: one facility org = one facility scope | 6.1, 5.2 |
| D11 | Revocation | Authority is re-read per call; triggers also kill the sessions, so a reactivation cannot resurrect them | 6.5 |
| D12 | PostgREST read surface | **The existing PostgREST read surface over partner data is revoked** from `authenticated` and replaced by Edge reads. Without this the passkey is bypassable by email OTP alone | 5.5 |
| D13 | Recovery | Email OTP alone never adds a credential to a member who has one. Recovery is a manager (or operator, or admin) re-invite | 6.5 |
| D14 | Offline | The design keeps the hooks (challenge purpose, TTL, binding) but builds nothing offline. WebAuthn assertions offline in an installed PWA stay `[unverified]` (A60) | 6.7 |

### 1.1 Where this departs from the proposed direction

| # | Departure | Why |
|---|---|---|
| X1 | The session resolves into a **new binding kind** (`partner`), not "resolve, then `bind_actor(uid)`" | With `bind_actor(uid)` any partner definer would trust the runtime's claim of a uid, so the passkey would protect nothing against a handler bug or an injected statement. A `partner` binding can only be created from a live session hash, and the user-lane and partner-lane definers refuse each other's binding. This is strictly narrower than residual R6 (edge doc section 3) for the partner lane. Cost: widen a CHECK and add one column on `private.actor_binding` |
| X2 | A dedicated **minter role** `edge_partner_minter` | A handler bug in any `edge_actor` partner function must not be able to mint a session. Same shape and same reasoning as 0041 |
| X3 | PIN: PBKDF2 stays in the Edge as proposed, but the verifier stored is `HMAC(pepper, PBKDF2 output)` and the **compare runs in the database** | For a 4-digit secret a slow KDF buys almost nothing against a leaked verifier: 10,000 candidates at 600,000 rounds is about 54 minutes on one core (measured, section 14). What protects it is that the table is unreadable, the pepper is not in the table, and online guesses are capped in the database |
| X4 | **Revoke the PostgREST partner-lane views** (D12) | "The PWA never talks to PostgREST" is necessary but not sufficient: the same person's Supabase JWT (from the OTP bootstrap, or from the player app) still reads `api.staff_shift_log` and friends today. This is the largest finding of the design |
| X5 | Operator/admin TOTP is **ours, in the database**, not Supabase MFA | The partner session is not a GoTrue session, so GoTrue's `aal` cannot be attached to it |
| X6 | Slice plan: slice 1 is split in five, the player-lane half of the course QR (`marker-scan`) is pulled forward and can run in parallel, and the PWA is its own track | Section 12 |
| X7 | The `facility org = one facility scope` invariant and `partner_invite` additions | `partner_scope` is per **org**, not per member (section 2, gap G2); without the invariant "grant is a subset of the inviter's scope" has no precise meaning |

## 2. What the repository already gives us, and what it does not

Facts the design leans on. Each was read at `eb92ee9`.

| # | Fact | Where |
|---|---|---|
| E1 | Every Edge transaction is `SET LOCAL ROLE edge_actor`, `edge_system` or `edge_signin_minter` over one `edge_gateway` pool. Kinds are `actor`, `system`, `delegate`, `signin_mint`. The actor kind binds `private.bind_actor(uid)` and asserts `private.actor_uid()` equals the expected uid | `supabase/functions/_shared/privileged.ts:292-377`; edge doc sections 2-3 |
| E2 | Player identity is GoTrue `auth.getUser(token)` with the anon key. Nothing else is an identity source | `privileged.ts:422-441` |
| E3 | `private.actor_binding.kind` is `CHECK (kind IN ('user','system_delegate'))`; user-lane definers refuse any other kind (`IF v_kind <> 'user'`) | `supabase/migrations/0030_edge_role_core.sql:122,375,397`; `0045_offline_totp_seed.sql:214,266` |
| E4 | A fully compromised runtime can `bind_actor(<any uid>)` (residual R6). This design keeps the partner lane narrower than R6 where it can, and says where it cannot | edge doc section 3 "Honest limit", section 8 R6 |
| E5 | `partner_member(user_id, org_id, role, revoked_at, invited_by)` has PK `(user_id, org_id)`. `partner_scope(org_id, facility_id?, trail_id?, sponsorship_id?)` hangs off the **org**, not the member | `0004_partner_programme.sql:20-46` |
| E6 | `private.has_facility_scope(uid, facility, roles)` reads non-revoked member + scope, lets admin through, and lets an `operator` reach a facility through **any** `facility_programme` row of its trail (no filter on `participation`). `partner_role_rank`: staff 1, manager 2, operator 3, sponsor 3 | `0007_private_helpers.sql:75-105,194` |
| E7 | Self-attestation has a database twin: a CHECK on `attestation`, and `22023 self_attestation_refused` in the offline-code recorder | `0004_partner_programme.sql:154`; `0045_offline_totp_seed.sql:283` |
| E8 | Every `api.` view is granted SELECT to `authenticated`, and the partner-lane ones filter on `auth.uid()` | `0010_api_views.sql:130-200`, grant loop `:213`; `0009_grants_revokes.sql:23` |
| E9 | Registries fail closed. `delete_my_data` raises on an unclassified FK to `auth.users`; `export_my_data` needs a `pii_export_policy` row; every function needs a `function_inventory` row; every `private_definer` policy needs an allow-list row and a fixture line | `0014_hardening.sql:37-96`; `0045:380-396,573-640`; edge doc section 6 |
| E10 | Precedent for a narrow mint role | `0041_signin_proof_hardening.sql:61-103`; edge doc section 12.1.1 |
| E11 | `private.hit_actor_rate_limit` never raises over the cap and builds `<uid>:<key>` in the database; `hit_system_rate_limit` builds `system:<key>`; the failure-counter pattern is `reserve_signin_otp_attempt` / `release_signin_otp_attempt` | `0030:320`; `privileged.ts:398`; `0035:561,585` |
| E12 | The staff offline-code requirement: verify **inside the database**, no seed reaches the staff runtime; and the HARD RULE that a GUC-keyed policy is not an ownership boundary against `edge_actor` | money doc lines 3831-3845 |
| E13 | `retention-purge` runs bounded definers, one try-lock per step, with `EXECUTE` granted to `edge_system` by owner decision | `privileged.ts:2395`; `0040_retention_hygiene_purges.sql`; edge doc sections 14.4, 14.8 |
| E14 | `app.audit_log` is insert-only (a trigger blocks update/delete except one redaction exception); nothing purges it | `0006_offers_booking_misc.sql:142-153` |
| E15 | An `npm:` import must be an exact entry in `supabase/functions/deno.json`, in `tools/service-role-lint/pinned-import-targets.json`, and in `supabase/tests/deno.lock` with a sha512 integrity; CI re-checks with `deno cache --frozen` | `tools/service-role-lint/src/config.ts:337-380`; `.github/workflows/ci.yml:395,451,509` |
| E16 | `_shared/http.ts` has **no CORS handling** (no browser client exists yet) | `supabase/functions/_shared/http.ts` (212 lines, no `Access-Control`) |
| E17 | Admin and demo status are tables read by definers (`app.admin_user`, `app.app_review_demo_account`; `private.is_admin`, `is_demo_account`) | `0007_private_helpers.sql:18-47` |
| E18 | `partner_invite` has `token_hash text NOT NULL UNIQUE`, `invitee_email`, `expires_at`, `accepted_at`. It has no `revoked_at`, no `accepted_by`, no attempt counter | `0004_partner_programme.sql:48-60` |
| E19 | OTP verification already runs server-side with the anon key, and the session it creates is closed on every path | `privileged.ts:3160-3215` |
| E20 | The held-review resolvers exist, are `service_role`-only, and say "the caller must authenticate the admin" | `0027_rewards_activation.sql:485-499`; money doc line 2132; edge doc line 163 |

### 2.1 Gaps found while reading (each is closed in this design)

| # | Gap | Consequence | Closed by |
|---|---|---|---|
| G1 | **E8: a person's Supabase JWT reads partner data directly through PostgREST.** `api.staff_shift_log` (player handles), `api.staff_activity`, `api.facility_programme`, `api.facility_qr`, `api.marker_code_batch`, `api.special_marker_stock[_movement]`, `api.sponsorship`, `api.operator_rollup`, `api.sponsor_rollup`, `api.my_partner_{org,member,scope,invite}` and the budget columns of `api.offer` all answer to `auth.uid()` + `has_*_scope` | Whoever can obtain a Supabase session for a staff member's email (email OTP, or the player app on the same account) reads those views with **no passkey**. The plan's "Staff / manager: passkey session" row (line 445) names "RLS helper `private.has_facility_scope()`" as the enforcement, which only works on a JWT; that reads as assuming the minted-JWT variant, where the JWT is the passkey's output (an inference). Under any variant where partner authority is not a Supabase JWT, these grants are a bypass | D12, section 5.5 |
| G2 | `partner_scope` is per org. A member of an org holds **every** scope row of the org, whatever the invite's `facility_id` says (the invite columns narrow nothing on accept) | "Grant is a subset of the inviter's own scope" (plan line 839) is under-defined | The one-facility-per-facility-org invariant, 5.2 |
| G3 | The operator's reach to a facility is "any `facility_programme` row for its trail", including `declined` and `left` | An operator can invite staff into a facility that has left the programme | Raised for the gate in 6.1; a `participation` filter is a one-line change in `has_facility_scope` |
| G4 | `partner_invite` rows are never purged (they carry `invitee_email`) | Unbounded retention of staff email addresses | Section 9 |
| G5 | No CORS handling | A browser PWA cannot call any function | S1.2, section 4.6 |
| G6 | `api.my_partner_invite` returns `token_hash` and `invitee_email` of every pending invite to **every member of the org, staff included** | Mild (the token is 256-bit and hashed) but it is staff-visible PII | Revoked with the rest of G1 |

## 3. The mechanism decision

The plan's two options, plus the hybrid it hints at (SimpleWebAuthn that mints a project JWT), against the proposed direction (C).

### 3.1 Comparison

| Criterion | A: Supabase Auth passkeys | B: SimpleWebAuthn, mints a project JWT | C (proposed): SimpleWebAuthn, opaque DB sessions |
|---|---|---|---|
| Status | The Supabase docs page says "Passkey support is experimental ... may change without notice" and needs an opt-in in the client `[verified 2026-10-04: docs page read from the supabase/supabase repo, master]` | Library mature (v14.0.3 on the registry `[verified: registry query]`); the minting is custom | Same library; the session layer is custom |
| User verification **required** | The handlers call `BeginDiscoverableLogin()` and `BeginRegistration(user, WithExclusions(...))` with no UV or resident-key option, and the docs show no setting `[verified: three handler files read from supabase/auth master; whether the hosted product differs is unverified]` | Ours: `required` (library output and a software-authenticator test, section 14) | Same as B |
| Proof that a session came from a passkey | A passkey login ends in the ordinary `issueRefreshToken(... PasskeyLogin ...)` `[verified: source]`. Whether the JWT's `amr` records it is `[unverified - training knowledge]`; an email-OTP session otherwise looks the same | The token exists only after verification | The session row exists only after verification |
| New secret in an Edge function | None | **The project JWT signing secret**: a function holding it can mint a token for any uid and any `role` claim. This contradicts the repo's lint posture (the service key appears in exactly two places, `privileged.ts:445-448`). Whether the project uses asymmetric signing keys that a function cannot use is `[unverified]` | None. The token is random; the database stores a hash |
| Revocation | GoTrue session and JWT lifetimes | A minted JWT is valid until `exp` unless every function also checks the database | Instant: checked in the database on every call |
| Clone detection | The handler stores the sign count; `CloneWarning` is referenced in none of the three files read `[verified: grep]` | Ours | Ours |
| Per-role session length (admin short) | Global GoTrue settings `[unverified]` | Ours via `exp` | Ours |
| Offline countersign (plan §7.6 case 2, A60) | No such API | Ours | Ours |
| Passkey-gated reads through PostgREST | No (the JWT is reachable by email OTP) | Yes, if the JWT is only ever minted after a passkey | **No, by design**: partner reads move to Edge reads and the views are revoked (D12) |
| Supply chain | None | 25 npm packages + the signing secret | 25 npm packages |
| Build cost | Lowest | Highest | Middle |

### 3.2 Reading the table honestly

- **B's one real advantage is the read path.** A passkey-minted Supabase JWT is the only variant under which the plan's `has_facility_scope(auth.uid())` views stay usable by the portal. C gives that up on purpose and pays for it with Edge reads (section 5.5). The price of B is a secret that can mint anything, in the same process as the handlers, and an authority that outlives revocation by the JWT lifetime. This repo has spent three PRs moving the other way (edge doc sections 12-14).
- **A is the cheapest and probably the right end state**, and it is not available for P5.1a: it is experimental, it cannot be shown to enforce UV, and it cannot show a downstream function that a session came from a passkey. Credentials cannot be migrated later (private keys do not move), but a re-enrolment under the same RP ID is one passkey tap per person, so the lock-in is small.
- **C's weak point is that the Edge runtime is the verifier.** The database cannot check an ECDSA signature (no extension on a hosted Postgres does that `[unverified - training knowledge]`). A compromised runtime can therefore ask the minter to mint a session for any member. That is R6 again, not a new class, and 4.4 and 11 say what is done about it and what is not.

### 3.3 Verdict and revisit triggers

C, as the owner proposed. Revisit A when **all** hold: Supabase passkeys are GA; the project can force UV required; a function can prove the method of a session (an `amr` entry or an `auth.sessions` column) and a short admin session can be enforced; and the player app wants passkeys anyway. The migration then re-enrols every staff member once; the tables in section 5 stay (sessions, PIN, TOTP are independent of where the passkey is verified).

## 4. Architecture

### 4.1 Principals, factors and session policy

| Principal | Enrolment | Sign-in | Step-up | Session idle / absolute `[proposed]` | Concurrent |
|---|---|---|---|---|---|
| Staff | invite, email OTP, passkey, PIN | passkey (UV) | PIN (class A1) | 30 min / 8 h | 3 |
| Manager | same | same | PIN (A1); a **fresh** PIN, at most 30 s old (A2) | 30 min / 8 h | 3 |
| Operator | invite from an admin, OTP, passkey, TOTP | passkey, then TOTP (`aal` 2) | TOTP at most 5 min old (A3) | 15 min / 4 h | 3 |
| Admin | a row in `app.admin_user` (written by ops, E17), then a one-time enrolment token from another admin (the first admin: a token minted by the project owner), passkey, TOTP | `aal` 2 | TOTP at most 5 min old for every A3 action | 10 min / 1 h | 2 |
| Sponsor | none before P6. The binder refuses a member whose only active role is `sponsor` | - | - | - | - |
| App-review demo account | refused by the binder (plan §4.7.7: any partner route is 403) | - | - | - | - |

The assurance a session needs is the **highest role the person holds** (admin > operator > manager or staff), recomputed on every call. A person promoted to operator keeps working at `aal` 1 until they sign in again; every A3 action refuses them until then.

Why these numbers (all `[proposed]`): a pro-shop shift is about 8 hours; re-authentication is one passkey tap; staff sessions must outlast a quiet hour at the till, which is why idle is 30 minutes and not 5. Admin and operator sessions run on personal laptops. The owner should tune them from pilot telemetry (open question Q2).

### 4.2 The request path

```
PWA --Authorization: Bearer gr_ps_<43 chars>--> Edge function (verify_jwt = false)
  1. CORS: exact origin, else no CORS headers; strict zod body, 64 KB cap (http.ts MAX_BODY_BYTES)
  2. sha256(token) in the Edge. The raw token is never logged, never stored, never sent to the database
  3. openScopedTx("partner", partnerBind(hash))
       SET LOCAL ROLE edge_actor; timeouts;
       select private.bind_partner_session(hash)   -- binds kind='partner', actor_uid, session_id
       post-bind assertion: private.actor_uid() equals the uid the binder returned
  4. handler op -> private.<action>_for_partner(...)    (a named definer, never a table statement)
       first statement: private.partner_authorize(facility, trail, roles[], class)
  5. write + audit in the same transaction; response `cache-control: no-store`
```

`bind_partner_session` accepts a session only if **all** hold: the hash exists; `revoked_at` is null; idle and absolute expiry have not passed; the bound credential exists and is not revoked; the user is not a demo account; the user holds at least one non-revoked membership whose role is not `sponsor`, or is in `app.admin_user`. Every failure raises the **same** SQLSTATE and message and the handler answers one constant `401` body, so there is no oracle between unknown, expired and revoked. It also advances `last_seen_at`, but at most once a minute, so a busy till does not write on every call.

`openScopedTx` needs a small extension (S1.2): today an actor kind must know the expected uid before it binds (`privileged.ts:349`). The partner bind returns the uid it bound, and the assertion compares that with `private.actor_uid()`; the handler never supplies a uid.

### 4.3 The binding kind and the one authorization seam

Two changes to the actor-binding core (a new migration; `0001`-`0045` stay immutable):

1. `private.actor_binding.kind` gains `'partner'`, and the table gains a nullable `session_id`. `bind_actor_internal` is extended (or `bind_partner_session` writes the row itself under the same policies) so that **only** `bind_partner_session` can produce `kind = 'partner'`.
2. Every existing user-lane definer already refuses a non-`user` binding (E3), so a partner-bound transaction cannot call `offline_seed_for_actor`, `delete_my_data_for_actor`, `export_my_data_for_actor` or the activation definers. The reverse is the new rule: **every partner-lane definer refuses a `user` binding.** Both directions get a pgTAP cell (PA-3).

`private.partner_authorize(p_facility_id, p_trail_id, p_roles, p_class)` is `SECURITY DEFINER`, `search_path = ''`, EXECUTE for **nobody** (called only from sibling definers, the `offline_seed_derive` shape). In order it checks:

1. a `partner` binding exists in this transaction;
2. the bound session row is **still live in this transaction** (a revocation that committed after the bind is seen, because the transaction is READ COMMITTED);
3. the role and scope **re-read from `partner_member` and `partner_scope`** through `has_facility_scope` / `has_trail_scope` with the explicit role list (E6), never a cached value, never a claim;
4. the session's `aal` and step-up state meet the action class (6.3);
5. then it returns the actor uid.

Every refusal is `42501`, which the handler maps to `403` (or `404` where the plan's matrix says a foreign id must not be probeable, plan §4.7.7).

**Making "forgot to call it" fail the build.** A new inventory check (check 14, next to checks 9-13 in `tools/db/verify-function-inventory.mjs`): every function whose name ends `_for_partner` must reference `private.partner_authorize` in its own body, and no function outside that family may read `kind = 'partner'` bindings. A must-fail fixture is a planted `_for_partner` function without the call. This is the same idea as check 13 (scan definer bodies) and costs one query.

### 4.4 The minter role

A role `edge_partner_minter`, shaped exactly like `edge_signin_minter` (`0041:61-103`): `NOLOGIN NOINHERIT NOBYPASSRLS`, a member of nothing, `edge_gateway` its only member `WITH INHERIT FALSE, SET TRUE`, `USAGE` on schema `private`, `EXECUTE` on exactly the mint definers and nothing else (checked by check 12). `openScopedTx` gains a kind `"partner_mint"` that runs as that role and binds nothing; the privileged lint's `privileged-mint-scope` rule is generalised to allow that kind only inside `openScopedTx` and one named caller module.

| Mint definer (EXECUTE: `edge_partner_minter` only) | What it does |
|---|---|
| `partner_challenge_issue(purpose, user_id?, invite_id?)` | 32 random bytes, `expires_at` at most 120 s out (CHECK) |
| `partner_challenge_consume(id)` | atomic `UPDATE ... SET consumed_at = now() WHERE consumed_at IS NULL AND expires_at > now() RETURNING ...`. **Committed in its own transaction before the Edge verifies**, so a failed verification burns the challenge (the same order GoTrue uses, `[verified: PasskeyAuthenticationVerify consumes the challenge first]`) |
| `partner_credential_lookup(credential_id)` | public key, sign count, user id; one uniform "not found" for unknown or revoked |
| `partner_session_mint(challenge_id, credential_id, new_sign_count, token_hash, assertion evidence)` | requires the challenge consumed, for this purpose, unused for a mint, at most 60 s old; advances the sign count by compare-and-set; writes the session; refuses a revoked credential or ineligible member; evicts the oldest session above the cap |
| `partner_invite_accept(token_hash, verified_uid, gotrue_session_id)` | 6.1 |
| `partner_credential_register_first(...)` | first credential of an invited member (6.1); a **later** credential is added by a signed-in member through an ordinary `_for_partner` definer |

**What this buys, and what it does not** (the 0041 table, restated for this lane):

| Attacker | Result |
|---|---|
| A handler bug or injected statement in an `edge_actor` partner transaction | cannot mint (`42501`); cannot bind another member (no `bind_actor`-style path yields `kind = 'partner'`) |
| The same in a system lane (`edge_system`) | cannot mint |
| A statement that can also `SET ROLE` (`edge_gateway` holds SET on every edge role) | **can reach the minter role**, as it can reach `edge_actor` today (the "KNOWN LIMIT (R6)" of 0041). It can mint a session for any member, because the database cannot verify the signature |
| A fully compromised runtime (R6) | unchanged: it can already `bind_actor(<any uid>)` and act through every **user**-lane definer. For the **partner** lane it can mint a session for any member (above), and it sees each real token and PIN that passes through it |

The mint stores the raw assertion (authenticator data, client data JSON, signature; about 400 bytes) on the session row for 30 days. That does not prevent a forged mint; it makes one **detectable later** by an out-of-band re-verifier that checks every mint's assertion against the credential's stored public key. That re-verifier is not built here; the evidence is retained so adding it later needs no migration (section 11, R-P1).

### 4.5 API surface

All under `/v1/partner/`. Three functions (one directory each, so the derived function inventory and the matrix stay small, plan §4.7.1a): `partner-session`, `partner-invites`, `partner-members`. Later slices add the plan's `partner-attest`, `partner-offers-redeem`, `course-qr`, `partner-entitlements-redeem`, `stock-admin`, `offers-admin`, `programme-config` and friends; each must carry matrix cells for every id it accepts.

| Route | Auth | Purpose |
|---|---|---|
| `POST session/options` | none (minter) | sign-in challenge (usernameless: `allowCredentials` empty, UV required) |
| `POST session` | none (minter) | `{challengeId, assertion}` to `{token, expiresAt, aal}` |
| `GET session` | session | who am I: roles, facility and trail scopes, step-up state, required assurance (all re-read) |
| `DELETE session` | session | sign out (revokes this session) |
| `POST session/step-up/pin` | session | `{derived}` sets `step_up_until` and `fresh_pin_until` |
| `POST session/step-up/totp` | session | `{code}` sets `aal` 2 and `mfa_until` |
| `POST session/lock` | session | clears every step-up window now |
| `POST invites` | session, A2 | create (rank and scope rule, 6.1) |
| `GET invites`, `DELETE invites/{id}` | session | list / revoke, by definer, scoped |
| `POST invites/accept/start` | none | `{token}`: sends the OTP to the address on the invite (server-side, anon key) |
| `POST invites/accept/verify` | none (minter) | `{token, code}`: verifies the OTP, closes the GoTrue session, returns an enrolment challenge |
| `POST credentials/options`, `POST credentials` | invite-bound or session | register; the first one mints the first session |
| `GET`, `PATCH`, `DELETE credentials[/{id}]` | session | list, relabel, revoke (own; or a manager's, 6.5) |
| `POST pin`, `POST members/{id}/pin-reset` | session | set/change own PIN; reset another member's (A2) |
| `POST totp/enrol`, `POST totp/confirm` | session | operator/admin |
| `POST members/{id}/revoke`, `POST orgs/{id}/sessions/revoke-all` | session, A2 | member revoke; the "panic button" |

Errors follow `_shared/http.ts` (`errorResponse(status, code, message)`); a bad session is always the same `401 unauthenticated`.

### 4.6 Transport: header in memory, not a cookie

Chosen: the session token lives in a JS variable in the PWA and travels as `Authorization: Bearer gr_ps_<43 base64url chars>` (the prefix makes it greppable by secret scanners). It is never written to `localStorage`, `sessionStorage` or IndexedDB.

| Concern | HttpOnly Secure SameSite=Strict cookie | Header in memory (chosen) |
|---|---|---|
| Needs a same-site API | **Yes.** The functions are served from the Supabase project host, a different registrable domain from `golfraven.<tld>` `[unverified - training knowledge: default function URL shape]`. A Strict cookie is not sent on a cross-site fetch at all. The two ways round it are a same-site proxy (a new component that sees every token) or `SameSite=None`, which loses Strict and meets Safari's third-party cookie blocking on the iPad `[unverified - training knowledge]` | No |
| CSRF | Ambient authority: needs SameSite or a CSRF token | **None by construction**: nothing is attached automatically. A custom `Authorization` header forces a CORS preflight, and the allowed origin is exact |
| XSS, token theft | The page cannot read the token | A script on the page can read it. **Mitigated, not removed**: strict CSP, no third-party script, no inline script |
| XSS, token *use* | Same page can still call the API with the cookie | Same. Neither option stops riding a live session; the PIN window, caps and the idle timeout bound it |
| Reload or iOS memory eviction | Survives | Lost: one passkey tap to sign in again. Accepted; the PIN is asked again anyway |
| Log exposure | Cookie headers are often redacted | `Authorization` is the header log tools redact by default `[unverified]`; the token is also never logged by our code (a source scan, as for the offline seed, money doc line 3817) |

Hardening that goes with the choice (S1.2 and S7a):

- **CORS** is a new `_shared` helper: the allowed origin is one exact string from an environment variable, `Vary: Origin`, `Access-Control-Allow-Headers: authorization, content-type`, no `*`, no credentials mode, `OPTIONS` answered without touching the database. A request from any other origin gets no CORS headers.
- **`verify_jwt = false`** on the three partner functions, so the gateway does not demand a Supabase JWT in the header the partner token occupies `[unverified - training knowledge: per-function setting in config.toml; edge doc section 15 item 7 already treats the gateway check as not-the-authentication]`. A mistakenly enabled gateway check fails closed (every call 401). The cost is losing the gateway's free filter of header-less floods; the per-IP-hash buckets in section 8 replace it.
- **CSP** for `apps/partners` (served with `_headers` on the static host `[unverified: host features]`): `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' <functions origin>; manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`, plus `Referrer-Policy: no-referrer`, `Permissions-Policy: publickey-credentials-get=(self), publickey-credentials-create=(self)`, `Cross-Origin-Opener-Policy: same-origin`. `require-trusted-types-for 'script'` is desirable and `[unverified]` on the iPad's Safari.
- **Optional later, not built:** proof of possession. The session is bound to a non-extractable WebCrypto key generated at sign-in, and each request carries a signature. That turns the in-memory token from "stealable" into "rideable only from the page", which is what HttpOnly buys, without a same-site proxy. It is the natural S7 hardening if the gate wants it.

## 5. Data model

### 5.1 New tables (all in `app`)

Every one: `ENABLE` and `FORCE ROW LEVEL SECURITY`; `REVOKE ALL ... FROM PUBLIC, anon, authenticated`; **no** grant to `edge_actor`, `edge_system`, `edge_partner_minter` or `service_role` (these hold credential material; 0045 gave `service_role` SELECT on its replay table, these get nothing). Access is only through the definers in 5.3, and `private_definer` policies are keyed on the **actor binding**, never on a settable GUC (the HARD RULE, E12).

| Table | Key columns | Notes |
|---|---|---|
| `partner_credential` | `id uuid pk`, `user_id` (FK `auth.users` cascade), `credential_id bytea unique` (at most 1,023 bytes), `public_key bytea` (COSE), `alg smallint`, `sign_count bigint`, `transports text[]`, `backup_eligible bool`, `backup_state bool`, `aaguid uuid`, `label text` (at most 40, member-chosen, e.g. "Shop iPad"), `created_at`, `last_used_at`, `revoked_at`, `revoked_by` (FK, set null), `revoke_reason` | at most 5 active per user (checked in the register definers); the WebAuthn user handle is the uuid's 16 bytes `[proposed]` (not PII on its own) |
| `partner_auth_challenge` | `id uuid pk`, `challenge bytea` (32 random bytes), `purpose` in (`sign_in`, `register`; `countersign` reserved for 6.7), `user_id` (register only), `invite_id`, `created_at`, `expires_at`, `consumed_at`, `minted_session_id` | CHECK `expires_at <= created_at + 120 s` for sign_in and register |
| `partner_session` | `id uuid pk`, `token_hash text unique` (64 hex, CHECK), `user_id`, `credential_id`, `aal smallint` in (1, 2), `created_at`, `last_seen_at`, `expires_at` (absolute, fixed at mint), `step_up_until`, `fresh_pin_until`, `mfa_until`, `revoked_at`, `revoke_reason`, `mint_challenge_id`, `mint_authenticator_data`, `mint_client_data_json`, `mint_signature` | the assertion columns are the 4.4 evidence |
| `partner_pin` | `user_id pk`, `salt bytea`, `iterations int`, `pepper_kid text`, `verifier bytea`, `failed_count smallint`, `last_failed_at`, `next_attempt_at`, `locked_at`, `must_change bool`, `set_at` | verifier is `HMAC-SHA256(pepper, PBKDF2-SHA256(pin, salt, iterations))` |
| `partner_totp` | `user_id pk`, `seed_version int`, `enrolled_at`, `confirmed_at`, `last_step bigint`, `failed_count`, `locked_until`, `revoked_at` | the seed is **derived** (below), never stored |

**PIN pepper and TOTP seed** use the offline-seed pattern (`0045:129-160`): a Vault secret (`partner_pin_key`, `partner_totp_key`; at least 32 bytes), read in **one** `SECURITY DEFINER` core with `EXECUTE` for nobody, `public.hmac` in Postgres, a labelled fixed-length message (`'golfraven/partner-totp/v1' || 0x00 || user_id || seed_version`). Staging and production keys differ. The Vault call and `public.hmac` are `[unverified]` on a real project, exactly as 0045 records.

### 5.2 Changes to existing tables

| Object | Change | Why |
|---|---|---|
| `private.actor_binding` | `kind` CHECK adds `'partner'`; new nullable `session_id uuid` | D5 |
| `app.partner_invite` | add `accepted_by` (FK `auth.users`, set null), `revoked_at`, `revoked_by`, `attempts smallint default 0`; CHECK `token_hash ~ '^[0-9a-f]{64}$'`; CHECK `expires_at <= created_at + interval '7 days'` | E18; the 72 h default is the writer's, the CHECK is the ceiling |
| `app.partner_scope` | a trigger: an org of kind `facility` may hold **at most one** scope row, and it is a `facility_id`; plus `UNIQUE (org_id, facility_id)` | G2. A chain is one org per facility with the person a member of several; the portal shows a switcher. The request names the facility, and `partner_authorize` checks it per call, so there is no "current org" in the session |
| `app.partner_member` | an `AFTER UPDATE OF revoked_at` trigger revokes that user's sessions; revoking the **last** active membership deletes the user's `partner_pin` and `partner_totp` rows | D11 |
| `private.function_inventory` | new column `expected_edge_partner_minter` (0041 added the same for the signin minter) | E9 |
| `api.offer` | redefine the five scope-conditional budget and eligibility columns to constant NULL for everyone (`CREATE OR REPLACE VIEW` can append but not drop columns, `0024_evidence_queued_claims.sql:73-76`); the partner read moves to Edge | G1; the view stays for players |

### 5.3 Functions

| Function | EXECUTE | Notes |
|---|---|---|
| `private.bind_partner_session(token_hash)` | `edge_actor` | the only producer of a `partner` binding; 4.2 |
| `private.partner_authorize(...)` | nobody | 4.3 |
| the mint definers of 4.4 | `edge_partner_minter` | refuse inside any actor-bound transaction (the 0041 rule) |
| `private.partner_whoami_for_partner()`, `partner_session_revoke_for_partner(...)`, `partner_session_lock_for_partner()` | `edge_actor` | |
| `private.partner_pin_params_for_partner()`, `partner_pin_set_for_partner(...)`, `partner_pin_verify_for_partner(derived)`, `partner_pin_reset_for_partner(member)` | `edge_actor` | 6.3 |
| `private.partner_totp_enrol_for_partner()`, `partner_totp_verify_for_partner(code)` | `edge_actor` | the HOTP is computed **in SQL**, proven against the TypeScript oracle and RFC 6238 vectors, as the money doc requires for the staff offline code (E12) |
| `private.partner_invite_create_for_partner(...)`, `..._revoke_...`, `..._list_...`; `partner_member_revoke_for_partner`, `partner_credential_register_for_partner`, `partner_credential_revoke_for_partner`, `partner_org_sessions_revoke_for_partner` | `edge_actor` | |
| `private.purge_partner_challenges()`, `purge_partner_sessions()`, `purge_partner_credentials()`, `purge_partner_invites()` | `edge_system` | section 9; each `EXECUTE` grant is the same owner-approved shape as 0040 and needs the same sign-off |

Every function: `SECURITY DEFINER`, owned by `private_definer`, `search_path = ''`, inside the ownership bracket (`SET ROLE private_definer` ... `RESET ROLE`, `0045:129-132,344`), `REVOKE ... FROM PUBLIC` then the grants above, a row in `private.function_inventory`, and must-fail cells.

### 5.4 The invariants checklist (what the gate should find in the migrations)

1. Every new table has FORCE RLS and no grant to `anon`, `authenticated`, any edge role or `service_role`. `private.edge_policy_allowlist` and its fixture are **unchanged** (edge roles hold no table privilege).
2. Every `private_definer` policy is narrow, keyed on the binding, and has a `private.definer_policy_allowlist` row plus a line in `supabase/tests/fixtures/definer_policy_exprs.txt`.
3. Every FK to `auth.users` is classified in `private.pii_retention_policy` (`delete_row`, or `set_null` for `revoked_by` and `accepted_by`) **and** has a `private.pii_export_policy` row (credentials: `export` of metadata without the public key; sessions, PIN, TOTP, challenges: `exclude` with a reason). Without them `delete_my_data` raises (E9). `delete_my_data` and `export_my_data` were last rebuilt in 0045 and 0044: the next change starts from those copies.
4. Every function has a `function_inventory` row, including `expected_edge_partner_minter`.
5. Checks 9-13 in `tools/db/verify-function-inventory.mjs` and `supabase/tests/matrix/10_function_inventory.sql` extend to the new role (the 0041 edits are the template: role attributes, membership closure, "nothing but the mint EXECUTEs", no privilege on any relation, no CREATE). Check 14 is new (4.3). Each has a must-fail fixture.
6. `tools/db/check-migrations-immutable.sh` passes (no earlier migration is edited).
7. The privileged-file lint (`tools/service-role-lint/src/privileged-lint.ts`) keeps its rules: no `service_role`, no new `Deno.env` read outside the allow-listed shapes, the new kinds only through `openScopedTx`. New env reads are limited to the exact CORS origin string, read in `privileged.ts` or the CORS helper; nothing secret is added to the environment (the pepper and TOTP key live in Vault).
8. Each new function directory is added to the three CI lists (`supabase/tests/unit/ci-function-lists.test.ts` fails the build until it is).
9. A matrix cell exists for every partner function times every id it accepts, including a foreign id (plan §4.7.1a).

### 5.5 Revoking the PostgREST partner-lane read surface (D12)

One migration in S1.1: `REVOKE SELECT ... FROM authenticated` on the views below, and redefine `api.offer` without the scope-conditional columns. The base tables, policies and helpers stay (harmless; they protect against a future grant). The views have no consumer yet, so nothing breaks except `supabase/tests/matrix/06_partner_scope_matrix.sql`, whose cells are rewritten into "denied" cells for every actor, and the replacement Edge reads ship with the slice that owns the data.

| View | Replaced by | Slice |
|---|---|---|
| `api.staff_shift_log` | `GET /v1/partner/shift-log` (A0, staff and manager of the facility) | S3 |
| `api.staff_activity` | `GET /v1/partner/staff-activity` (manager, operator) | S3 |
| `api.special_marker_stock`, `..._stock_movement` | stock read in `stock-admin` | S5 |
| `api.facility_programme`, `api.marker_code_batch`, `api.facility_qr`, `api.sponsorship`, `api.operator_rollup`, `api.sponsor_rollup` | `programme-config`, `qr-print`, `sponsorships-admin`, rollup reads | S2b, S6 |
| `api.my_partner_org`, `..._member`, `..._scope`, `..._invite` | `GET session` and `GET invites` | S1.3 |

Left alone on purpose: `api.trail_programme`, `api.special_marker_availability` (readable by all authenticated players by design, plan §4.7.3) and the player-own `my_*` views.

## 6. Flows

### 6.1 Invite, accept, enrol

The invite rule, in the database (`partner_invite_create_for_partner`):

- The inviter's session is live and meets class A2 (a fresh PIN) or A3.
- **Role strictly below the inviter's own** (`partner_role_rank`, E6): a manager may invite staff; an operator may invite staff and managers; only an admin invites operators or sponsors (a sponsor invite stays disabled until P6).
- **Grant is a subset of the inviter's reach.** With the one-facility-per-org invariant (5.2) an invite names an org, and the inviter must pass `has_facility_scope(inviter, <that org's facility>, <roles ranking above the invited role>)`, which already covers both "member of that org with a higher role" and "operator of a trail that includes the facility" (E6). Cells: manager invites at another facility: `403`; manager invites a manager or operator: `403`; operator invites at a facility not on its trail: `403` (plan §4.7.7).
- *For the gate (G3):* that operator reach ignores `participation`. Filtering `declined` and `left` out of `has_facility_scope`'s operator leg is a one-line change and is recommended.
- An invite to an org where the invitee already has an **active** membership is refused (`409`); a **revoked** membership is reactivated with the invite's role, the old sessions stay dead (6.5) and the PIN is set again (`must_change`).
- The token is 32 random bytes, `gr_inv_` + base64url, generated in the Edge; **only its SHA-256** reaches the database (`token_hash`, 64 hex). The link is `https://partners.golfraven.<tld>/invite#<token>`: a fragment is never sent to a server, so no CDN or access log holds it, and a mail scanner that prefetches the link cannot consume it (consumption is a POST that also needs the OTP). Expiry 72 h `[proposed]`, hard ceiling 7 days (CHECK).

Acceptance, all in Edge-plus-database, **with no Supabase session on the staff device**:

1. `POST invites/accept/start {token}`. Rate-limited (section 8). The Edge asks the database (a minter definer) for the `invitee_email` of an unexpired, unaccepted, unrevoked invite with `token_hash = sha256(token)`; if there is one it **sends an OTP to that address** (no email is typed, so a token holder cannot redirect the code), and either way it answers a constant body, so the endpoint is neither an invite-existence nor an email oracle.
2. `POST invites/accept/verify {token, code}`. The Edge calls `verifyOtp` with the anon key (the E19 verifier), takes the user id and the GoTrue `session_id`, then **closes that session** (`closeSession`, E19). The minter's `partner_invite_accept(token_hash, uid, gotrue_session_id)` then, in one transaction: locks the invite; refuses unless it is live and **`lower(btrim(auth.users.email)) = lower(btrim(invitee_email))` in SQL** (one implementation of the normalisation, the lesson of 0041 L2), the email is confirmed, and the GoTrue session row for that uid is fresh (the 0041 mechanism, `[unverified]` columns, E19/0041); inserts or reactivates `partner_member`; sets `accepted_at` and `accepted_by`; increments `attempts` (an invite locks after 10); issues a `register` challenge bound to that uid and invite.
3. WebAuthn create in the PWA (`residentKey: required`, UV required, `attestation: none`, exclude the member's existing credential ids). `POST credentials` verifies in the Edge (`verifyRegistrationResponse`, `requireUserVerification: true`, exact origin and RP ID), then `partner_credential_register_first` stores it and the Edge mints the first session.
4. The PWA forces setting the PIN (6.3) before it will show anything, and, for an operator or admin, enrolling TOTP (6.4).

A forwarded link fails twice: the OTP goes to the invited mailbox, which the forwardee cannot read, and `partner_invite_accept` itself refuses any uid whose verified email is not the invite's (`403`, plan §4.7.7 and AT 16; the cell calls the definer directly with a different account, because the HTTP path cannot reach that state). An invite for an address that signs in with an Apple private-relay address fails closed (the relay address is a different email); the player-account linking rules do not apply here (plan §3.4 rule 3).

### 6.2 Sign-in

1. `POST session/options` returns a 32-byte challenge, `userVerification: required`, empty `allowCredentials`, `timeout: 120000` (verified to be what `generateAuthenticationOptions` emits when asked).
2. The PWA calls `navigator.credentials.get`. On a shared iPad the operating system's chooser is expected to list every staff passkey registered for this RP ID on that device and the person picks theirs `[unverified - training knowledge; S0 checks it on a real iPad]`. No email or username is typed, so there is no username oracle.
3. `POST session`: the Edge consumes the challenge (own transaction), looks the credential up, and runs `verifyAuthenticationResponse` with the stored key and counter, exact origin, exact RP ID, `requireUserVerification: true`. It also checks `response.userHandle` equals the credential owner's handle (the library does not). It then calls `partner_session_mint`.
4. Counter policy `[verified: software-authenticator test]`: a non-zero counter that does not strictly increase is **refused** (equal and lower both), and a `0` against a stored `0` is **accepted** (the library's behaviour for authenticators that keep no counter). A refused regression writes an `audit_log` row and raises an operator alert (the plan §8.3 alert path), and blocks that assertion; the credential is not auto-revoked (a flaky authenticator would lock a person out), a manager decides. Synced passkeys report `0`, so **clone detection does not exist for them**: section 11, R-P3.
5. `aal` is 1; an operator or admin must continue with TOTP before any A3 action (6.4).

Replay of an assertion fails because the challenge is single-use and already consumed; replay of a token needs the token.

### 6.3 Step-up PIN and the action classes

The passkey proves the credential (and, on a shared iPad, the device); the PIN picks the **person** (plan §9.2, FM-20). It is not authentication by itself: it is useless without a live session of the same member.

**PIN rules.** Exactly four digits. Refused at set: repeated digits, ascending and descending runs, and a short list of the most common PINs (for example `1234`, `4321`, `1212`, `2580`). Set or changed only in a session with a passkey assertion in the last 5 minutes plus the current PIN (unless `must_change`).

**Where the secret goes.** The Edge fetches the member's salt and iteration count (`partner_pin_params_for_partner`, refused while locked), runs PBKDF2-HMAC-SHA256 with the WebCrypto API (`[proposed]` 600,000 iterations, the OWASP-style figure from training knowledge `[unverified]`; the value is stored per row so it can rise on the next set), and sends only the **derived** bytes to `partner_pin_verify_for_partner`. In Postgres the definer locks the `partner_pin` row, applies the lock and backoff rules, computes `HMAC-SHA256(pepper, derived)` with the Vault pepper (E12 pattern), compares, and updates the counters and the session in the same statement sequence. The Edge runtime sees the PIN while it types and nothing it can reuse afterwards; the stored verifier is useless without the Vault pepper.

**Honest arithmetic.** With the pepper unknown, a stolen table gives an attacker nothing to test against. With the pepper also known, 10^4 PINs at 600,000 rounds is about 3,230 s (about 54 minutes) on one core as measured (323 ms per derivation on this host, section 14). The KDF therefore protects little; the pepper and the online cap do the work, and the doc does not claim otherwise. The 600,000 figure also costs about a third of a second of CPU per PIN entry in the Edge; if the hosted runtime's CPU budget is tight the floor is 210,000 (115 ms measured), because the argument above does not depend on it. `[unverified]`: the hosted runtime's CPU limit (S0 measures it).

**Lockout.** Counters live in the `partner_pin` row, not in rate-limit buckets: after the 3rd consecutive failure the next attempt is refused for 30 s, after the 4th for 5 min, after the 5th the member is **locked** (`locked_at`). 20 failures in a day lock regardless of successes between them. A lock survives new sessions. Unlock: a manager (or operator, or admin) of an org the member belongs to, class A2, never for themselves; it sets `must_change`, so the person chooses a new PIN under a fresh passkey assertion and nobody else ever learns it. A lone manager is reset by an operator; an operator by an admin. Every failure, lock and reset writes `audit_log`.

**Action classes.** `partner_authorize` takes the class; the table is the policy.

| Class | Needs | Examples |
|---|---|---|
| **A0** | a live session | reads (`GET session`, shift log, own stock), sign-out, lock, list own credentials |
| **A1** | A0 and `step_up_until > now()` (a PIN within **90 s**, not sliding) | `partner-attest`, "Marker sold" token mint (`course-qr`), offer redeem, special-marker hand-over (R1 scan and R2 token), stock movements by staff, the offline-voucher countersign |
| **A2** | A0 and a PIN within **30 s** (one prompt per action) | invite create or revoke, member revoke, PIN reset, credential revoke of someone else, "Rotate PIN" for the course QR, revoke-all |
| **A3** | `aal` 2 and `mfa_until > now()` (a TOTP within **5 min**) | operator and admin actions: programme and sponsor config, offer approve, `qr-print`, `codes-generate`, `settlement-export`, held-review resolve, stock reconciliation overrides |

The window is per session, set by that session's PIN. A second person who walks to the iPad inside someone's 90 s window can still act as them; that residual is the cost of not asking a PIN per sale, and the "Lock" button, the idle timeout and the window length are what bound it. Pilot telemetry decides whether A1 should be per action (Q2).

### 6.4 TOTP for operator and admin

Enrolment shows the derived seed once as an `otpauth://` QR (SHA-1, 6 digits, 30 s: what authenticator apps support reliably `[unverified - training knowledge]`), and `confirm` needs a valid code. Verification is `partner_totp_verify_for_partner(code)`: HOTP computed in SQL, window plus or minus 1 step, replay refused by `UPDATE ... SET last_step = $s WHERE last_step < $s`, 5 failures in an hour lock for 15 minutes, a success sets `aal` 2 and `mfa_until`. Reuse: the SQL HOTP core is the same primitive the money doc already requires for the staff offline-code verifier (E12), so it is written once and proven against `_shared/offline-code/totp.ts` and the RFC 6238 vectors.

### 6.5 Revocation, recovery, self-attest

- **Authority is per call.** Revoking a member or deleting a scope row takes effect on the **next call** because `partner_authorize` re-reads (acceptance test 1). A member revoke also revokes that user's sessions (trigger), because otherwise a **reactivation** would resurrect them.
- **Credentials.** A credential revoke kills the sessions bound to it (checked per call through the join). A member can revoke their own; a manager can revoke a member's. The stolen-iPad button is `orgs/{id}/sessions/revoke-all` (A2) plus revoking the credentials registered from that device (their `label` is how a manager finds them).
- **Recovery.** Email OTP **never** adds a credential to a member who has an active one. A member adds a second passkey while signed in (strongly encouraged at enrolment). A member who lost every device is recovered by a manager (an operator for a lone manager, an admin for an operator) who revokes the member's credentials and issues a fresh invite; the member then repeats 6.1. Nobody can recover themselves by mailbox alone, because that would make the email account the real credential.
- **Self-attest** (plan AT 16, A2-21). Enforced in three places: the partner definers compare the target player's uid with the bound actor (`22023`, mapped to `422`); the existing CHECK on `attestation` and the 0045 recorder stay as the backstops (E7). The related plan cell, "a manager invites an account on the same device as their own: the first attest goes to `held_review` plus `fraud_signal`", belongs to S3.

### 6.6 Admin actions and the audited surface

Admin passes every `has_*_scope` (E6). An admin session is short (4.1), always `aal` 2, and every A3 action writes `audit_log` with the actor, the action, the subject and no secret. This design adds no new admin power; it only makes the existing one reachable solely through a passkey, a TOTP and a short session.

### 6.7 Offline (plan §7.6)

- **Online staff, offline player** (the expected case): staff enter the player's handle and 6 digits on an online device. This needs the session and the money-doc verify-and-record definer; it is slice S3 and is **independent of WebAuthn offline**.
- **Both offline (conditional build):** the PWA holds up to 20 prefetched staff challenges and countersigns a voucher with the member's passkey. Two things stay `[unverified]`: that `navigator.credentials.get` against a stored challenge works in an installed PWA with no network (A60, to be settled by the S7e spike on a real iPad), and the storage lifetime of the challenge cache in an installed PWA on iOS `[unverified - training knowledge]`. The plan's prefetched challenges live in `app.checkin_challenge(staff_user_id, facility_id)` (plan §4.4), whose `edge_actor` insert policy currently forces `staff_user_id IS NULL` (edge doc section 4); issuing them needs a new partner definer.
- **What the design reserves now so it need not be redone:** challenge `purpose = 'countersign'` with a facility binding and a 24 h TTL (the plan's figure); an assertion verified later must belong to the same member as the session that uploads it; and `offline_code_bound_staff()` (`0045:181`) is keyed on `kind = 'user'`, so S3's verify-and-record definer, which runs under a `partner` binding, either extends that predicate or adds its own policy (allow-list and fixture change either way).

## 7. Supply chain and outbound hosts

| Item | Entry | State |
|---|---|---|
| Import map | `"@simplewebauthn/server": "npm:@simplewebauthn/server@14.0.3"` in `supabase/functions/deno.json` (the latest at authoring time `[verified: registry]`; pin the version current at S0) | to add |
| Allow-list | the exact same string in `tools/service-role-lint/pinned-import-targets.json` | to add |
| Lockfile | `supabase/tests/deno.lock`: **25 `npm` entries** for the Deno graph (the library, `@hexagon/base64`, `@levischuck/tiny-cbor`, fifteen `@peculiar/*`, `asn1js`, `pvtsutils`, `pvutils`, `reflect-metadata`, `tsyringe`, two `tslib` versions) `[verified 2026-10-04: deno info --json on a scratch import, Deno 2.5.2]`. Today the lock has 5 npm entries. Each needs a `sha512` integrity (the lint's `NPM_INTEGRITY`, `config.ts:337`) and a `specifiers` row | to add; the three CI function lists (check, cache, tamper step: `ci.yml:395,451,509`) need the new entrypoints |
| Outbound host | **none.** Registration with `attestation: none` and assertion verification ran with `--deny-net` after the packages were cached `[verified: 13 cases, section 14]`. The library also exports a `MetadataService` (`[verified: export list]`); that it downloads the FIDO metadata blob over the network is `[unverified - training knowledge]`, and it is **not used** here. Attestation formats other than `none` are not requested; that they would need root certificates is `[unverified - training knowledge]` | no allow-list entry; the pull-request checklist line "No new outbound host" stays true |
| Email OTP | goes through GoTrue with the anon key, as the player flow already does (E19); no new host | none |

The graph is five times the size of today's. That is the cost of the library (its X.509 and ASN.1 stack is there for attestation formats this design does not use). Options for the gate, in order of preference: accept it with the lock, the integrity check and a quarterly bump discipline (the repo's existing posture); or replace the library with a small in-tree verifier for the two ceremonies actually used (attestation `none`, ES256 and RS256 assertions: about 150 lines of CBOR, authenticator-data parsing and WebCrypto verification). The second removes 24 packages and creates the "own WebAuthn code" risk; this design recommends the first.

## 8. Rate limits

Reuses `private.hit_actor_rate_limit` and `hit_system_rate_limit` (E11). Pre-authentication buckets cannot use the actor limiter (no actor is bound), so they use system buckets keyed on a **hash of the client IP computed in the Edge** (the IP is never stored) `[unverified: that the forwarded-for header is trustworthy behind the gateway]`. A `partner` twin of `hitRateLimitForActor` (same definer body, partner binding) serves authenticated calls. Every number is `[proposed]`. The plan's existing caps (staff attest 60/staff/h, hand-over 5 failures/staff/h, `course-qr` token issue 60/staff/h, and the §8.3 cold-start caps) are unchanged.

| Endpoint | Key | Limit |
|---|---|---|
| `session/options` | IP hash; global | 60/h; 1,200/h |
| `session` (verify) | IP hash; credential | 10 failures/h; 5 failures per credential per hour, then a 15 min credential cooldown |
| any partner call | member | 1,200/h (alert, not block) |
| PIN verify | member | the in-row rules of 6.3 (3 / 4 / 5 consecutive; 20 a day) |
| TOTP verify | member | 5 failures/h, 15 min lock; a step cannot be reused |
| `invites` create | inviter; invitee email hash | 20/day; 3 per email per day |
| `invites/accept/start` | token hash; invitee email hash | 3 sends per token per hour; 5 failed OTP proofs per target per hour (the existing `reserve_signin_otp_attempt` / `release_signin_otp_attempt` pair, 0035) |
| `invites/accept/verify` | token | 10 attempts per invite, then locked |
| credential add / revoke | member | 10/h |

Concurrency is tested in pgTAP as for the existing limits (plan §4.7.8).

## 9. Retention and purge

Follows `retention-purge` (E13): bounded definers (a constant `LIMIT 5000` inside each, never a parameter), `EXECUTE` for `edge_system`, a try-lock per step, run from the hourly scheduler already specified in edge doc section 15.

| Data | Kept | Mechanism |
|---|---|---|
| `partner_auth_challenge` | expiry + 1 h | `purge_partner_challenges` |
| `partner_session` (including the assertion evidence) | 30 days after `expires_at` or `revoked_at` `[proposed]` | `purge_partner_sessions` |
| `partner_credential`, active | until the member's account is deleted (`delete_my_data`, the registry-driven pass) | - |
| `partner_credential`, revoked | 180 days after `revoked_at` `[proposed; counsel]` | `purge_partner_credentials` |
| `partner_pin`, `partner_totp` | until the last membership is revoked (trigger, 5.2) or the account is deleted | trigger / `delete_my_data` |
| `partner_invite` | 90 days after accepted, expired or revoked | `purge_partner_invites` (closes G4) |
| `audit_log` auth events | **permanent** (insert-only, E14); credential and session ids and uids, never a secret | open question Q5 |
| rate-limit buckets | 2 days | existing `purge_rate_limit_buckets` |

Account deletion: the staff member's own `delete_my_data` removes credentials, sessions, PIN, TOTP and challenges through the registry (5.4 item 3); `audit_log.actor_user_id` is redacted by the existing narrow exception (E14).

## 10. Threat table

| Threat | Attack | Controls | Residual |
|---|---|---|---|
| Phishing, credential | A look-alike site asks for the passkey | WebAuthn is origin-bound; wrong origin and wrong RP ID are refused `[verified: both cases in the test]`; RP ID is the narrow host | none beyond browser bugs |
| Phishing, invite | An attacker relays the invite link **and** the emailed OTP and enrols their own passkey | the invite is single use, 72 h, email-bound, the inviter sees the acceptance and the new credential's label in the portal, cold-start caps apply to a new member (plan §8.3) | a relayed OTP at enrolment succeeds (any email-OTP bootstrap has this); mitigated by in-person onboarding at pilot sites |
| Stolen shop iPad | Thief has the device | UV (the iPad passcode or biometrics) for every assertion; idle 30 min; PIN for A1; manager revokes credentials and runs `revoke-all` | thief with passcode, an open session and the PIN acts until revoked |
| PIN shoulder-surfing | Watcher learns a PIN | masked entry; useless without the member's credential and a session; 5-failure lock; 90 s window; per-member only | a watcher who also holds the unlocked iPad (above) |
| Session theft by XSS | Script reads the in-memory token | strict CSP, no third-party script, no inline script, `frame-ancestors 'none'`; the token is not persisted; A1 and A2 need a PIN the script would have to capture; per-staff caps and anomaly alerts | a script on the page rides the live session and can read keystrokes. Same for the cookie variant (4.6) |
| Session theft in transit or logs | Token captured on the wire or in a log | TLS; token not logged by our code; header redaction `[unverified]`; hashed at rest | an observer inside the Edge runtime sees tokens (R-P1) |
| CSRF | A third-party page triggers a call | no ambient credential; custom header forces preflight; exact-origin CORS | none |
| Invite forwarding | Link sent to a colleague | OTP goes to the invited mailbox; SQL email comparison; `403` otherwise (AT 16) | the colleague **is** the mailbox owner |
| Replay | Assertion, challenge, session token, invite | single-use challenge consumed before verify; token needs the live session; invite single use under lock; sign count | a replayed *token* inside its lifetime (needs theft first) |
| Counter regression, cloned authenticator | Two copies of one key | a non-zero counter must strictly rise; regression refused, audited, alerted | synced passkeys report 0: no clone detection (R-P3) |
| Staff collusion | A staff member sells scans, or hands a friend their PIN | co-signal required for hard evidence (plan §4.5); per-staff and per-facility caps and the anomaly rule (§8.3); named attribution to a person and a credential | collusion is a policy problem, not an authentication one |
| Manager abuse | A manager floods invites | rank and scope rule in the database; 20 invites/day; every invite audited; the operator sees `staff_activity` | an honest-looking manager can still invite real people |
| Enumeration | Probe members, invites, credentials | usernameless sign-in; constant `401`; constant invite-start body; foreign id `404` where the plan says so | timing differences are not measured |
| Brute force | PIN, TOTP, OTP, invite token, sign-in | PIN and TOTP lock in the database; OTP reuses the 0035 counters; invite tokens are 256-bit and attempt-capped; per-IP and per-credential buckets | an attacker with a live session can lock the member out of the PIN (a lock lever, harmless beyond that) |
| Privilege confusion | A Supabase JWT used as partner authority, or the reverse | partner functions never call `getActorFromRequest`; partner token prefix is rejected by the player path (GoTrue refuses it); **D12 removes the PostgREST reads** | none after D12 |
| Stale authority | Revoked member keeps working | per-call re-read; triggers kill sessions; reactivation cannot resurrect | a request already inside its transaction when the revoke commits finishes |
| Compromised Edge runtime | Runtime or a dependency is malicious | minter role, partner binding, assertion evidence, locked and integrity-checked dependencies | R-P1: it can mint sessions and sees tokens and PINs in flight |
| Compromised dependency | A malicious `@simplewebauthn/server` release | exact pin, sha512 lock, `--frozen` CI, tamper test (E15) | a malicious *pinned* version; the library sees assertions, not secrets |
| Mailbox takeover | Attacker owns a staff mailbox | email never adds a credential to a member who has one (D13); invites need an inviter | takeover at first enrolment (above) |
| Admin takeover | Attacker targets an admin | passkey + TOTP, 10 min idle, 1 h absolute, every A3 action re-asks TOTP, audited | a device-bound hardware key is not required (R-P4) |
| Lock-out DoS | Lock a person out | PIN lock needs a live session; recovery is a manager action | a pro shop with one person and no manager waits for the operator (Q3) |
| Clock skew | Device or server clock off | all windows use the database clock; a TOTP step is plus or minus 1 | a badly wrong device clock fails closed |

## 11. Residual risks and honest limits

- **R-P1: the Edge runtime is the WebAuthn verifier.** A compromised runtime can ask the minter for a session for any member and sees every token and PIN that passes through it. The partner lane is narrower than R6 (a compromised runtime cannot act as a partner who is not signing in, and the user-lane definers refuse the partner binding), but it is not closed. Retained assertion evidence makes a forged mint detectable by an out-of-band re-verifier; that is **not built** here. Closing R6 itself is the "PR5" the edge doc already names.
- **R-P2: the PIN is verified after the Edge sees it.** The Edge handles the plaintext PIN while the person types; only the derived value reaches the database.
- **R-P3: synced passkeys.** A passkey synced through a platform account (backup eligible) can be used from any device in that account, and reports a counter of `0`. "The passkey proves the device" is true only for device-bound credentials. `backup_eligible` and `backup_state` are stored; nothing is enforced on them in P5.1a.
- **R-P4: admin without a hardware key.** The design asks for passkey + TOTP (plan line 448); it does not require a device-bound key. Requiring `backup_eligible = false` for admin is a later hardening if the platform's authenticators make it practical `[unverified]`.
- **R-P5: the A1 window is per session, not per person.** Section 6.3.
- **R-P6: the stray Supabase JWT.** After D12 a staff member's Supabase JWT reads no partner data and authorizes no partner function. It still authorizes the **player** lane for that account, which is correct.
- **Unverified in the hosted environment** (S0 resolves them on a real project): npm resolution of the 25-package graph; CPU time for PBKDF2 at 600,000 rounds and for assertion verification; `verify_jwt = false` per function; function CORS preflight; Vault and `public.hmac`; `auth.sessions` columns for the invite freshness check; an installed-PWA passkey ceremony on a real iPad, including the shared-iPad chooser; A60.

## 12. Slice plan for P5.1a

Each slice is one or more PRs, each independently gateable and each with an "as built" section appended to this document (the repo's convention). Database halves ship before their TypeScript halves (the edge doc's PR1 / PR2 split). Dependencies: S0, then S1.1 to S1.5 in order; S2a is independent; S2b and S3 need S1.4; S4 and S6 need S1.5; S5 needs S3; S7 tracks S1.2 onward against a fixed contract.

| Slice | Content | Needs |
|---|---|---|
| **S0** | Supply chain and spike: the npm pin, allow-list, lock and CI list changes; a `_shared/partner/webauthn.ts` wrapper; the software-authenticator fixture as unit tests; the real-project checks of section 11 recorded in this document | this design signed off |
| **S1.1** | **DB spine.** Role `edge_partner_minter`; binding kind `partner`; tables `partner_credential`, `partner_auth_challenge`, `partner_session`; `bind_partner_session`, `partner_authorize`, the mint definers, revoke triggers; the scope invariant; `partner_invite` additions; **the PostgREST read revocation (D12)**; registries; checks 9-14; pgTAP | S0 |
| **S1.2** | **Edge core.** `openScopedTx` kinds `partner` and `partner_mint`; lint rule; the CORS helper; function `partner-session` (options, verify, get, sign-out, lock); the partner rate-limit twin; Deno integration suite | S1.1 |
| **S1.3** | **Invites and enrolment.** `partner-invites`, server-side OTP, first-credential registration, `partner-members` (list, revoke, credential revoke, revoke-all); purge definers for challenges, sessions, invites | S1.2 |
| **S1.4** | **PIN and step-up.** `partner_pin`, Vault pepper, definers, `session/step-up/pin`, lockout, reset | S1.3 |
| **S1.5** | **TOTP and `aal` 2.** `partner_totp`, SQL HOTP core (shared with S3), operator and admin session policy | S1.4 |
| **S2a** | **Player lane** (parallel; no staff dependency). `marker-scan` and the player's co-signal intake: accept `{facilityId, fix, jti}` and tie it to the purchase evidence row (plan §7.6 G2-03, §4.6(q)): `pending` without a qualifying fix, `valid` within 7 days of one, the 120 s rule judged against the fix's time | P3 |
| **S2b** | **Staff lane.** `course-qr` (rotating token on "Marker sold", today's PIN and "Rotate PIN", hand-over token), `qr-print`, the Ed25519 signing key in Vault, `facility_qr` and `course_qr_token` writers; their reads | S1.4, S2a |
| **S3** | **Attest and redeem.** `partner-attest` (online token and the offline code with the money doc's verify-and-record definer, superseding `offline_code_record_step_for_actor`), `partner-offers-redeem`, self-attest, same-device rule, cold-start caps, `staff_activity`, `attestation_shift_log`, their Edge reads | S1.4 |
| **S4** | **Receipts and review.** `receipts`, the review and `held_review` queue (wrapping `resolve_held_*`, E20), SLA alerts | S1.5, S3 |
| **S5** | **Hand-over and stock.** `partner-entitlements-redeem`, `entitlements-collect`, `stock-admin`, vouchers, the availability projection, the stock reads | S3 |
| **S6** | **Programme and sponsors.** `programme-config`, `offers-admin`, `sponsorships-admin`, settlement (P5.1b), rollup reads | S1.5 |
| **S7** | **`apps/partners` PWA.** 7a shell, CSP, enrolment, sign-in, PIN, lock (against fixtures, from S1.2); 7b attest and course-QR screens; 7c hand-over and stock; 7d manager, operator, admin; 7e offline (the A60 spike, then the voucher if built) | S1.2 onward |

### 12.1 Acceptance tests per slice

`PA-n` are new for this design. `AT(n)` are the build plan's P5 acceptance tests (plan line 2807 onward). pgTAP files continue the existing numbering (`supabase/tests/matrix/24_...`).

**S0**
- PA-0a: the software authenticator registers and signs in against the wrapper; wrong origin, wrong RP ID, missing UV, equal and lower counters and a wrong challenge are each refused; `0` against `0` passes (the section 14 cases, as a committed test).
- PA-0b: `deno cache --frozen` passes; the tamper step still fails on a changed hash; the verification suite passes with network denied.
- PA-0c: the real-project checks of section 11 are recorded, with pass or fail.

**S1.1**
- PA-1: no privilege for `anon`, `authenticated`, any edge role or `service_role` on the five tables; FORCE RLS on; checks 9-14 pass and each has a must-fail fixture.
- PA-2: `bind_partner_session` refuses an unknown hash, an idle-expired session, an absolute-expired one, a revoked one, a revoked credential, a demo account, a sponsor-only member and a member with no active membership, with an **identical** SQLSTATE and message.
- PA-3: a `partner` binding is refused by every user-lane definer; a `user` binding is refused by every `_for_partner` definer.
- PA-4: staff at A acting at B is `403`; a revoked member's next call is `403` on a live session; reactivation does not revive old sessions; deleting the scope row refuses the next call (AT 1, authentication half).
- PA-5: a facility org with a second scope row, or a non-facility scope, is refused by the trigger.
- PA-6: every view in 5.5 answers "denied" to `authenticated` for every actor, including `staff@X` with a valid JWT; `api.offer` returns NULL budget columns to a scoped member.
- PA-7: a challenge consumed by 12 concurrent calls succeeds once; an expired or wrong-purpose challenge is refused; a mint with an unconsumed challenge is refused.
- PA-8: only `edge_partner_minter` can mint; it executes nothing else (check 12-style).
- PA-9: the sign count never decreases except `0`-to-`0`; the compare-and-set loses cleanly under concurrency.

**S1.2**
- PA-10: CORS allows exactly one origin; any other gets none; `OPTIONS` never opens a connection.
- PA-11: a Supabase JWT sent to a partner function is `401`; a partner token sent to a player function is `401`; a source scan finds no `console.*` in the partner modules.
- PA-12: valid assertion mints; wrong origin, wrong RP ID, no UV, regression, replayed challenge, `userHandle` mismatch: one uniform `401`; a regression writes `audit_log` and raises the operator alert.
- PA-13: the lint fails on a fixture that uses the mint kind outside its caller.

**S1.3**
- PA-14: AT(16) part two: a forwarded invite fails for a non-matching verified email (`403`); single use under concurrency; expired, revoked and unknown are one `404`; only the hash is stored (no plaintext column, none in logs).
- PA-15: grant-subset and rank cells of plan §4.7.7 (manager invites at Y, or a manager or operator: `403`; operator at a facility not on its trail: `403`); a staff member cannot invite.
- PA-16: email OTP alone cannot add a credential to a member with an active one; recovery by re-invite works; a revoked member's credentials and sessions are dead.
- PA-17: `accept/start` answers identically for a valid and an invalid token; the OTP goes only to the invited address.

**S1.4**
- PA-18: the stored verifier is not a function of the PIN alone (a dump without the Vault pepper verifies nothing); 5 consecutive failures lock, and the 6th correct attempt is still refused; 20 concurrent wrong attempts evaluate at most 5; the lock survives a new session; reset sets `must_change`; trivial PINs are refused at set.
- PA-19: the step-up window is per session; a second session of the same member does not inherit it; A1, A2 and A3 refuse outside their windows.

**S1.5**
- PA-20: SQL HOTP equals the TypeScript oracle and the RFC 6238 vectors; replay of a step is refused; plus or minus 1 step; lockout; an operator action at `aal` 1 is refused; promotion does not upgrade an old session.

**S2a/S2b**: AT(19) in full (token replay `409`; more than 120 s from the fix `422 qr_expired`; no fix gives `pending`; the PIN rules and the 429 and rotation alarm; forged printed QR `422` plus `fraud_signal`; `staff@X` cannot mint or read the PIN for Y; an `unattestable` fix goes to `held_review`; the fix is counted once). Also AT(3), AT(4).

**S3**: AT(1) (attestation half), AT(2), AT(12), AT(13), AT(15), AT(16) part one (self-attest `422`); the shift-log read is exactly the old view's contents and no more; the verify-and-record definer never returns a seed or an expected code (money doc step 3); the offline recorder primitive is no longer executable by `edge_actor` (money doc step 3).

**S4**: AT(11), AT(18), AT(7) (handle escaping in exports); `resolve_held_*` reachable only through an A3 definer.

**S5**: AT(8) and AT(21) entire, including the race for the last unit and the voucher path.

**S6**: AT(10), AT(14), AT(17), AT(20); operator and admin A3 cells; `programme-config` and `offers-admin` foreign-id cells.

**S7**: a browser test that the app works under the section 4.6 CSP (no inline script, no eval); the token is absent from every storage API after sign-in; a reload requires a passkey tap; the PIN prompt appears for A1; and, for 7e only, A60.

## 13. Open questions for the owner

Product calls only; the technical points are in the sections above.

| # | Question | Why it matters | Recommendation |
|---|---|---|---|
| Q1 | **The partners domain.** Confirm the exact host (`partners.golfraven.<tld>`) before anyone enrols. | The RP ID is baked into every credential; changing it re-enrols every staff member. The same host serves the CSP and CORS | Fix it before S1.2 ships to staging |
| Q2 | **Session and step-up ergonomics.** Idle 30 min and absolute 8 h for staff, a 90 s PIN window for A1, a fresh PIN per A2 action. Is "a PIN per sale" acceptable at a busy till, or should "Marker sold" be a per-action PIN? | Friction against the shared-iPad residual (R-P5) | Start as written; read pilot telemetry |
| Q3 | **Recovery ownership.** A lost device is recovered by the shop's manager; a shop with no manager by the trail operator; an operator by an admin. Is the trail operator willing to be that authority, and who answers the phone for a pro shop locked out on a Saturday? | Section 6.5 makes the mailbox alone insufficient on purpose | Operator as second line; the owner as admin of last resort |
| Q4 | **Chains and groups.** One login across several courses of one chain is a person who is a member of several facility orgs, with a switcher. Is that acceptable, or does a chain need one org with many facilities? | The second shape needs member-level scope narrowing (a new table) | One org per facility |
| Q5 | **Retention of auth audit.** `audit_log` is permanent and insert-only. Is a permanent record of who enrolled and revoked what acceptable under Law 25, and is 180 days right for revoked credentials? | Counsel and the privacy officer | Ask counsel before S1.1 merges |
| Q6 | **PIN length.** The plan says 4 digits. 6 digits multiplies the online guess space by 100 at the cost of one more tap; offline it changes little (section 6.3). | Online guessing is already capped at 5 | Keep 4 |

## 14. What was verified in the authoring session, and how

| Claim | How it was checked | Result |
|---|---|---|
| `@simplewebauthn/server` current version, license, dependencies | `curl https://registry.npmjs.org/@simplewebauthn/server/latest` and `/14.0.3` | 14.0.3, MIT, `engines.node >= 20`, ten direct dependencies |
| It imports and runs under Deno | `deno run` of a scratch file (Deno 2.5.2 at authoring time) with `npm:@simplewebauthn/server@14.0.3` | exports `generateRegistrationOptions`, `verifyRegistrationResponse`, `generateAuthenticationOptions`, `verifyAuthenticationResponse`, `MetadataService` and others |
| Size of the dependency graph | `deno info --json` on that file | 25 npm packages |
| UV and resident-key options | `generateRegistrationOptions(... residentKey: "required", userVerification: "required", attestationType: "none", timeout: 120000)` and `generateAuthenticationOptions(... userVerification: "required")` | `requireResidentKey: true`, UV required, attestation `none`, challenge 32 bytes (43 base64url chars), default timeout 60,000 ms |
| Registration and assertion semantics | A software authenticator (WebCrypto ES256, a hand-built authenticator data and a CBOR attestation object) driven against the real library, 13 cases | registration with UP+UV+AT verifies (`singleDevice`, not backed up); without UV refused; with BE+BS reports `multiDevice`, backed up; wrong origin refused; assertion counter 1 verifies; counter 1 again refused ("lower than expected"); counter 0 after 1 refused; no UV refused; wrong origin refused; wrong RP ID hash refused; counter 5 verifies; counter 0 against stored 0 **verifies**; a different expected challenge refused |
| No outbound host needed | the same 13 cases re-run with `deno run --cached-only --deny-net` | all 13 produced the same results with network denied |
| PBKDF2 cost | `crypto.subtle.deriveBits` PBKDF2-SHA256, 3-run mean, 4-core container, Deno 2.5.2 | 100,000: 57 ms; 210,000: 115 ms; 600,000: 323 ms; 1,000,000: 555 ms. 10,000 PINs at 600,000 = about 3,230 s |
| Supabase passkeys are experimental | the passkeys guide, `apps/docs/content/guides/auth/passkeys.mdx` in the `supabase/supabase` repo, master, fetched with `curl` from the raw file host | "Passkey support is experimental ... may change without notice", opt-in client flag, `supabase-js` 2.105.0 or later, discoverable credentials, up to 5 origins |
| GoTrue passkey handlers | `internal/api/passkey_authentication.go`, `passkey_registration.go`, `passkey_manage.go`, `api.go` and `go.mod` in `supabase/auth`, master, fetched the same way | routes under `/passkeys`; `BeginDiscoverableLogin()` and `BeginRegistration(user, WithExclusions(...))` take no UV, resident-key or attestation option; the challenge is consumed before verification; success calls `issueRefreshToken(... PasskeyLogin ...)`; `go-webauthn/webauthn` is a dependency; no `CloneWarning` reference in the three handler files |
| Repository facts | every `path:line` in section 2, read in the worktree at `eb92ee9` | as cited |

Not verified (and marked `[unverified]` where used): whether the hosted Supabase platform runs the `master` handlers read above; the hosted Edge runtime's Deno version, CPU limit, `npm:` resolution and `verify_jwt` setting; Vault and `public.hmac`; `auth.sessions` columns; any iOS or Safari behaviour (passkey ceremony in an installed PWA, shared-iPad chooser, cookie blocking, storage lifetime, Trusted Types); the OWASP iteration figure; whether a function receives a trustworthy client IP; GoTrue's `amr` content; authenticator-app TOTP algorithm support.
