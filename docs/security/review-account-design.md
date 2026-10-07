# The App Store review account: submission windows, sign-in audit, and "disabled"

Status: built in migration `0051_review_account_window.sql` (see "As built" at the end). The requirement is build plan §4.7.7 matrix row "App-review demo account | requests an offer, a special marker or any partner route | 403", the Apple 2.1 row ("One `app-review` account whose OTP is delivered to a monitored reviewer inbox. It has no partner scope, can receive no offer or special marker, **audits every sign-in, and is disabled outside submission windows**") and acceptance test 14 ("The review account can sign in and cannot receive a reward"). Before 0051 the repository had the table (`app.app_review_demo_account`, 0007), the 403 on reward activation (`activate-handler.ts`) and the partner-route refusal (`bind_partner_session`, `partner_authorize`). It did not have the last two behaviours of that sentence.

Every statement about Supabase Auth (GoTrue), EAS or Apple that was not checked in this repository is tagged `[unverified — training knowledge]`.

## 1. What each phrase means here

| Phrase | Meaning | Enforced by |
|---|---|---|
| "submission window" | A half-open interval `[starts_at, ends_at)` in `app.app_review_window`. Several may exist; the account is enabled while the clock is inside **any** of them. No row means disabled: the default is closed. One window is at most 60 days. Global, not per account: there is one review account, and a per-account window would be a second place a stale row could keep it open. | `CHECK` constraints; `private.review_window_open_at(timestamptz)` |
| "disabled" | Two layers, both fail closed. **(a)** The database: every authenticated Edge request is refused (403 `review_account_disabled`) and `private.bind_actor` refuses to open an actor-bound transaction for the account, exact to the instant. **(b)** GoTrue: `auth.users.banned_until` is set, so a token can no longer be obtained. | (a) migration 0051 + `privileged.ts`; (b) `tools/review-account/review-account.sh` |
| "sign-in" | GoTrue owns the sign-in call (email OTP, then a session) and the database never sees it. What the database sees on every Edge request is the GoTrue **session id** in the access token's `session_id` claim `[unverified — training knowledge: GoTrue puts session_id in every access token it issues]`. A sign-in is therefore "the first authenticated request under a new session id". | `private.review_account_gate` |
| "audits every sign-in" | One `app.audit_log` row per (account, session, outcome), written on that first request, whether the request is allowed or refused. | `private.review_account_gate`, partial unique index `audit_log_review_session_once` |

## 2. The enforcement point, and why this one

Options considered for "outside every window, the review account cannot sign in":

| Option | Verdict |
|---|---|
| **A GoTrue hook** (a Supabase Auth hook that refuses the sign-in) | Not used. The repository uses no Auth hook anywhere, so this would be a new hosted-only dependency that nothing here can test `[unverified — training knowledge that such hooks exist and what they receive]`. |
| **Refuse every Edge call for that uid outside a window** | **Used, as the primary enforcement.** It needs no hosted feature, it is exact to the instant (no scheduler lag), and it is testable with the real `privileged.ts` against the harness cluster. The check lives in the database twice (the gate and the binder), not only in the Edge. |
| **Ban the Auth user (`banned_until`) from a scheduled job** | **Used, as the second layer.** It is the only thing that stops GoTrue issuing a token at all. It cannot be the only layer: it lags the window by one schedule period, and the repository schedules nothing today (`retention-purge`'s own header: "Nothing in this repository schedules it"). So it is a script (`review-account.sh sync`) and a deploy step, and the database refusal does not wait for it. |
| Write `auth.users` from a SQL function | Rejected. It needs a new grant on a table the Auth service owns; the rule for this change is that no grant is broadened. |

What is **not** covered, said plainly: a still-valid access token used **directly against PostgREST** (the `api.*` views, as `authenticated`, keyed on `auth.uid()`) is not an Edge call, so neither database layer sees it. Those views hold only the account's own rows (an empty profile, no offers: see section 4) and the token dies at `jwt_expiry` `[unverified — default and the project's setting]`. The ban prevents a new token. Closing that last gap in SQL would mean a window predicate in every `authenticated` policy, which this change does not do.

## 3. The design

**Tables and functions** (all in `0051`):

- `app.app_review_window (id, starts_at, ends_at, note, created_at)`. `FORCE RLS`, no client policy. `service_role` has full DML (the posture of `app.admin_user` and `app.app_review_demo_account`: it is how the owner administers them). One `private_definer` `SELECT` policy `USING (true)` (the `pd_read_demo_account` shape: the table holds no personal data), registered in `private.definer_policy_allowlist` and `supabase/tests/fixtures/definer_policy_exprs.txt`. It is **not** keyed on a GUC.
- `private.review_window_open_at(p_at)`: `starts_at <= p_at < ends_at` over the table. `EXECUTE` for `service_role` only.
- `private.review_account_gate(p_uid, p_session_id) -> 'not_review' | 'allowed' | 'disabled'`. `SECURITY DEFINER`, `search_path = ''`, owned by `private_definer`, `EXECUTE` for `edge_system` only. For a non-review account it returns `not_review` and writes nothing. For the review account it evaluates the window at `clock_timestamp()` (not `now()`: a long transaction must not carry a stale "open") and writes one audit row. **It returns a status and never raises over the outcome**: the audit row has to commit with the refusal, and a `RAISE` rolls it back (the lesson of 0020, `partner-auth-design.md` E11). It raises only for a `NULL` uid, which writes nothing.
- `private.bind_actor_internal` (redefined from 0047, one added check): a `kind = 'user'` bind of a review account outside a window raises `42501`. A system delegate is not a sign-in (it acts on one queued row of the owner, on the system's schedule), so only the user kind is refused. This is the backstop for an Edge path that skipped the gate.
- `audit_log_review_session_once`: a partial unique index on `app.audit_log (actor_user_id, action, subject_id) WHERE action IN ('review_account.session_allowed', 'review_account.session_refused')`. The gate catches its `unique_violation`; no `ON CONFLICT` arbiter is read, so the function needs no `SELECT` on `audit_log`. A `NULL` `subject_id` never conflicts.

**Edge**: `privileged.ts#getActorFromRequest` is the one choke point every authenticated function already passes through (12 of 12 call it inside `handleRequest`). After `auth.getUser` succeeds it calls the gate in its own short `edge_system` transaction **before** any request transaction opens (the `hitRateLimitForActor` ordering rule: no request ever holds two pooled connections). `disabled` throws `HttpError(403, "review_account_disabled")`, which `handleRequest` turns into the response; an unexpected value fails closed as `disabled`. A failure of the gate's own database call is a 500, not a pass.

**What a sign-in audit row holds**: `actor_user_id` (redacted to `NULL` by `delete_my_data` like every audit row), `action` (`review_account.session_allowed` or `..._refused`), `subject_table = 'auth_session'`, `subject_id` = the session id (a random uuid; canonicalised to lower case, or `NULL` if the token carried no readable one), `detail = {"outcome": "allowed" | "refused"}`. No email, no IP, no user agent, no token. A session that is refused and later allowed (a window opened) gets both rows: the log never loses the first answer. An unreadable session id is audited on **every** request: the failure direction is more rows, never a sign-in with no record.

**Cost**: one extra short transaction per authenticated Edge request (for every user, not just the review account), because the gate has to ask the database whether the caller is the review account. Not cached, because a cache would delay a window's end. Measure before launch `[unverified]`; a short negative cache keyed on "not a review account" would be the first optimisation, at the price of a newly designated account being enabled for up to the cache period.

## 4. The restrictions that already existed, and where each is pinned

| Restriction (plan) | Mechanism | Pinned by |
|---|---|---|
| Can sign in (AT 14) | Inside a window the binder admits the account and the gate returns `allowed` | `29d` (bind succeeds, `actor_uid()` is R), `review-account.deno.test.ts` (request passes) |
| Cannot receive a reward (AT 14) | 403 `forbidden` before any reward is read (`activate-handler.ts`) | `rewards-activate.deno.test.ts` (now run **inside** a window, since the account cannot be bound outside one), `activate-handler.test.ts` |
| No partner scope | No `partner_member` row; both scope predicates false; `bind_partner_session` and `partner_authorize` refuse it (`is_demo_account`); the provisioning script refuses an address that is a partner member or an admin | `29a` (`has_facility_scope` / `has_trail_scope` false, no member row), matrix `25` PA-2 and the `zz24` NIT cell |
| Can receive no offer or special marker | **No write path exists on the only lane it can bind.** `edge_actor` and `authenticated` hold no `INSERT` or `DELETE` on `offer`, `offer_code`, `entitlement`, `special_marker_stock`, `special_marker_stock_movement`, `marker_credit`. The offer and marker *request* routes are P6 and do not exist yet, so a handler-level 403 cannot be written yet | `29a` (privilege cells), `29d` (bound as R, `INSERT` into each is `42501`) |
| Audits every sign-in | `review_account_gate` | `29b`-`29f`, `review-account.deno.test.ts` |
| Disabled outside submission windows | gate + binder backstop + Auth ban | `29a`-`29f`, `review-account.deno.test.ts`, `tools/db/test-review-account-tool.sh` |

## 5. Owner procedure

`docs/owner/review-account-procedure.md`.

## 6. `[unverified]`

- GoTrue admin API shapes used by the script: `POST /auth/v1/admin/users` with `email_confirm` and `ban_duration`; `PUT /auth/v1/admin/users/{id}` with `ban_duration` `"none"` or `"<hours>h"`; that a banned user cannot request or verify an email OTP; that a ban does not revoke an access token already issued.
- That GoTrue puts `session_id` in every access token (the gate degrades to "audit every request" if it does not; it never fails open).
- That a ban set far in the future (`876000h`) is accepted.
- The `jwt_expiry` of the hosted project.
- A scheduler for `review-account.sh sync` (a Supabase cron, a GitHub Actions schedule, or the owner's machine): nothing in this repository schedules it.
- Apple App Review's behaviour with a window that is open for the review period only.
