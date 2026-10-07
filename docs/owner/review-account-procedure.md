# App Review account: provision, open and close a window, and what to give Apple

Owner-facing. Design and the argument for it: `docs/security/review-account-design.md`. Migration `0051_review_account_window.sql`; tool `tools/review-account/review-account.sh`; proof `tools/db/test-review-account-tool.sh` and matrix `29a`-`29f`.

The review account is **closed by default**. It works only while a submission window is open, and the database refuses it the instant the window ends. Opening a window is a deliberate act around a submission. Every sign-in is audited.

Everything about Supabase Auth, App Store Connect and EAS below is `[unverified — training knowledge]` unless it cites this repository: none of it could be exercised here (no hosted project, no Apple account).

## Before the first submission window: a deploy precondition

The database refuses the account the instant a window ends, but **GoTrue keeps issuing codes and tokens until the account is banned**, and a token reads the whole `api.*` catalogue (the live offer list and other players' public handles) directly from PostgREST. So, **before you open the first window**, one of these must exist and have been seen to work once:

- **(a)** a schedule that runs `review-account.sh sync` at least every 15 minutes (a Supabase cron, a GitHub Actions schedule or a machine you control; nothing in this repository schedules it `[unverified]`), **or**
- **(b)** your own standing rule to run `review-account.sh close` the moment a review ends.

Details and the reasoning: `docs/security/review-account-design.md` section 2.

**One review account per Supabase project.** There is exactly one (a unique index), in each project: `gr-staging` for the dry run and `gr-prod` for the real one. Do the whole procedure **twice**, staging first with a staging-only reviewer address, then production. The two accounts, windows and Auth bans are independent.

**Never delete the review-account row, to switch it off or to replace the account.** Deleting the row turns the account into an ordinary player: the database stops refusing it a window, a reward is no longer refused, and a token issued before any Auth ban keeps working until it expires (a ban does not revoke an issued token). **`close` is the off switch** (and `sync` keeps it off). To REPLACE the account use `retire` (section 6), which keeps the row and marks it retired.

**Before you deploy 0051 to a project**, check that it holds at most one review-account row, because 0051's unique index fails the migration otherwise (and a failed migration is a failed deploy). 0051 also adds `retired_at`, so `retire` exists only after the deploy:

```sql
select count(*) as review_accounts from app.app_review_demo_account;   -- must be 0 or 1
-- if it is more than 1: keep the one real reviewer. For each OTHER row, delete that reviewer's Auth user in the dashboard: the foreign key removes
-- its row with it, so nothing is left behind to be an ordinary player. (Do not delete only the row, and do not just ban the user: a ban does not revoke
-- a token already issued.) After 0051 is applied, replace an account with `retire`, never by hand.
select user_id from app.app_review_demo_account order by user_id;
```

## What you need, and where it lives (never in git: this repository is public)

| Value | Where | Notes |
|---|---|---|
| The reviewer mailbox address | `REVIEW_ACCOUNT_EMAIL` in your shell, or one line on standard input | A dedicated, monitored mailbox. The tool never takes it as an argument, never prints it, hands it to `psql` and `jq` on standard input only (so it is on no command line), unsets it before starting any child, and keeps the Auth response (which names it) out of every file |
| Database connection | the standard libpq variables (`PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`, `PGPASSWORD`) of the **production** project | The login must be allowed to `SET ROLE service_role` |
| Auth admin API | `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` of the production project | `SUPABASE_URL` must be exactly `https://<host>`: userinfo, a path and look-alike hosts are refused. The key goes to `curl` on standard input, never on a command line, and is removed from the environment before any child starts. Use `GOLFRAVEN_REVIEW_AUTH=skip` to act on the database only and ban by hand in the dashboard instead |
| `jq`, `curl`, `psql` | on your `PATH` | |

## 1. Provision (once)

Prerequisite: the production Supabase project, custom SMTP (so the OTP reaches the mailbox), migration `0051` applied, and the deploy precondition above. Do **not** sign the address in beforehand: the tool creates the Auth user itself.

```shell
printf '%s\n' "$REVIEWER_ADDRESS" | bash tools/review-account/review-account.sh provision
```

It creates the Auth user (born banned), marks it the review account (`app.app_review_demo_account`) and leaves it **banned and closed**. Re-running it with the same address is harmless. What it refuses, by design:

- **An address that already has an Auth user.** A typo in the address must not turn a real player into the review account. Use a fresh address. If you created the Auth user for this purpose and it has never been used, pass `--adopt`: the tool then checks that it has **never signed in** (`auth.users.last_sign_in_at` is empty), has no evidence, plays, rewards, offer codes, entitlements, marker credits, purchases, devices, push tokens, bookings, achievements, attestations or fraud signals, and is neither a partner member nor an admin.
- **A second review account.** There is exactly one per project (a unique index). To replace it use `retire` (section 6), then provision the new address.
- **A partner member or an admin** (the review account has no partner scope).

## 2. Open a window around a submission

```shell
bash tools/review-account/review-account.sh open --hours 72 --note "build 1.0.0 submission"
```

`--hours` is 1 to 1440 (the database refuses a window over 60 days). The note must not contain an address. The database enables the account at once; the tool then clears the Auth ban so GoTrue will send an OTP. Open it **before** you submit and long enough to cover the review (App Review can take days `[unverified]`), and keep an eye on the reviewer mailbox.

## 3. Close it

```shell
bash tools/review-account/review-account.sh close
```

The database refuses the account from that instant (a request answers 403 `review_account_disabled`); the tool then bans the Auth user. **`close` ends the windows that are open now and leaves FUTURE windows in place:** the database will enable the account again when one starts, while GoTrue stays banned until the next `sync` or `open`, which fails closed (the account cannot get a code in the meantime). Delete a future window by hand if you do not want it. A window that simply runs out is also refused by the database at its end instant, but **GoTrue keeps issuing codes until the ban is set**, so also run

```shell
bash tools/review-account/review-account.sh sync
```

on a schedule (every 5 to 15 minutes is enough; it is idempotent) `[unverified: nothing in this repository schedules it; a Supabase cron, a GitHub Actions schedule or your own machine all work]`. `status` prints counts and whether a window is open, no address:

```shell
bash tools/review-account/review-account.sh status
```

## 4. What to give Apple (App Store Connect, App Review Information)

Field names `[unverified — training knowledge]`.

- **Sign-in required**: yes. **Username**: the reviewer address (it is in App Store Connect, which is the right place; it is not in this repository). **Password**: none; this is an email one-time-code sign-in. Say so in the **Notes** field: "Sign in with email. The 6-digit code is sent to the monitored reviewer inbox; contact us at the review contact address and we will read it to you, or the inbox is monitored during the review window."
- **Notes**: "Guest browse works with no account. The review account is enabled only for the review period. It has no partner role, cannot receive a reward, offer or special marker, and every sign-in is audited." (Plan: Apple 2.1 row, build plan line 1871; guest browse is plan line 1872.)
- **Contact** details are your own; they are not in this repository.
- Open the window (step 2) before pressing **Submit for Review**.

## 5. Verify, and on which build

Which Supabase project a build talks to is set by the public `EXPO_PUBLIC_*` values in that profile's EAS environment, **not** by `apps/mobile/eas.json` (it carries none, and no staging profile). The real `eas.json` has three profiles: `development` (dev client, internal), `preview` (internal distribution, production attest environment) and `production` (store). So:

- **Staging dry run:** a **`preview`** build, its EAS environment pointed at `gr-staging`, installed through internal distribution on a registered device `[unverified: ad hoc registration]`. Run steps 1 to 4 below against `gr-staging` with the staging reviewer.
- **Real reviewer path:** the **`production`** build, pointed at `gr-prod`, installed from **TestFlight**: it is the binary Apple reviews. Run steps 1 to 4 against `gr-prod` with the production reviewer, **with a window open**, before you submit. (The earlier assumption that a TestFlight build points at staging does not hold for this profile set: if you also want a staging TestFlight build, that is a decision for you to make, because `eas.json` has no profile for it.)

1. Before opening: sign in as the reviewer on that build. Expect no code (banned) or, if the ban was not set, a 403 `review_account_disabled` on the first request.
2. After `open`: sign in; the app works. Wallet activation (flag on) answers 403 `forbidden`.
3. `select action, subject_id, created_at from app.audit_log where action like 'review_account.%' order by created_at` (service role): one `session_allowed` row per session, plus any `session_refused` rows from before the window.
4. After `close`: the next request is 403 `review_account_disabled`.

## 6. Replace the review account (`retire`)

```shell
bash tools/review-account/review-account.sh retire
printf '%s\n' "$NEW_REVIEWER_ADDRESS" | bash tools/review-account/review-account.sh provision
```

`retire` does three things, in this order: **(1) `close`** (it ends every open window); **(2) bans the old Auth user**; **(3) marks the row retired** (`retired_at`). **It never deletes the row.** Why: a ban does not revoke an access token the old account already holds, so for up to that token's life the old account would be an ordinary player if its row went (no window gate, no reward or credit refusal). A retired row keeps the account a review account for every refusal, and the database refuses it on every request and in every window, whether or not one is open. Retired is one-way (the database refuses to clear it), and the row is kept while its Auth user exists; the only way it goes is deleting the Auth user (the foreign key cascades), which you do only when you are sure no token can be live. A retired account does not count as the active one, so `provision` accepts the new address; the retired address can never be provisioned again, and `sync` keeps a retired account's Auth user banned even while a window is open.

In `GOLFRAVEN_REVIEW_AUTH=skip` mode `retire` makes no Auth call: it retires the row in the database (so the account is refused everywhere), **does not claim a ban**, prints `ACTION REQUIRED` telling you to ban the Auth user in the dashboard yourself, and **exits 3**. Do that ban before you relax: until you do, GoTrue can still issue it tokens, which the database refuses on every Edge request but direct PostgREST reads do not see.

If you cannot run the tool at all, do the three steps by hand in this order: end the open windows, ban the Auth user in the dashboard, then `update app.app_review_demo_account set retired_at = now() where user_id = '<id>' and retired_at is null;` as `service_role`.

## 7. If something goes wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| Reviewer cannot get a code | The Auth ban was not cleared (the tool printed an Auth error), or custom SMTP is not live | `sync` with a window open; check the dashboard's user ban state |
| Reviewer signs in but every call is 403 `review_account_disabled` | The window has ended or never opened | `status`; `open` again |
| `open` printed an Auth error but the window exists | The database enabled the account but GoTrue still bans it (the safe direction) | Fix the Auth error and run `sync`, or clear the ban in the dashboard |
| `close` printed an Auth error | The database already refuses the account; GoTrue may still issue a code | Run `sync`, or set the ban in the dashboard |
