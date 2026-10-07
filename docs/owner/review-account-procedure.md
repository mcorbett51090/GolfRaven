# App Review account: provision, open and close a window, and what to give Apple

Owner-facing. Design and the argument for it: `docs/security/review-account-design.md`. Migration `0051_review_account_window.sql`; tool `tools/review-account/review-account.sh`; proof `tools/db/test-review-account-tool.sh` and matrix `29a`-`29f`.

The review account is **closed by default**. It works only while a submission window is open, and the database refuses it the instant the window ends. Opening a window is a deliberate act around a submission. Every sign-in is audited.

Everything about Supabase Auth, App Store Connect and EAS below is `[unverified — training knowledge]` unless it cites this repository: none of it could be exercised here (no hosted project, no Apple account).

## What you need, and where it lives (never in git: this repository is public)

| Value | Where | Notes |
|---|---|---|
| The reviewer mailbox address | `REVIEW_ACCOUNT_EMAIL` in your shell, or one line on standard input | A dedicated, monitored mailbox. The tool never takes it as an argument and never prints it |
| Database connection | the standard libpq variables (`PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`, `PGPASSWORD`) of the **production** project | The login must be allowed to `SET ROLE service_role` |
| Auth admin API | `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` of the production project | The key goes to `curl` on standard input, never on a command line. Use `GOLFRAVEN_REVIEW_AUTH=skip` to act on the database only and ban by hand in the dashboard instead |
| `jq`, `curl`, `psql` | on your `PATH` | |

## 1. Provision (once)

Prerequisite: the production Supabase project, custom SMTP (so the OTP reaches the mailbox), migration `0051` applied.

```shell
printf '%s\n' "$REVIEWER_ADDRESS" | bash tools/review-account/review-account.sh provision
```

It creates the Auth user if the address has none (born banned), marks it the review account (`app.app_review_demo_account`), refuses an address that is a partner member or an admin, and leaves the account **banned and closed**. Re-running it is harmless.

## 2. Open a window around a submission

```shell
bash tools/review-account/review-account.sh open --hours 72 --note "build 1.0.0 submission"
```

`--hours` is 1 to 1440 (the database refuses a window over 60 days). The note must not contain an address. The database enables the account at once; the tool then clears the Auth ban so GoTrue will send an OTP. Open it **before** you submit and long enough to cover the review (App Review can take days `[unverified]`), and keep an eye on the reviewer mailbox.

## 3. Close it

```shell
bash tools/review-account/review-account.sh close
```

The database refuses the account from that instant (a request answers 403 `review_account_disabled`); the tool then bans the Auth user. A window that simply runs out is also refused by the database at its end instant, but **GoTrue keeps issuing codes until the ban is set**, so also run

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

## 5. Verify

1. Before opening: sign in as the reviewer on a TestFlight build. Expect no code (banned) or, if the ban was not set, a 403 `review_account_disabled` on the first request.
2. After `open`: sign in; the app works. Wallet activation (flag on) answers 403 `forbidden`.
3. `select action, subject_id, created_at from app.audit_log where action like 'review_account.%' order by created_at` (service role): one `session_allowed` row per session, plus any `session_refused` rows from before the window.
4. After `close`: the next request is 403 `review_account_disabled`.

## 6. If something goes wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| Reviewer cannot get a code | The Auth ban was not cleared (the tool printed an Auth error), or custom SMTP is not live | `sync` with a window open; check the dashboard's user ban state |
| Reviewer signs in but every call is 403 `review_account_disabled` | The window has ended or never opened | `status`; `open` again |
| `open` printed an Auth error but the window exists | The database enabled the account but GoTrue still bans it (the safe direction) | Fix the Auth error and run `sync`, or clear the ban in the dashboard |
| `close` printed an Auth error | The database already refuses the account; GoTrue may still issue a code | Run `sync`, or set the ban in the dashboard |
