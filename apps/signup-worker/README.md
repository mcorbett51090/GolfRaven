# @golfraven/signup-worker

The K2 double-opt-in email signup backend (build plan §10 P0, K2; decision
0001 Addendum D R3; `docs/p0/gate-review.md` S5/S6): a Cloudflare Worker +
D1 that gives `apps/landing`'s signup form somewhere real to POST to, plus
the K2 signup-count script.

## What it is

- **Cloudflare Worker** (`src/index.ts`), TypeScript, same-origin under
  `golfraven.<tld>/api/*` (so `apps/landing` needs no CORS in production).
- **Cloudflare D1** (`migrations/0001_create_signups.sql`) holds one table,
  `signups`.
- **Cloudflare KV** holds rate-limit counters only — nothing durable.
- **Resend** sends the confirmation email (same provider approach as the
  owner's other Worker — see "Credits" below).
- **Cloudflare Turnstile** is the bot check on `POST /api/signup`.

Several modules (`src/turnstile.ts`, `src/ratelimit.ts`, `src/email.ts`)
are adapted from the owner's production Worker,
`raven-site-kit/secure-upload/worker/src/{turnstile,ratelimit,email}.ts` —
each file's header comment says exactly what was reused and why.

## Endpoints

| Route | Method | What it does |
|---|---|---|
| `/api/signup` | POST | Validate, rate-limit, verify Turnstile, upsert a pending row, send the confirmation email **if the send limits allow it** (see "Send limits" below). **Always** returns the same generic `202` — whether the address is new, already pending, already confirmed, or previously unsubscribed, and whether or not an email was actually sent (no account enumeration, no signal that a send was skipped). |
| `/api/confirm` | GET | Renders a minimal page with a "Confirm" button. Never confirms — so an email-link scanner that GETs the link doesn't trigger it. |
| `/api/confirm` | POST | Performs the confirmation. **Single-use, not idempotent** (gate finding F4): the token is cleared on success, so a second POST with the same token shows the generic "invalid or already used" page rather than re-confirming. Expired/unknown token → the same generic page. |
| `/api/unsubscribe` | GET | Renders a page with an "Unsubscribe" button. |
| `/api/unsubscribe` | POST | Unsubscribes. Idempotent (a second POST is a no-op, still 200). This is also the RFC 8058 one-click target — every email's `List-Unsubscribe`/`List-Unsubscribe-Post` headers point a mail client's automated POST straight here, no page visit needed. |

## Send limits (gate findings F6, N1, N3)

A confirmation email is sent only if ALL of these pass, checked in this order:

1. **Per-email cooldown** — 10 minutes since the last send to this address.
2. **Per-email daily cap** — 3 sends/UTC-day to this address.
3. **Global daily cap** — `GLOBAL_DAILY_SEND_CAP` (default **500**) sends/UTC-day across every
   address. This is an intentional abuse brake, not a bug: without SOME ceiling, an attacker who can
   trigger 500+ Turnstile-solved requests could either burn through the Resend plan's quota (a hard
   failure for everyone) or run up its bill. The trade-off is real and visible: once tripped, every
   *other* legitimate signup that UTC day gets the normal `202` "check your inbox" response but
   **no email is ever sent** — there is no user-facing error, only a `console.error("confirmation
   email skipped by send limit", { reason: "global-send-daily-cap" })` log line. Size the cap to the
   Resend plan, and put a Workers Logs alert on that log line if you want to be notified when it trips.

**N1 (BLOCKING, fixed):** none of the three checks above ever invalidates a link that was already
emailed. On an existing (pending or previously-unsubscribed) row, the confirm/unsubscribe tokens are
rotated ONLY in the branch that goes on to actually attempt a send — if the send is skipped for any
reason, the row is left completely untouched, so the last email that WAS actually sent keeps working.
A brand-new address's very first insert is unaffected (there is no prior emailed link to protect).

## What's stored, and why (for the privacy notice)

`signups` (D1) — one row per lower-cased email address:

- `email_lc`, `consent_version`, `age_confirmed` — the actual consent
  record: which wording the visitor saw, and their 16+ attestation. This
  is the durable evidence the privacy notice promises exists.
- `source` — optional free-text attribution (the landing page sends its
  `trail` radio value here — there's no separate `trail` column).
- `created_at`, `confirmed_at`, `unsubscribed_at` — the double-opt-in and
  subscription-state timeline. **`confirmed_at` is a permanent historical
  fact once set — a later unsubscribe-then-re-signup never moves it**
  (see `src/k2-count.ts`'s header comment: K2 counts confirmations, not
  current subscribers).
- `confirm_token_hash`, `confirm_expires_at`, `unsubscribe_token_hash` —
  **hashes only**. Raw tokens exist only in the email link and are never
  written to D1.

**Deliberately NOT stored anywhere in D1: IP address or user agent.**
Rate limiting (`src/ratelimit.ts`) lives entirely in KV, keyed by
`sha256(pepper + ip)` — never the raw address — and is TTL'd (expires on
its own), never durable.

## Data retention (gate finding F11, N2, N8)

A scheduled (cron) handler (`src/index.ts`'s `scheduled`, wired in
`wrangler.toml`'s `[triggers]`) purges two classes of row once daily:

- **Unconfirmed rows older than 30 days, whose confirm token has also
  already expired**, are deleted unconditionally (N8: `created_at` alone
  isn't enough — a re-signup near the 30-day mark rotates in a fresh,
  still-valid 48h token without moving `created_at`, so a `created_at`-only
  cutoff could delete a row out from under a link someone can still click).
  Unconfirmed rows **never** count toward K2 (`src/k2-count.ts` only ever
  reads rows with a non-null `confirmed_at` — see its header comment), so
  this purge can never change a K2 count.
- **Confirmed-but-unsubscribed rows**, more than 30 days past their
  `unsubscribed_at`, are deleted too — but **only once the K2 verdict is
  safely past its recording window** (N2, BLOCKING fix — the previous gate
  let deletion start as soon as `K2_GATE_CLOSES_AT` parsed to *any* past
  date, including malformed values like `"2026"` or `"1"`, which
  `new Date(...)` happily parses to 2026-01-01 / 2001-01-01 and enables
  deletion immediately):
  - `Env.K2_GATE_CLOSES_AT` must be a **strict, full ISO-8601 UTC
    timestamp**, `YYYY-MM-DDTHH:MM:SSZ` exactly (no bare date, no other
    offset form, no fractional seconds) — see `checkK2GateClosesAt` in
    `src/config.ts`.
  - It must be **no earlier than `2026-11-16T00:00:00Z`** — the earliest a
    real K2 gate close could ever be (plan P0 start 2026-10-05 + the
    42-day gate window) — so a value like day 0 typed into this var by
    mistake can never sneak through.
  - Deletion of this class still doesn't start until **30 days AFTER**
    that timestamp (K2's own verdict is read at "≈ wk 7", after the gate
    itself closes at wk 6 — this extra margin is the actual safety buffer).
  - Any other value (unset, malformed, too early, or the grace period not
    yet elapsed) deletes **nothing** in this class and logs one PII-free
    `console.warn` per cron run naming the reason (no address, no raw env
    value) — see `runRetentionCron` in `src/index.ts`.

  Until all of the above hold, a confirmed signup is effectively kept
  indefinitely once unsubscribed, which is the safe default.

**Processors:** GolfRaven uses two data processors for this backend —
**Cloudflare** (hosting the Worker, D1, KV, and the Turnstile bot check,
which receives the visitor's IP via `remoteip`) and **Resend** (delivers
the confirmation email). See `apps/landing/src/index.html`'s privacy
section for the visitor-facing version of this notice.

## Owner deploy runbook

Nothing in `wrangler.toml` is deployable as-is — every `TODO(owner)` must
be filled in first. None of this was run as part of building this
package; it's the checklist for whoever deploys it.

1. **Create the D1 database and KV namespace:**
   ```shell
   npx wrangler@4 d1 create golfraven-signups
   npx wrangler@4 kv namespace create RATE_LIMIT_KV
   ```
   Paste the returned `database_id`/`id` into `wrangler.toml`, and set
   `account_id` (`npx wrangler@4 whoami`).

2. **Apply the migration:**
   ```shell
   npx wrangler@4 d1 execute golfraven-signups --remote --file=./migrations/0001_create_signups.sql
   ```

3. **Set secrets** (never put these in `wrangler.toml`):
   ```shell
   npx wrangler@4 secret put RESEND_API_KEY
   npx wrangler@4 secret put TURNSTILE_SECRET
   npx wrangler@4 secret put TOKEN_PEPPER   # e.g. `openssl rand -hex 32`
   ```

4. **Verify the sending domain in Resend** and add its SPF, DKIM and DMARC
   DNS records (this is the P0 external prerequisite `apps/landing`'s
   README already calls out — do this before anything else here matters:
   without it, confirmation emails land in spam or get rejected outright).
   Set `RESEND_FROM_EMAIL` in `wrangler.toml` `[vars]` to an address on
   that verified domain.

5. **Create a Turnstile widget** for the landing page's domain in the
   Cloudflare dashboard. Put the **site key** (public) in
   `apps/landing/src/config.js`'s `TURNSTILE_SITE_KEY`, and the **secret
   key** in this Worker's `TURNSTILE_SECRET` (step 3).

6. **Set the route** in `wrangler.toml` (`golfraven.<tld>/api/*`) and
   `PUBLIC_BASE_URL`, once the domain is registered and pointed at
   Cloudflare. **N11: `PUBLIC_BASE_URL`'s host is also the expected
   Turnstile hostname** (`src/index.ts`'s `expectedTurnstileHostname`) —
   serving the landing page from any OTHER hostname (a bare `www.`, a
   `*.pages.dev` preview, staging) makes every signup fail closed with a
   generic Turnstile error. Point `PUBLIC_BASE_URL` at whichever hostname
   the landing page is actually served from, and keep them in sync if that
   ever changes.

7. **Deploy:** `npx wrangler@4 deploy` (pin the version rather than
   floating on `wrangler@latest`, so a deploy is reproducible).

8. **Point `apps/landing`'s `SIGNUP_ENDPOINT`** (`src/config.js`) at the
   deployed route (e.g. `https://golfraven.example/api/signup`, or just
   `/api/signup` for a same-origin deploy), and redeploy the landing page.
   **Load the deployed landing page and check the browser console for zero
   CSP violations** — this confirms `_headers`'s `script-src`/`frame-src`
   allow-list for `https://challenges.cloudflare.com` actually matches what
   Turnstile needs before relying on it end to end in the next step.

9. **Verify end to end** before logging K2's day 0: submit the landing
   page's form for real, confirm the email arrives (check spam too), click
   confirm, and confirm the row's `confirmed_at` is set
   (`npx wrangler@4 d1 execute golfraven-signups --remote --command "SELECT email_lc, confirmed_at FROM signups"`).
   **N13: if the test address used here should NOT count toward K2, add it
   to `docs/p0/K2.md`'s "Excluded addresses" section and commit that BEFORE
   logging day 0** — R3 has no lower bound on `confirmedAt`, so this
   end-to-end confirmation counts toward the K2 gate unless excluded, and
   the exclusion only takes effect if its own line was committed strictly
   before day 0 (see "How to run the K2 count" below).
   **Only then** log day 0 in `docs/p0/K2.md`, before any promotion
   (decision 0001 Addendum D R3) — this package does not, and should not,
   set that date itself. Once day 0 is logged, also set
   `K2_GATE_CLOSES_AT` in `wrangler.toml` to day 0 + 42 days (see "Data
   retention" above) and redeploy.

## How to run the K2 count

```shell
# 1. Build once (the CLI imports the built dist/k2-count.js and dist/k2-blame.js):
pnpm --filter @golfraven/signup-worker build

# 2. Export the table (documented D1 export command):
npx wrangler@4 d1 execute golfraven-signups --remote --json \
  --command "SELECT email_lc, confirmed_at FROM signups" > export.json

# 3. Run the count — day 0 and the excluded-addresses list are ALWAYS read
#    from the repo's own docs/p0/K2.md (there is no --k2-doc override —
#    gate finding F7):
node scripts/k2-count.mjs --export export.json
```

The script **refuses to run** if day 0 isn't logged in `docs/p0/K2.md`
yet (decision 0001 Addendum D R3), or if day 0's own line in K2.md isn't
committed. It prints the advisory (day0+14d, bar 100) and gate (day0+42d,
bar 300) counts and a PASS/FAIL verdict against each, plus the full result
as JSON. `src/k2-count.ts` implements the counting rule literally — see
its header comment, especially: **it counts confirmations, not current
subscribers** — an address that confirmed before the cutoff and later
unsubscribed still counts.

**Exclusion timing (F7/F8 residual):** R3 excludes an address only if it
was "listed ... before Day 0". The CLI enforces this with `git blame` on
`docs/p0/K2.md` — an address counts as excluded ONLY if its own line's
commit author-time is strictly before day 0 00:00 UTC. An address added
on/after day 0, or whose line isn't committed yet, is printed in the
output as "not excluded (added on/after day 0 or uncommitted)" rather than
silently applied. The full excluded-addresses list actually used is always
echoed in the output (never just a count), and a bullet that doesn't
resolve to exactly one clean email address is a hard refusal, not a silent
drop.

## Testing approach

Tests use plain Vitest with hand-rolled in-memory fakes for D1/KV
(`test/fakes.ts`) rather than `@cloudflare/vitest-pool-workers` or
Miniflare. `src/config.ts` defines narrow `D1Like`/`KVLike` interfaces
specifically so a plain object can stand in for the real binding — the
real Cloudflare types satisfy them structurally, so nothing about the
deployed Worker changes. This keeps the test suite fast and dependency-light
while still exercising the real request/response flow (`Request`/`Response`
are Node's native Fetch API globals, no polyfill needed).

`npm run k2-count` / `node scripts/k2-count.mjs` is the CLI; its markdown
parsing (`parseDay0FromK2Doc`, `parseExcludedAddressesFromK2Doc`,
`extractRows`) is covered directly in `test/k2-count-cli.test.ts`.

## Local dev (not part of this build)

`wrangler dev` isn't wired up or exercised here (deploy is explicitly an
owner step for this task). Once the bindings above are provisioned,
`npx wrangler dev` from this directory should work using wrangler's
default local D1/KV emulation.
