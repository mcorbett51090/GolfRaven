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
| `/api/signup` | POST | Validate, rate-limit, verify Turnstile, upsert a pending row, send the confirmation email. **Always** returns the same generic `202` — whether the address is new, already pending, already confirmed, or previously unsubscribed (no account enumeration). |
| `/api/confirm` | GET | Renders a minimal page with a "Confirm" button. Never confirms — so an email-link scanner that GETs the link doesn't trigger it. |
| `/api/confirm` | POST | Performs the confirmation. Idempotent. Expired/unknown token → a generic "invalid or expired" page. |
| `/api/unsubscribe` | GET | Renders a page with an "Unsubscribe" button. |
| `/api/unsubscribe` | POST | Unsubscribes. This is also the RFC 8058 one-click target — every email's `List-Unsubscribe`/`List-Unsubscribe-Post` headers point a mail client's automated POST straight here, no page visit needed. |

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

## Data retention (gate finding F11)

A scheduled (cron) handler (`src/index.ts`'s `scheduled`, wired in
`wrangler.toml`'s `[triggers]`) purges two classes of row once daily:

- **Unconfirmed rows older than 30 days** are deleted unconditionally.
  Unconfirmed rows **never** count toward K2 (`src/k2-count.ts` only ever
  reads rows with a non-null `confirmed_at` — see its header comment), so
  this purge can never change a K2 count.
- **Confirmed-but-unsubscribed rows**, more than 30 days past their
  `unsubscribed_at`, are deleted too — but **only once the K2 verdict is
  safely recorded**: the cron skips this class entirely until the owner
  sets `Env.K2_GATE_CLOSES_AT` (an ISO-8601 date/time — day 0 + 42 days,
  once day 0 is logged in `docs/p0/K2.md`), and even then never deletes
  before that date. Until then, a confirmed signup is effectively kept
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
   wrangler d1 create golfraven-signups
   wrangler kv namespace create RATE_LIMIT_KV
   ```
   Paste the returned `database_id`/`id` into `wrangler.toml`, and set
   `account_id` (`wrangler whoami`).

2. **Apply the migration:**
   ```shell
   wrangler d1 execute golfraven-signups --remote --file=./migrations/0001_create_signups.sql
   ```

3. **Set secrets** (never put these in `wrangler.toml`):
   ```shell
   wrangler secret put RESEND_API_KEY
   wrangler secret put TURNSTILE_SECRET
   wrangler secret put TOKEN_PEPPER   # e.g. `openssl rand -hex 32`
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
   Cloudflare.

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
   (`wrangler d1 execute golfraven-signups --remote --command "SELECT email_lc, confirmed_at FROM signups"`).
   **Only then** log day 0 in `docs/p0/K2.md`, before any promotion
   (decision 0001 Addendum D R3) — this package does not, and should not,
   set that date itself. Once day 0 is logged, also set
   `K2_GATE_CLOSES_AT` in `wrangler.toml` to day 0 + 42 days (see "Data
   retention" above) and redeploy.

## How to run the K2 count

```shell
# 1. Build once (the CLI imports the built dist/k2-count.js):
pnpm --filter @golfraven/signup-worker build

# 2. Export the table (documented D1 export command):
wrangler d1 execute golfraven-signups --remote --json \
  --command "SELECT email_lc, confirmed_at FROM signups" > export.json

# 3. Run the count (day 0 and excluded addresses are read from
#    docs/p0/K2.md automatically — see its "Day 0" / "Excluded addresses"
#    sections):
node scripts/k2-count.mjs --export export.json
```

The script **refuses to run** if day 0 isn't logged in `docs/p0/K2.md`
yet (decision 0001 Addendum D R3). It prints the advisory (day0+14d, bar
100) and gate (day0+42d, bar 300) counts and a PASS/FAIL verdict against
each, plus the full result as JSON. `src/k2-count.ts` implements the
counting rule literally — see its header comment, especially: **it counts
confirmations, not current subscribers** — an address that confirmed
before the cutoff and later unsubscribed still counts.

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
