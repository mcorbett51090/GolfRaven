# @golfraven/landing

The K2 landing page (build plan §10 P0, check K2 — "player signal"): a
static, dependency-free page promoting "Track & complete the Tennessee Golf
Trail and the Vancouver Island Golf Trail — get the finisher's marker",
with a double-opt-in email signup form. It has no build framework and no
trackers/analytics, by design (K2's channel is organic promotion, not
paid, per O23/O24). It loads exactly ONE third-party script — Cloudflare
Turnstile, a spam/bot check on the signup form, and only once signups are
actually open (see "How signups work" below and `_headers`'s CSP).

## Structure

- `src/index.html` — the page markup and copy.
- `src/styles.css` — mobile-first styles, GolfRaven placeholder brand
  colors (P2 designs the real mark, build plan §5.6).
- `src/config.js` — sets `window.SIGNUP_ENDPOINT` and
  `window.TURNSTILE_SITE_KEY`. Both blank (`""`) by default.
- `src/main.js` — wires the signup form to `SIGNUP_ENDPOINT`. If either
  `SIGNUP_ENDPOINT` or `TURNSTILE_SITE_KEY` is unconfigured, the form is
  never shown and the Turnstile script is never loaded; the page shows
  "Signups open soon" instead, and never attempts a submit with nowhere to
  send it (or no way to pass Turnstile verification).
- `src/_headers` — Cloudflare Pages headers, including the CSP that
  allow-lists exactly `https://challenges.cloudflare.com` and nothing else.
- `scripts/build.mjs` — copies `src/` to `dist/` verbatim.
- `scripts/test.mjs` — a smoke check (no external references beyond the
  one allowed Turnstile origin, expected scripts only, `SIGNUP_ENDPOINT`
  and `TURNSTILE_SITE_KEY` default empty, required copy present).

## How signups work (double opt-in)

1. The visitor submits their email, trail preference, 16+ confirmation and
   the consent-copy version to `SIGNUP_ENDPOINT` as
   `POST { email, trail, ageConfirmed, consentVersion, turnstileToken, source }`
   (JSON) — `turnstileToken` comes from the Cloudflare Turnstile widget,
   and `source` is the same trail-preference value as `trail` (the backend
   doesn't have a dedicated `trail` column; `source` is where it's kept).
2. **The backend is now built** — `apps/signup-worker` (a Cloudflare
   Worker + D1), a sibling package in this monorepo — but **it is not yet
   deployed**, which is still a genuine P0 blocker for K2's clock: see
   `apps/signup-worker/README.md` for what it stores and why, and its
   "Owner deploy runbook" for the remaining steps (D1/KV provisioning,
   Resend domain verification + SPF/DKIM/DMARC, Turnstile widget
   creation, setting the route). Until it's deployed and
   `SIGNUP_ENDPOINT`/`TURNSTILE_SITE_KEY` are pointed at it, no signup can
   be recorded and K2 has not started.
3. Until then, `SIGNUP_ENDPOINT` (and/or `TURNSTILE_SITE_KEY`) stays `""`
   and the page correctly shows "Signups open soon" — this is deliberate,
   not a bug.
4. **K2's clock (Day 0) is pinned in `docs/p0/K2.md`, not implied by this
   README** (decision 0001, Addendum D, R3): Day 0 is the UTC date the
   page is publicly reachable **and** the backend has delivered a
   confirmation email end to end. It is logged in `docs/p0/K2.md`
   *before* any promotion, and the clock is never restarted. The count
   that matters is distinct lower-cased emails whose `confirmedAt` falls
   before Day 0 + 14 days (advisory) and Day 0 + 42 days (the N = 300
   gate); owner/test addresses are excluded only if listed in
   `docs/p0/K2.md`'s "Excluded addresses" field before Day 0.
   `apps/signup-worker/scripts/k2-count.mjs` computes this count and
   refuses to run until Day 0 is set.

## Before this page goes live

Before deploying for real (setting `SIGNUP_ENDPOINT` and pointing the
domain at this build), fill in the `[OPERATING ENTITY NAME — TBD]` and
`[CONTACT EMAIL — TBD]` placeholders in `src/index.html`'s privacy
section. `scripts/test.mjs` enforces this: when the `DEPLOY=1` environment
variable is set, the smoke test **fails the build** if either placeholder
is still present in the built `dist/index.html` (gate review S5). Local
and CI builds that don't set `DEPLOY=1` are unaffected, so the
still-placeholder page keeps building and testing green until the owner
fills these in and a deploy is actually attempted.

## Deployment (owner step, not done in this P0 skeleton)

The plan (build plan §10 P0) targets **Cloudflare Pages** at
`golfraven.<tld>` (the domain itself is also a P0 external prerequisite:
register `golfraven.com` preferred, hold `.golf`/`.ca` if cheap). Deploying
`dist/` there is an **owner step**, because it needs credentials this
skeleton does not have:

1. Register the domain (if not already done as part of the P0 external
   prerequisites).
2. Create a Cloudflare Pages project and connect it to this repo (or use
   `wrangler pages deploy dist` directly, as `deploy-site.yml` will for
   `apps/site` from P2 on — build plan §5.2).
3. Set `SIGNUP_ENDPOINT` and `TURNSTILE_SITE_KEY` (via `src/config.js`, or
   by templating them at deploy time) once `apps/signup-worker` is
   deployed (see its README's "Owner deploy runbook").
4. Point `golfraven.<tld>` at the Pages project.

Nothing above is done by this P0 skeleton — the page works today as a
static "signups open soon" placeholder, which is a valid K2 state (the
early-read threshold is advisory and the 6-week N = 300 gate is what
matters — build plan §10 P0, K2).
