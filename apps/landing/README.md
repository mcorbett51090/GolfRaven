# @golfraven/landing

The K2 landing page (build plan §10 P0, check K2 — "player signal"): a
static, dependency-free page promoting "Track & complete the Tennessee Golf
Trail and the Vancouver Island Golf Trail — get the finisher's marker",
with a double-opt-in email signup form. It has no build framework, no
third-party scripts, and no trackers, by design (K2's channel is organic
promotion, not paid, per O23/O24).

## Structure

- `src/index.html` — the page markup and copy.
- `src/styles.css` — mobile-first styles, GolfRaven placeholder brand
  colors (P2 designs the real mark, build plan §5.6).
- `src/config.js` — sets `window.SIGNUP_ENDPOINT`. Blank (`""`) by default.
- `src/main.js` — wires the signup form to `SIGNUP_ENDPOINT`. If no
  endpoint is configured, the form is never shown; the page shows
  "Signups open soon" instead, and never attempts a submit with nowhere to
  send it.
- `scripts/build.mjs` — copies `src/` to `dist/` verbatim.
- `scripts/test.mjs` — a smoke check (no external references, expected
  scripts only, `SIGNUP_ENDPOINT` defaults empty, required copy present).

## How signups work (double opt-in)

1. The visitor submits their email (and trail preference) to
   `SIGNUP_ENDPOINT` as `POST { email, trail }` (JSON).
2. **The backend is not built yet.** Wiring `SIGNUP_ENDPOINT` to something
   real requires, at minimum:
   - an endpoint that accepts the POST, validates the email, and stores
     `{ email, trail, confirmedAt: null }` somewhere durable (even a simple
     KV/table is enough at P0 scale);
   - **custom SMTP with SPF, DKIM and DMARC configured for the sending
     domain** (build plan §10 P0: "Set up custom SMTP with SPF/DKIM/DMARC"
     is an explicit P0 external prerequisite, owned by Matt) — without
     correctly configured SPF/DKIM/DMARC, confirmation emails land in spam
     or get rejected outright, which would quietly sink K2's signup count;
   - the confirmation email itself, with a single-use confirmation link
     that flips `confirmedAt` and is what actually adds the signup to the
     list — an unconfirmed row never counts toward K2's N = 300 (build
     plan §10 P0, K2's full gate);
   - an unsubscribe path (link in every email, or a reply-to address) per
     the privacy notice on the page.
3. Until that backend exists, `SIGNUP_ENDPOINT` stays `""` and the page
   correctly shows "Signups open soon" — this is deliberate, not a bug.

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
3. Set `SIGNUP_ENDPOINT` (via `src/config.js`, or by templating it at
   deploy time) to the real backend endpoint once it exists.
4. Point `golfraven.<tld>` at the Pages project.

Nothing above is done by this P0 skeleton — the page works today as a
static "signups open soon" placeholder, which is a valid K2 state (the
early-read threshold is advisory and the 6-week N = 300 gate is what
matters — build plan §10 P0, K2).
