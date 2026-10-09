# @golfraven/partners

The staff, operator and admin portal PWA (build plan §3.1 row H), a static single-page app served from its own origin
(`partners.golfraven.<tld>`, owner question Q1) under a strict CSP. Design: [`docs/security/partner-auth-design.md`](../../docs/security/partner-auth-design.md)
sections 4.5 and 4.6; what S7a built and why: its "As built: S7a" section.

**S7a is the shell, sign-in and session**: passkey sign-in, a signed-in home that shows the session, sign-out, lock, a reauth
helper for later screens, EN and FR-CA strings, the CSP, and the tests that pin all of it. **S7a's second half (this README's "PIN step-up" and
"Invites and enrolment" sections) closes the seams S1.3 to S1.5 left**: the browser-derived PIN, invite and enrolment acceptance with the first
passkey and the forced first PIN, and the operator / admin second factor. **S7b adds the attest and course-QR shop-floor screens** (PIN before every A1
action). Hand-over, stock, manager, operator and admin screens are S7c to S7d.

## The one rule that shapes everything

The opaque `gr_ps_` session token is held **in memory only**: one closure variable inside `src/api/client.ts`. It is not returned to callers,
not in `localStorage`, `sessionStorage`, IndexedDB, a cookie, Cache Storage or a service worker, not in a URL, not logged. **A reload loses it, by
design: the next session needs a fresh passkey tap.** Lock and sign-out wipe it. The page talks to the partners API origin and never to
PostgREST. Every dynamic string reaches the DOM through `textContent`, so handles and names are inert text.

## Stack

Plain TypeScript, bundled by **esbuild 0.27.7** into a static bundle. No framework, no runtime dependency (`package.json` has no `dependencies`;
a test fails if one appears and another fails if any `src/` import is not relative).

Why: the page is a few dozen DOM nodes and a handful of fetches, and its job is to be auditable under a CSP with no inline script, no eval and
Trusted Types required. A framework adds an inline-script or `new Function` risk, a supply-chain surface that ships to the browser, and a
runtime nobody reviewed. `apps/site` uses Astro 5, but Astro's value there is a content-routed multi-page site, which this app is not. esbuild
was already in the lockfile (vitest 5 uses it through Vite 8), so **the lockfile gains one importer entry and no new package**; the version is
pinned exactly. pnpm 10 prints "Ignored build scripts: esbuild" at install: esbuild's own postinstall is only an optimisation, its binary comes
from the platform optional dependency, and the build runs without it.

## Layout

```
index.html              page template (no inline script, no inline style, CSP meta)
public/                 manifest + icon, copied as-is
src/main.ts             entry: wires the client, the controller and the renderer
src/api/                client.ts (the token lives here), session-routes.ts (typed step-up routes), errors.ts, types.ts
src/webauthn/           base64url.ts, assertion.ts (sign-in), registration.ts (create: options in, registration JSON out)
src/auth/               sign-in.ts, reauth.ts, pin.ts (browser derivation), step-up.ts (requirePin), pin-setup.ts (set / change / email proof)
src/app/                controller.ts (DOM-free state machine), state.ts, enrol-flow.ts, panels.ts, invite-link.ts, messages.ts
src/ui/                 dom.ts (textContent-only builder), forms.ts, notice.ts, render.ts, views-enrol.ts, views-panels.ts
src/i18n/               en + fr-CA, same pattern as apps/mobile
scripts/                build.mjs, lib/config.mjs, lib/csp.mjs, lib/scan-output.mjs
test/                   vitest; test/e2e/ is the Playwright suite
```

## Build

```sh
GOLFRAVEN_PARTNERS_API_BASE=https://<project>.supabase.co/functions/v1 pnpm --filter @golfraven/partners build
```

`GOLFRAVEN_PARTNERS_API_BASE` is the **functions root** of the partners API: the client calls `<base>/partner-session/<route>`,
`<base>/partner-invites/<route>`, `<base>/partner-attest/<route>`, `<base>/course-qr/<route>` and `<base>/qr-print`. It is baked into the bundle, and the CSP `connect-src` is built from it: one **path-scoped** source per partner
function (`<base>/partner-session/`; the list is `src/api/partner-functions.json`, the same one the client's `call()` allow-list uses), never the
whole API origin (the same host serves `/rest/v1` and every other edge function). The default is a placeholder on the
reserved `.example` TLD (`https://partners-api.golfraven.example/functions/v1`) because the real host is owner question Q1;
`GOLFRAVEN_ENV=production` **refuses the placeholder** (any spelling, a trailing dot included), **refuses `localhost`, loopback and bare-IP
hosts**, and **refuses `GOLFRAVEN_PARTNERS_E2E=1`**, so a production deploy cannot ship any of them by accident.

Output (`dist/`): `index.html`, `assets/app-<hash>.js`, `assets/styles-<hash>.css`, `manifest.webmanifest`, `favicon.svg` and a generated
`_headers` (Cloudflare Pages syntax) carrying the CSP and the other headers. The last build step scans the output and fails the build on an
inline script, eval, `new Function`, a storage API, a service worker, a source map or an origin that is not the API's, and (from esbuild's metafile)
on any bundle input that is not under `src/` or that comes from `node_modules`.

`_headers` also carries `Strict-Transport-Security: max-age=31536000; includeSubDomains`, and marks `/`, `/index.html` and `/invite` `Cache-Control: no-store`
(the hashed `/assets/*` stay immutable). `Permissions-Policy: camera=(self)` from S7b (paste-only attest for now; a later scan into the token field can use the camera without another header change).

### Deploy checklist (operator steps; none are code)

1. Serve `dist/` from the partners origin on a host that applies `_headers` (the page also carries the CSP in a `<meta>`, so a host that ignores
   `_headers` still gets the policy minus `frame-ancestors`; the other headers would be missing, so do not rely on that).
2. The page's own origin must equal **`GR_PARTNER_ORIGIN`** and the `app.partner_rp_config.origin` row (design 18.4): they are the origin the
   server's CORS allows and the one every assertion is checked against.
3. Build with `GOLFRAVEN_PARTNERS_API_BASE` set to the real functions root.

## The CSP

`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src` one path-scoped source per entry of `partner-functions.json`
(`partner-session`, `partner-invites`, `partner-members`, `partner-attest`, `course-qr`, `qr-print`); `manifest-src 'self'; worker-src 'none';
object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'`.
Emitted by `scripts/lib/csp.mjs`, once as the response header and once as the `<meta>`. Stricter than design 4.6 in three places (no `'self'` in
`connect-src`, no `data:` images, `worker-src 'none'`); see the design doc's "As built: S7a". Trusted Types is enforced by Chromium; Safari
support is `[unverified]` and an unsupporting browser ignores both directives, leaving the rest of the policy in force.

## The API client

`createPartnerApi({ baseUrl })` covers every route of the S1.2 contract: `signInOptions`, `verify`, `session`, `signOut`, `lock`,
`reauthOptions`, `reauth`; the **pre-session routes of S1.5** beside `signInOptions`: `acceptStart(kind, token)`, `acceptVerify(kind, { token, code })`
(`kind` is `invite` or `enrolment`) and `registerFirst({ challenge, credential })` (the first credential, which opens the first session: the token is
held by the client exactly as `verify`'s is, and a cancel while it is on the wire revokes it instead); plus `call(method, fn, route, body)` for every
other authenticated route. The step-up routes (`GET pin`, `step-up/pin`, `pin/set`, `pin/change`, `otp-proof/*`, `totp/*`) go through `call` and are
typed in `src/api/session-routes.ts`. Every request:

- sends exactly `Content-Type: application/json` (GET included), plus `Authorization: Bearer ...` on session routes;
- uses `credentials: "omit"`, `redirect: "error"`, `cache: "no-store"`, `referrerPolicy: "no-referrer"` (no cookie rides along, ever);
- never sends the reserved `X-GR-PoP` header (the server ignores it today).

Errors are `PartnerApiError` with a closed `kind`: `unauthenticated` (401, the one answer for a dead session and a refused sign-in),
`reauth_refused` (403 on `POST reauth`: the session is alive), `forbidden` (403), `unsupported_media_type` (415), `rate_limited` (429),
`conflict` (409), `gone` (410), `unprocessable` (422), `bad_request`, `not_found`, `unavailable` (503), `server`, `network` (a refused, dropped or **timed-out** request: every request is cut off after
15 s), `malformed_response`, `aborted` (a cancelled sign-in). A 401 on an authenticated call wipes the token before the caller sees the error. `Retry-After` on a 429 is read when the browser lets the page see it: the partner CORS helper sends
`Access-Control-Expose-Headers: Retry-After` (and only that), so `retryAfterSeconds` is the server's value in a real cross-origin browser; it is
`null` only if a deployment drops the header, and the UI then shows a generic wait message.

## Sign-in, lock, sign-out, reauth

- **Sign-in**: `POST options`, `navigator.credentials.get` with the server's options, `POST verify`, then `GET session`. The page **refuses
  options that weaken the ceremony**: `userVerification` must be `required` and `allowCredentials` must be empty (usernameless,
  discoverable credentials), or it never calls the browser.
- **Lock** (gate ruling, design 20.4): wipes the token and shows sign-in with a "Locked" notice **at once**, then sends `POST sign-out` with a
  copy of the token, so lock **revokes the session**: a token copied out of the page before the lock is dead immediately, not at its idle
  expiry. Resuming needs a new passkey tap and opens a **new** session. The wording stays "Locked" (and, if the server could not be told,
  "locked on this device, the server could not be reached"). The server's own `lock` route (clears the PIN grant, reauth window and OTP proof
  without revoking, 0049) is **no longer called by the page**; retiring it, or making it revoke with `revoke_reason = 'lock'`, is a server
  follow-up (not in this slice), and any non-revoking lock must authorize as PEEK.
- **Sign-out**: the same ordering: the token is wiped and the screen leaves the session **before** `POST sign-out` is sent, and it stays that way
  if the request fails or never answers (the UI then says so honestly). Lock and Sign-out are never disabled by a busy refresh.
- **Leaving the page**: `pagehide` wipes the token and sends a keepalive sign-out; `pageshow` with `persisted` (a back/forward-cache restore)
  forces signed-out (`src/app/lifecycle.ts`). Chromium restores a page from the bfcache with its variables and screen intact, so a signed-in
  page could come back with a live token.
- **Reauth** (`src/auth/reauth.ts`, `reauthWithPasskey(api, { credentials })`): `POST reauth/options`, a fresh assertion, `POST reauth`; opens
  the server's 5-minute window. Exported for the screens that need it (adding a credential, A2 actions); S7a has no screen of its own for it.

## PIN step-up

The PIN is four digits, typed on this page, turned into 32 derived bytes **in the browser**, and only those bytes leave it (design 6.3, 19.4).

- **The contract is shared, not copied.** `src/auth/pin.ts` imports `supabase/functions/_shared/partner/pin-contract.ts` and `pin-deny-list.ts` (Web Crypto
  only) by relative path, plus `token.ts` for the base64url helpers. `scripts/lib/inputs.mjs` allows exactly those three files outside `src/` (an exact
  list, not a directory: a fourth fails the build) and still refuses everything from `node_modules`. `test/pin.test.ts` pins the derivation to
  `pin-vectors.ts` (four vectors computed with Python, at the floor, the default and the ceiling) **and** to node's own PBKDF2 as an independent oracle.
- **`requirePin(actionClass)`** (`src/auth/step-up.ts`, wired on the controller) is what an A1 or A2 screen calls. One call is the whole conversation: `GET pin`
  (salt and iteration count; a locked, unset or must-change PIN ends the call at once), the prompt, the rule and deny-list check, PBKDF2, `POST step-up/pin`
  with `{ derived }` and nothing else. A wrong PIN or a back-off asks again (the server counts; five consecutive failures lock); the call resolves with a
  `PinGrant` (single-use, 60 s, 30 s for A2) or rejects with a `StepUpError` (`cancelled`, `unset`, `must_change`, `locked`, `bad_params`, `busy`).
  `unavailableStepUp` is still exported: a screen wired with it fails closed.
- **The rules bite here.** A PIN the shape rule or the deny-list refuses is never derived and never sent, at a set **and** at a verify (it cannot be a PIN
  this page ever set, and it costs the member no failure). A server that asks for a work factor outside `[210000, 1000000]`, or a salt that is not 16 bytes,
  is refused before anything is derived (`bad_params`).
- **Set and change** (`src/auth/pin-setup.ts`, the "PIN" button on the home screen): a fresh 16-byte salt and 600,000 iterations, sent as `{ derived, salt, iterations }`.
  The server only accepts it inside the session's enrolment window or after an **email proof** (a code mailed to the member's own address:
  `otp-proof/start`, `otp-proof/verify`); the page opens the proof first when neither is live. A change also needs the current PIN.
- **The first PIN after an enrolment is forced**: the screen after the first passkey is the set-PIN form and it has no cancel (Lock and Sign out stay). It may
  be left only after the server has refused to give this person a PIN (an operator or admin holds none) or already has one.
- **Honest limit.** A JavaScript string cannot be wiped: the four digits live in the page's heap until it is collected (a heap snapshot after a set still
  finds them; the invite token and the session token are not retained once their flow ends or the session does). What the page guarantees is that the digits
  are never put in a request, a URL, a header, any storage, the console or the controller's state.

## Invites and enrolment

`https://partners.<tld>/invite#<gr_inv_ token>` (or a `gr_enr_` token for a recovery or admin enrolment, pasted from "I have an invite or enrolment code"):

1. **Open or paste.** The token rides in the URL **fragment** (never sent to a server); `src/app/invite-link.ts` hands it to the flow and removes it from the
   address bar. Nothing is sent by opening the link. The token is held in the flow's closure only: it is not in the state, so it is never drawn.
2. **Email me a code** (`accept/start`): the server mails a one-time code to the address on the invite (the page types no address) and answers one constant body.
3. **The code** (`accept/verify`): on success the server returns the create ceremony's options. A person who already has a passkey (`409 existing_member_sign_in`) or needs a manager's recovery (`409 recover_required`) is sent to sign-in with that notice.
4. **Create passkey** (a button press: Safari wants a user gesture): `navigator.credentials.create` for the server's options, which the page refuses if they weaken the ceremony (UV and resident key required, attestation `none`, ES256 / RS256 only, 32-byte challenge); then `POST credentials`, which stores the credential and opens the **first session**.
5. **The forced first PIN**, then home. If `aal` is below the required level the home screen offers the second factor.

Deploy: `/invite` must serve `index.html` (Cloudflare Pages does this for a project with no `404.html`; `_headers` marks `/invite` no-store).

## The second factor (operators and admins)

When `aal < requiredAal` the home screen offers **Enter authenticator code** (`step-up/totp`) and **Add an authenticator** (`totp/enrol`, gated by the same
email proof or enrolment window, then `totp/confirm` in the same session). The seed is shown **once, as text** (and the `otpauth://` link): there is no QR
renderer in the page (no dependency may be added), so the person types the key into an authenticator app. The seed is in the state only while its panel is open.

## Not built, and the seam each leaves

| Not built | Seam |
|---|---|
| Camera scan of a player check-in QR into the attest token field | `camera=(self)` is open; the field is paste-only today |
| Hand-over, stock, manager / operator / admin screens (S7c–S7d) | `controller.requirePin` / `reauthWithPasskey` / `openTotp`; `state.work` is the pattern for a shop-floor screen |
| Invite create / list / revoke, branch E (an existing member joins another org), member recovery, credential list | `partner-invites` and `partner-members` are in the CSP and the `call()` allow-list; the pre-session half is built, the session half is not |
| A QR for the TOTP seed | none: the seed and the `otpauth://` link are shown as text |
| Offline behaviour | none |
| **Service worker** | **deliberately none.** The page is installable-ish through its manifest only. A service worker would sit between the page and the token's requests and could cache an API response; the design wants neither. If one is ever added it must never cache API responses or touch the token, `worker-src` must be widened to `'self'`, and the build scan's service-worker rule must be revisited deliberately |

## Tests

```sh
pnpm --filter @golfraven/partners test          # vitest, then the Playwright suite
pnpm --filter @golfraven/partners test:unit     # vitest only
pnpm --filter @golfraven/partners test:e2e      # Playwright only
```

- **Unit**: the client (headers, credentials, error mapping, spies on every storage API and `console`), base64url, the WebAuthn options and
  serialiser, the controller, i18n parity, the CSP (including Google's `csp_evaluator`), a source scan, and a real build whose output is scanned
  (with must-fail fixtures proving the scanner catches each thing it exists to catch).
- **Contract**: `test/contract.test.ts` and `test/controller.test.ts` run the **real** `partner-session` handler
  (`supabase/functions/_shared/partner/session-handler.ts`) over in-memory ports with real ES256 assertions, so the client's requests are judged
  by the server's own Origin, media-type, bearer and body rules.
- **Playwright** (`test/e2e/`): the built bundle served under its real `_headers` CSP, a Chromium **virtual WebAuthn authenticator** over CDP
  (`WebAuthn.enable`, `addVirtualAuthenticator`, `addCredential`) signing in against the same real handler on a second `localhost` port (so CORS is
  real). It asserts zero CSP violations, the token absent from every storage API and from the V8 heap after lock and sign-out, a reload landing on
  sign-in with no request, no cookie on any request, and a probe page proving the CSP really blocks eval, `new Function`, inline script, inline
  handlers, `javascript:` links, `innerHTML`, a foreign origin and a Trusted Types policy. Chromium comes from `PLAYWRIGHT_BROWSERS_PATH`
  (`/opt/pw-browsers` here); never run `playwright install` locally. Outside CI a browser that cannot launch skips the suite with a message;
  under `CI=true` it is a failure; `GOLFRAVEN_E2E_SKIP=1` opts out deliberately. A machine with a Chrome but without the pinned build may point the suite at it with
  `GOLFRAVEN_E2E_CHROME=/path/to/chrome` (CI never sets it).
- **The S7a PIN and invite cells**: the fake partner server (`test/support/fake-partner-server.ts`) now runs the real `partner-invites` handler too, with
  working in-memory PIN, email proof, TOTP, invite / enrolment acceptance and a registration verifier that really parses the attestation object the
  browser (or the software authenticator) produced, so an enrolled credential can sign in afterwards. The e2e harness page mounts the real app on demand
  and has a "request PIN (A1)" button standing in for the first A1 screen.

## Languages

`en` and `fr-CA`, the same shape as `apps/mobile` (`MessageKey`, `{placeholders}`, `.one`/`.other` plurals, parity test). The browser's language
picks the default and a button on the page switches; the choice is not stored (the app writes to no storage API). The French is
`[unverified: not reviewed by a native fr-CA speaker]`.
