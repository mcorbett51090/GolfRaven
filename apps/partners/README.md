# @golfraven/partners

The staff, operator and admin portal PWA (build plan §3.1 row H), a static single-page app served from its own origin
(`partners.golfraven.<tld>`, owner question Q1) under a strict CSP. Design: [`docs/security/partner-auth-design.md`](../../docs/security/partner-auth-design.md)
sections 4.5 and 4.6; what S7a built and why: its "As built: S7a" section.

**S7a (this slice) is the shell, sign-in and session**: passkey sign-in, a signed-in home that shows the session, sign-out, lock, a reauth
helper for later screens, EN and FR-CA strings, the CSP, and the tests that pin all of it. The screens that do real work (course QR, attest,
hand-over, stock, manager, operator, admin) are S7b to S7d.

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
src/api/                client.ts (the token lives here), errors.ts, types.ts
src/webauthn/           base64url.ts, assertion.ts (options in, assertion JSON out)
src/auth/               sign-in.ts, reauth.ts, step-up.ts (interface only: the PIN seam)
src/app/                controller.ts (DOM-free state machine), messages.ts
src/ui/                 dom.ts (textContent-only builder), render.ts
src/i18n/               en + fr-CA, same pattern as apps/mobile
scripts/                build.mjs, lib/config.mjs, lib/csp.mjs, lib/scan-output.mjs
test/                   vitest; test/e2e/ is the Playwright suite
```

## Build

```sh
GOLFRAVEN_PARTNERS_API_BASE=https://<project>.supabase.co/functions/v1 pnpm --filter @golfraven/partners build
```

`GOLFRAVEN_PARTNERS_API_BASE` is the **functions root** of the partners API: the client calls `<base>/partner-session/<route>` and, later,
`<base>/partner-attest/...`. It is baked into the bundle and its origin becomes the CSP `connect-src`. The default is a placeholder on the
reserved `.example` TLD (`https://partners-api.golfraven.example/functions/v1`) because the real host is owner question Q1;
`GOLFRAVEN_ENV=production` **refuses the placeholder**, so a production deploy cannot ship it by accident.

Output (`dist/`): `index.html`, `assets/app-<hash>.js`, `assets/styles-<hash>.css`, `manifest.webmanifest`, `favicon.svg` and a generated
`_headers` (Cloudflare Pages syntax) carrying the CSP and the other headers. The last build step scans the output and fails the build on an
inline script, eval, `new Function`, a storage API, a service worker, a source map or an origin that is not the API's.

### Deploy checklist (operator steps; none are code)

1. Serve `dist/` from the partners origin on a host that applies `_headers` (the page also carries the CSP in a `<meta>`, so a host that ignores
   `_headers` still gets the policy minus `frame-ancestors`; the other headers would be missing, so do not rely on that).
2. The page's own origin must equal **`GR_PARTNER_ORIGIN`** and the `app.partner_rp_config.origin` row (design 18.4): they are the origin the
   server's CORS allows and the one every assertion is checked against.
3. Build with `GOLFRAVEN_PARTNERS_API_BASE` set to the real functions root.

## The CSP

`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src <API origin>; manifest-src 'self'; worker-src 'none';
object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'`.
Emitted by `scripts/lib/csp.mjs`, once as the response header and once as the `<meta>`. Stricter than design 4.6 in three places (no `'self'` in
`connect-src`, no `data:` images, `worker-src 'none'`); see the design doc's "As built: S7a". Trusted Types is enforced by Chromium; Safari
support is `[unverified]` and an unsupporting browser ignores both directives, leaving the rest of the policy in force.

## The API client

`createPartnerApi({ baseUrl })` covers every route of the S1.2 contract: `signInOptions`, `verify`, `session`, `signOut`, `lock`,
`reauthOptions`, `reauth`, plus `call(method, fn, route, body)` for later screens' authenticated calls to other partner functions. Every request:

- sends exactly `Content-Type: application/json` (GET included), plus `Authorization: Bearer ...` on session routes;
- uses `credentials: "omit"`, `redirect: "error"`, `cache: "no-store"`, `referrerPolicy: "no-referrer"` (no cookie rides along, ever);
- never sends the reserved `X-GR-PoP` header (the server ignores it today).

Errors are `PartnerApiError` with a closed `kind`: `unauthenticated` (401, the one answer for a dead session and a refused sign-in),
`reauth_refused` (403 on `POST reauth`: the session is alive), `forbidden` (403), `unsupported_media_type` (415), `rate_limited` (429),
`bad_request`, `not_found`, `unavailable` (503), `server`, `network`, `malformed_response`. A 401 on an authenticated call wipes the token
before the caller sees the error. `Retry-After` on a 429 is read when the browser lets the page see it: the partner CORS helper sends
`Access-Control-Expose-Headers: Retry-After` (and only that), so `retryAfterSeconds` is the server's value in a real cross-origin browser; it is
`null` only if a deployment drops the header, and the UI then shows a generic wait message.

## Sign-in, lock, sign-out, reauth

- **Sign-in**: `POST options`, `navigator.credentials.get` with the server's options, `POST verify`, then `GET session`. The page **refuses
  options that weaken the ceremony**: `userVerification` must be `required` and `allowCredentials` must be empty (usernameless,
  discoverable credentials), or it never calls the browser.
- **Lock**: sends `POST lock`, then **wipes the token whether or not that request succeeded**, and shows sign-in with a "Locked" notice.
  Resuming needs a new passkey tap and opens a **new** session. On the server (`partner_session_lock_for_partner`, 0049) lock clears, for that
  session only, the **PIN grant**, the **reauth window** and the **email OTP proof**, and counts as activity (it advances `last_seen_at`, which
  restarts the idle clock). It does **not** revoke the session: the server session **survives until its idle or absolute expiry** (30 min / 8 h
  for staff, shorter for operator and admin, `[proposed]`), with no holder. **Sign-out is the revoke.** On a shared shop iPad that difference
  matters: a locked session is still a valid bearer, so a token copied before the lock (the in-memory token is stealable by a script on the
  page; the CSP mitigates that and does not remove it) stays usable for up to the idle window, with step-up grants cleared. Use **sign-out at
  the end of a shift** and lock between customers. Whether lock should also revoke is an open decision for the gate (design doc 19.4); the
  behaviour is as built.
- **Sign-out**: `POST sign-out` (revokes the session), and the token is wiped even when the request fails (the UI says so honestly).
- **Reauth** (`src/auth/reauth.ts`, `reauthWithPasskey(api, { credentials })`): `POST reauth/options`, a fresh assertion, `POST reauth`; opens
  the server's 5-minute window. Exported for the screens that need it (adding a credential, A2 actions); S7a has no screen of its own for it.

## Not in S7a, and the seam each leaves

| Not built | Seam |
|---|---|
| PIN prompt and browser PBKDF2 derivation (S1.3 owns the derivation contract) | `src/auth/step-up.ts`: the `StepUp` interface and `unavailableStepUp`, which rejects every request, so a screen that needs a PIN before S1.3 lands fails closed |
| Enrolment and invite acceptance (S1.5) | none needed: they are pre-session routes; the client has `call()` for session routes and the pre-auth routes will be added beside `signInOptions` |
| Course QR, attest, hand-over, stock screens (S7b, S7c) | `render.ts` draws the signed-in home; a screen is a new `AppState` branch and `api.call(...)` |
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
  under `CI=true` it is a failure; `GOLFRAVEN_E2E_SKIP=1` opts out deliberately.

## Languages

`en` and `fr-CA`, the same shape as `apps/mobile` (`MessageKey`, `{placeholders}`, `.one`/`.other` plurals, parity test). The browser's language
picks the default and a button on the page switches; the choice is not stored (the app writes to no storage API). The French is
`[unverified: not reviewed by a native fr-CA speaker]`.
