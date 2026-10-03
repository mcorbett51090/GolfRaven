# @golfraven/mobile

GolfRaven's mobile app (Expo SDK 57 / React Native 0.86, build plan §3.1 row G, §7).

**Status: P4.1 first slice + P4.2a** — the app shell, the signed catalog cache, the outbox model, EN/FR-CA scaffolding and the
16+ age screen (P4.1), and, from P4.2a, a **real `ApiClient`** for the Edge Functions that exist (sign-in methods, delete,
export, push token), secure token storage, Sign in with Apple / email OTP sign-in, account linking, deletion and export. The
mock of `api.*` survives for tests and the `__DEV__` demo only. It started before M-freeze, the K3/K4 verdicts and the
production catalog keyset, on the owner's instruction; read **"What is gated"** below before relying on any of it.
**P4.2b-1 adds** real evidence submission (single and batch), prefetched check-in challenges and the attestation *seam* (below). **Still P4.2b-2 / later:** the native App Attest / Play Integrity modules, the offline TOTP, Wallet activation.
**Nothing here has run on a device or against a real Supabase project / Apple / Google** `[unverified]`.
The P0 Android Health Connect reader for check **X1** is still here, unchanged in behaviour.

- Library choices and the findings behind them: [`SPIKE.md`](SPIKE.md).
- Spec: `RavenGolf/docs/golf-trails/02-build-plan.md` §7 (the app), §3.3/§3.5 (the signed catalog), §10 P4.

## Layout

```
app/                    expo-router routes ONLY (thin screens). Note: never create src/app/ —
                        expo-router would use it as the route root instead of this directory.
  _layout.tsx           providers + the minAppVersion force-update gate
  (tabs)/               Trails (+ directory), Played, Achievements, Wallet (conditional), Me
  trail/[id] facility/[id] course/[id]   guest-browsable detail pages
  age-gate.tsx sign-in.tsx sign-in-methods.tsx force-update.tsx dev/x1.tsx
src/
  catalog/              signed-catalog verifier + cache (the fail-closed core)
  outbox/               §7.6 outbox: pure state machine, stores, runner
  db/                   SqlDatabase interface, migrations, expo-sqlite adapter
  age/ signin/          O18 age gate (flag in the secure store); sign-in state machines, nonce, Apple/Google adapters
  api/                  ApiClient interface; the real HTTP client (zod-validated, retry policy); the in-memory mock (dev/tests only)
  auth/                 AuthService seam; supabase-auth.ts (@supabase/auth-js, session in the secure store); mock-auth.ts (dev only)
  secure/               SecureStore interface + expo-secure-store adapter (session, O18 age flag, device id)
  account/              Me → Sign-in methods link flow, account deletion + local wipe, data export + share sheet
  push/                 push-token registration (client call + adapter; the native module is a follow-up)
  wallet/               O17 visibility rule
  browse/               pure selectors for the guest screens
  i18n/                 en + fr-CA catalogues, plural rules, locale resolution
  runtime/              composition root and React context (the only place that wires things); backend selection (real/demo/unconfigured)
  screens/ ui/ demo/    shared screen pieces, components, a labelled dev-only demo catalog
  health-connect/       P0 X1 reader (below)
test/                   vitest; test/support has the real-signer fixtures and the node:sqlite adapter
```

## What is built

| Area | State |
|---|---|
| **Navigation** | expo-router tabs + stack. Typechecks and **bundles for Android and iOS** (`expo export`, Metro + Hermes). Never run on a device or simulator `[unverified — needs a device]`. |
| **Guest browse (P4 AT 13)** | Trails list, Directory, region filter, Trail page (roster stops, `0 of n`), Facility page, Course page with booking rail, all with no account. "Near me" and "in progress" are not built. |
| **Signed catalog cache (AT 12)** | Fetches `catalog/v1/{manifest,manifest.sig,versions,versions.sig}.json` from `EXPO_PUBLIC_CATALOG_BASE_URL`; verifies the Ed25519 signatures over the exact bytes with the **same** canonical-JSON / domain-tag code the signer uses (`@golfraven/catalog-tools/manifest-core`); honours `minAppVersion` (force-update screen, cached catalog stays readable) and `revokedKids`; checks every shard's SHA-256 and length before swapping the cache atomically; re-verifies the cache on every load. A bad signature is never applied and raises the "catalog out of date" banner. **Rollbacks:** a manifest older than the highest `catalogVersion` this install has ever verified (`maxVerifiedCatalogVersion`, its own SQLite row, raised on every verified manifest — including `update_required` and same-version ones) is refused, and that floor survives the cache being dropped (revocation, keyset change, corruption). It does **not** survive an uninstall / "clear data" or the in-memory fallback store (SQLite could not be opened); an optional compiled-in `MIN_CATALOG_VERSION` (`src/catalog/keys.ts`, empty for now) bounds those cases once set. `refresh()` is single-flight and the floor is re-checked inside the save transaction. A corrupt revoked-set or floor row refuses every catalog (`TRUST_STATE_CORRUPT`) instead of reading as empty. The app shows a dedicated banner (not "catalog out of date") and **Me → Reset catalog data** is the way out (the button is shown only in that state, and `resetCatalogData()` is a no-op on a healthy install, so it can never strand a readable catalog): it drops the cache, clears **only unreadable** trust rows (re-seeding a cleared floor from `MIN_CATALOG_VERSION`) and **keeps a valid floor and a valid revoked set** (clearing those would be a one-tap rollback / un-revocation). Trade-off: clearing a *corrupt* revoked set forgets revocations until the next verified manifest re-lists them, and clearing a *corrupt* floor re-opens rollback down to the compiled-in minimum until the next verified manifest raises it (`src/catalog/manager.ts` header). Fetches have a timeout, a streamed size cap and refuse redirects, and send no cookies; the runtime injects `expo/fetch` (`src/runtime/services.ts`), whose body is a native stream, so the cap applies while streaming `[the stream cap, redirect refusal and cancellation are unverified on a device — only the installed expo source was read]`; RN's global `fetch`, believed to expose no body stream, is only the fallback used by tests. |
| **Outbox (AT 11)** | `pending → sent → accepted \| queued \| retry \| needs_attention` as a pure, tested state machine; SQLite persistence behind `OutboxStore`; a runner with crash recovery, backoff + jitter + `Retry-After`, 422 `catalog_stale` re-match, "Unlisted course" hold, 90-day dead letters. Matching is stubbed (see below). |
| **Age gate (AT 20)** | Neutral birth-year screen, runs before any provider; under the minimum only a device-local flag is kept and the retry is refused; the year is never stored. **The flag lives in the secure store** (`…ThisDeviceOnly` Keychain class, so it is not in an iCloud backup or a device migration); an old SQLite flag is moved across once and deleted; if the secure store fails the gate **fails closed** (sign-in blocked, browse still works). |
| **Evidence submission (P4.2b-1)** | `ApiClient.submitEvidence` → `POST evidence`, and `submitEvidenceBatch` → `POST evidence-batch` for historic imports (`origin: "import"`: date-only sources, sorted by event time, split at the server's 100 items and 64 KiB). Body shape = the server's strict whitelist (`src/evidence/payload.ts`, compared in tests with bodies the **real handlers accepted**); `source_ref` / `input_hash` canonicalisation = the server's (`source-ref.ts`, cross-checked with its own output). **The server's answers map to the §7.6 table; where the plan and the server differ the server wins** (see "Plan vs server" below). Never retried inside the http client (the outbox owns retries); the bearer is `credentials.accessToken` only. A **401** is not a rejection: the runner refreshes the item's owner's token once and resends once, else the item is `retry` and the pass stops. A payload that is not a valid submission is a local dead letter (`unsendable`), never a request. `test/evidence-wire.test.ts`, `test/evidence-runner.test.ts`. |
| **Check-in challenges (P4.2b-1)** | Up to 10 single-use challenges prefetched while online and signed in (`checkin-challenge`, TTL read from the server: 24 h), kept in SQLite (schema v3, `checkin_challenge`) **per owner and per device**, dormant on sign-out like outbox items, deleted on account deletion (the deleted user's only) and when expired. A check-in consumes exactly one **atomically, before use**; it is never offered again, even if the send fails. Redeemed at send time (`checkin-token`, as the owner), the jti persisted before the evidence request. None left (or expired) → the evidence goes without one and the item says so (`evidencePenaltyApplies`: the server's x0.6). Online, a live challenge can be taken instead. `src/challenges/`, `test/challenges.test.ts`. |
| **Attestation seam (P4.2b-1)** | `src/attest/`: the `Attestor` interface (`generateKey`/`attestKey`/`assert` for iOS, `integrityToken` for Android), typed results (`ok` / `unattestable` / `failed`, never thrown), the **server's** request bindings byte for byte (`binding.ts`, cross-checked with vectors the server's own functions produced), and `UnattestableAttestor`, the only implementation shipped: every operation answers `unattestable / not_implemented`, `hardwareSupportsAttestation: false`, so a redemption is graded `unattestable` (G3-08), never `failed`. **No native dependency was added.** |
| **Real `ApiClient` (P4.2a)** | `src/api/http-client.ts` against `<EXPO_PUBLIC_API_BASE_URL>/<function>`: `me-signin-methods` (list / link / unlink), `me-delete`, `me-export`, `me-push-token`. Every response is validated with zod; the shapes were **recorded from the server's own handlers** (`test/fixtures/edge-contract.json`), every error status is mapped to an `ApiError`, bearer = Supabase access token (one forced refresh on a 401), idempotent calls retry (network / 5xx / short 429), `link`/`unlink` never do. Details and the endpoint table: header of `http-client.ts`. Evidence and check-in calls are P4.2b-1 (next row). No endpoint serves `getPolicy` / plays / achievements / programmes yet, so the real client answers the compiled default (16) and "nothing" **without a request**. |
| **Release builds never use the mock** | Three layers (`src/dev-guard.ts`): selection (`runtime/backend.ts`: real / demo / unconfigured, demo only when `__DEV__` and no server configured), construction (a mock needs a token only `devOnly(true)` can issue), bundling (nothing imports a mock statically; the one `require` is under `__DEV__`; `expo export --no-bytecode` of both platforms was grepped: no mock string in the release bundle). A release build with no server config is **unconfigured**: network calls fail with `not_configured`, nothing is faked. `test/backend.test.ts`. |
| **Token storage** | `expo-secure-store` 57.0.4 via `src/secure/`, every item `keychainAccessible: AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY`. The Supabase session (access + refresh token) is persisted by `@supabase/auth-js` 2.65.0 through that store under one key and nowhere else (`test/supabase-auth.test.ts` runs the real library against a fake GoTrue). Never SQLite, never AsyncStorage (not installed; scanned). |
| **Sign-in (O12/O18)** | Age screen first, then **Sign in with Apple** (`expo-apple-authentication`, iOS), **email OTP** (Supabase Auth codes), **Google** behind an adapter that says "not configured" (no native SDK in this build). Apple: a CSPRNG raw nonce, **SHA-256 hex to Apple, raw to the server and to Supabase Auth**; right after sign-in the app calls `link` once to hand the server the authorization code so the grant can be revoked on deletion. Apple is listed first and is present wherever Google is (AT 17). `src/signin/flow.ts`. |
| **Me → Sign-in methods (AT 18)** | List, remove (never the last: 422 `last_sign_in_method`), add Sign in with Apple. **Never auto-links:** on `409 email_proof_required` the flow stops; a code is sent only when the player taps "Send me a code" (Auth with `shouldCreateUser: false`), and the proof is sent only when they type it and confirm. 422 wrong code (attempts left), 429 lockout, 409 relay / already-linked / refused, 501, 502/503 all have copy. A private-relay Apple account links only here. `src/account/link-flow.ts`. |
| **Delete / export / push** | Delete: confirm (en, fr-CA) → `DELETE me-delete` → wipe the session, **the deleted user's** outbox rows and check-in challenges (plus the ownerless legacy rows; another user's dormant plays stay), a data export left in the share cache, and user caches; **the device-local age flag, the device id, the language and the public signed catalog are kept**. Export: `GET me-export` → a dated `.json` in the cache dir → the share sheet → deleted again. Push: `POST me-push-token` behind a permission prompt asked only from a button; `expo-notifications` is **not** installed, so the control is disabled in this build. |
| **i18n (EN / FR-CA)** | Typed catalogues with a parity test; French is machine-drafted and unreviewed. Catalog `nameFr` / `blurbFr` are used in fr-CA. |
| **Wallet (O17)** | Tab hidden unless some trail's mock programme status is `pilot`/`live`; contents are placeholders. |
| **Policy gates** | `test/policy.test.ts` (and `test/config-api.test.ts`: only public `EXPO_PUBLIC_*` values are read, a `service_role` / secret key is refused, no secret-shaped literal ships): no `app.config.*` (a dynamic config could hide things from a scan of `app.json`); the static **and** Expo-resolved config is clean; no background-location / `SYSTEM_ALERT_WINDOW` permission, permission names compared short or qualified; config plugins limited to an allow-list; `android.allowBackup` is `false`; the **generated** `AndroidManifest.xml` and `Info.plist` are clean (AT 5); no ads/analytics SDK in the lockfile (AT 7). The generated-file tests skip locally unless you ran `expo prebuild --no-install`, and **fail** under `CI` if the files are missing; the `verify` job runs prebuild first. |

## Configuration

| Variable | Purpose |
|---|---|
| `EXPO_PUBLIC_CATALOG_BASE_URL` | `https://host[/path]` serving `catalog/v1/`. Unset: no network refresh; in a `__DEV__` build the screens show a labelled **demo** catalog (it never touches the verifier). |
| `EXPO_PUBLIC_STORE_URL` | `https://…` store listing for the force-update screen. |
| `EXPO_PUBLIC_API_BASE_URL` | The project's **Edge Functions root**, e.g. `https://<ref>.supabase.co/functions/v1` (`https://` only; local `http://` only in a dev build). The client appends `/<function-name>`. |
| `EXPO_PUBLIC_SUPABASE_URL` | The project URL (`https://<ref>.supabase.co`, an origin, no path). Auth is `<url>/auth/v1`. |
| `EXPO_PUBLIC_SUPABASE_ANON_KEY` | The **public** anon / `sb_publishable_…` key. A `service_role` JWT, an `sb_secret_…` key, or a JWT whose role cannot be read is refused at parse time. |

All three server values must be valid for a build to talk to a server; with any missing, a **release** build is `unconfigured` (no network API, no fake data) and a **dev** build is the labelled `demo`. Public values only; nothing secret belongs here. `src/catalog/keys.ts` ships an **empty** keyset until the production
keyset exists (§3.5), so a build today verifies nothing and **no catalog can be applied**: set a keyset locally to
try a signed catalog (a development build trusts whatever is compiled in; a release build additionally needs ≥ 2 keys,
see "What is gated"), and never commit a private key.

## What is gated

- **M-freeze:** `SUPPORTED_CONTRACT_MAJOR` is `0` (`src/config-values.ts`); the freeze moves it to `1`.
- **Production keyset (§3.5, P3 gate):** empty on purpose. At startup a **release** (`!__DEV__`) build runs
  `assertReleaseKeyset` (≥ 2 well-formed keys) through `resolveTrustAnchors` (`src/catalog/keys.ts`) and **never throws**:
  if the check fails — as it does today — the verifier is given **no keys at all**, network refresh is turned off, and
  Me → Catalog says why. Failing closed rather than crashing is deliberate: a throw at startup would crash-loop every launch
  of every build until the keyset exists. Development builds skip the check.
- **K3 / K4:** which Health lanes ship; nothing built here depends on them.
- **Counsel L7:** no HealthKit read before it signs; HealthKit is not installed.
- **§7.5 attestation decisions:** see SPIKE.md finding F4 (the Expo App Attest module hashes the challenge string, which
  does not match the server's raw-nonce binding, and has no DeviceCheck token).
- **Still stubbed or not built (after P4.2b-1):** the native attestation client (P4.2b-2; the app ships `UnattestableAttestor`); evidence submission and
  check-in challenges are built, but nothing in the UI creates evidence yet (`services.enqueueEvidence` is the entry point a check-in / import screen
  will call; the dev panel's `{ dev: true }` plays are refused locally as `unsendable` against a real server); no endpoint feeds `getPolicy` / plays / achievements / programmes, so the
  real client answers the compiled default and "nothing" with no request), share cards, the on-device matcher, file import, the user-pick
  flow (§4.3), the private-club trail note (O8), App Attest, Wallet activation, the offline TOTP. Effects worth
  knowing, in `src/runtime/services.ts`: `rematch` only checks the stored course still exists in the current catalog and, with no
  verified snapshot (every build until the keyset exists), returns `{ ok: false }` — so a 422 `catalog_stale` answer **dead-letters**
  the play; `findCourseForUnlisted` always returns `null`, so an "Unlisted course" play never becomes sendable; `resolveQueued`
  (`src/outbox/machine.ts`) has **no caller**, so a `queued` play never leaves `queued` on the device.
- **Pending owner keys / native modules (P4.2a leaves these as adapters):**
  - **Google sign-in:** the flow, nonce handling and "not configured" path exist; there is **no native Google SDK** (no Expo 57 package in the
    lock) and no OAuth client. The Google button is not shown until an adapter reports `available` (`signin/google.ts` says how). Server side,
    linking Google is still a 501 (server O2), so no Google grant is captured or revocable yet.
  - **Sign in with Apple on Android** needs a web flow and a Services ID (server O3): the Apple button is shown on Android only when Google is
    offered (AT 17) and then reports "not available on this device".
  - **Push notifications:** `expo-notifications` (a native module plus push credentials) is not installed; the registration call, device id and
    state machine are real and tested, the control is disabled. Follow-up: implement `PushAdapter` over it, pin it, allow-list its plugin.
  - **Supabase project values and Apple/Google provider configuration** (`EXPO_PUBLIC_*` above, the Apple Services/App ID, key and entitlement
    on the owner's Apple account): none exist in this repo, by design.
- **Supabase Auth auto-links same-email identities at sign-in `[unverified — training knowledge; server doc "the honest gap"]`.** The app never
  links by email match (its own `link` calls carry no proof unless the player typed one), but a native Apple/Google sign-in whose verified
  email matches an existing account can still be linked **inside GoTrue** before the app is involved. Closing that is a Supabase Auth setting /
  a pre-check the owner has to decide (server doc, `docs/security/p3-money-path-requirements.md` O12), not something the client can do.
- **Outbox rows and check-in challenges are per user** (P4.2b-0 / -1): sign-out leaves them dormant, deletion removes the deleted user's. The SQLite file is in the iOS
  backup set (`test/ios-backup.test.ts`), so a challenge nonce can sit in a backup: it is single-use, bound at the server to the user and device id, expires within 24 h,
  and rows for another device id are never selected.
- **iOS Keychain items survive an uninstall** `[from the Keychain's documented behaviour, not observed on a device]`, so a reinstalled app may
  find the previous session (and the age flag, which only strengthens the retry refusal). A first-launch marker that clears a stale session is a
  follow-up; deciding it is a product call.
- **Backups (iOS):** the under-age flag, the session and the device id are `…ThisDeviceOnly` Keychain items (`AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY`;
  option `keychainAccessible` and the constant read from the installed `.d.ts` and Swift source, `test/secure-storage.test.ts`), so they are not in
  an iCloud/iTunes backup or a device migration `[Keychain backup semantics: not observed on a device]`. `android.allowBackup` is `false`.
  **`golfraven.db` itself is still in `<Documents>/SQLite` on iOS and still in the backup set** (catalog cache + the evidence outbox, i.e. a
  player's own pending plays): `expo-sqlite` 57.0.3 takes a directory but nothing sets `NSURLIsExcludedFromBackupKey`, and neither it nor
  `expo-file-system` 57.0.7 has such an option (`test/ios-backup.test.ts` pins that). Moving the DB is not a fix (`Library/Caches` is purgeable,
  `Library/Application Support` is backed up). Closing it needs a small native module / config-plugin Swift that sets `isExcludedFromBackup` on the
  `Documents/SQLite` directory before the DB opens `[Apple behaviour: training knowledge, unverified]`; not built here.
- **`expo-secure-store`'s config plugin is deliberately not used:** the module autolinks without it, and the plugin would add an unused Face ID
  usage string and Android backup-rule attributes (backup is already off). `expo-apple-authentication`'s plugin is used (it sets the
  `com.apple.developer.applesignin` entitlement, confirmed in a generated `ios/` from `expo prebuild`) and is on the policy allow-list with that reason.
- **Open decisions flagged in code:** the year-only age boundary (`src/age/gate.ts`), whether a `401` should retry
  instead of dead-lettering (`src/outbox/machine.ts`), what happens to a cache signed by a key that is later revoked
  (it is dropped; `src/catalog/manager.ts`).

## Scripts

- `pnpm typecheck` — two programs: `tsconfig.json` (the app: no Node types, so a Node-only API in app code fails here)
  and `tsconfig.test.json` (adds the tests and `@types/node`).
- `pnpm test` — vitest: the catalog verifier against artifacts from the **real** `tools/catalog` emitter/signer (with
  `versions.json` signed by a separate key so no verifier check is masked by another), the cache manager on both the
  memory and `node:sqlite` stores (anti-rollback, races, force-update), the fetch limits, the outbox, i18n parity, the age
  gate, policy scans.
- `pnpm build` — no-op; there is no EAS build or `expo export` in CI yet.
- `pnpm export:ios` / `pnpm export:android` — `expo export` behind `scripts/check-public-env.mjs`, which refuses (exit 1, names the variable, never
  prints the value) a secret-shaped key (`service_role` JWT, `sb_secret_…`) or an unusable anon key in any `EXPO_PUBLIC_*` variable, in `process.env` or
  the `.env*` files, because Metro inlines those values into the bundle. The same guard is EAS Build's `eas-build-pre-install` hook. A bare
  `npx expo export` does not run it. The export scripts pass `--clear` (Metro's transform cache key ignores `EXPO_PUBLIC_*` values, so a value inlined
  into an earlier export on the same machine could otherwise ship again after the variable was unset) and then run `scripts/scan-bundle.mjs` over
  the output directory (`scripts/export-and-scan.mjs`, which forwards extra arguments such as `--output-dir` to `expo export` and scans the same
  directory): it fails on a JWT whose payload `role` is not `anon`, and on an `sb_secret_…` key, printing the file and the kind, never the value.
  The guard's exit codes: 1 a real finding, 2 the guard could not run (both block; the messages differ).
- Metro runs the public-env guard (`metro.config.js`, P4.2b-1): every bundling path (`expo start`, `expo export`, `expo run:*`, `eas update`, Gradle,
  Xcode) fails on a secret-shaped `EXPO_PUBLIC_*` value, naming the variable only. A guard that cannot run also blocks (fail closed), with its own message.
  The explicit scripts above remain.
- Recorded evidence-lane fixtures: `pnpm --filter @golfraven/rules exec vitest run --config ../../apps/mobile/scripts/record-edge-contract.vitest.config.ts`
  re-runs the REAL server handlers over the server's fakes and **fails if `test/fixtures/edge-contract.json` is stale**; with `RECORD_EDGE_CONTRACT=1` it
  rewrites the evidence-lane entries (keys `challenge_*`, `token_*`, `evidence_*`, `batch_*`, and `vectors`; the P4.2a entries are kept byte for byte). See the
  header of `scripts/record-edge-contract.rec.ts` for what is real and the one thing replaced (`privileged.ts`: it needs Postgres). CI runs the verify
  mode in the `verify` job.
- `CHECKIN_UI_ENABLED` (`src/features.ts`, `false` until P4.2b-2/3 add a check-in screen): while false the app does not prefetch check-in challenges at startup
  or after a sync (they would only expire unused and count against the hourly limit). P4.2b-2/3 flips it with the screen.
- Outbox ownership (P4.2b-0): every outbox item carries the `ownerUserId` of the Supabase session that created it (SQLite schema v2; rows from
  before it become `needs_attention` / `owner_unknown` and are never sent). Only that user's session sends or sees an item; sign-out leaves a
  user's items dormant, account deletion wipes all of them. Details: `src/outbox/runner.ts`, `src/outbox/enqueue.ts`, `src/db/sql.ts`.
- Release-bundle check for the mock (P4.2a): `expo export --platform android|ios --no-bytecode` in a scratch copy, then grep the bundle for
  `mock-user-`, `demo-authorization-code`, `mock-access-token`, `createMockApi`, `createMockAuth`, `MOCK_OTP_CODE`: all absent (recorded
  in the PR notes; `test/backend.test.ts` guards the source-level half in CI).
- Local checks that are not in CI: `pnpm exec expo export --platform android` (and `ios`) proves Metro can bundle the
  app (`--no-bytecode` and a grep show what a release bundle contains). CI **does** run
  `expo prebuild --no-install` before the tests, so the policy test scans the **generated** `AndroidManifest.xml` and
  `Info.plist` (AT 5, `allowBackup`); run the same locally before `pnpm test` to get those two tests instead of skips.
  Delete the generated `android/` and `ios/` afterwards (they are gitignored).
- This package needs `pnpm -r build` first: it imports the built `dist/` of `@golfraven/catalog` (types) and
  `@golfraven/catalog-tools`.

## Plan vs server: contract mismatches found in P4.2b-1 (the server wins)

| # | Plan | Server (handler, recorded) | What the app does |
|---|---|---|---|
| 1 | §7.6: `201` / `409 duplicate` = accepted | A new **and** a replayed play are `200 {status:"accepted", replay}`; a changed replay is `409 evidence_conflict` | `200 accepted` is accepted; `409 evidence_conflict` is a dead letter with the code kept. The plan's 201 / `409 duplicate` are still understood. |
| 2 | §7.6: `202 queued_catalog` is an answer with a code | `202 {data:{status:"queued_catalog"}}`; a replay of a row the 7-day drain gave up on is `200 {status:"needs_attention"}` | the body's `status` is the `code`; the second is `needs_attention / queue_expired` |
| 3 | §7.5: iOS binds `SHA-256(canonical_body ‖ challenge)` | iOS binds `SHA-256(UTF-8(S))`, S a canonical string with the nonce as text; only Android keeps body ‖ raw challenge | `src/attest/binding.ts` follows the server |
| 4 | §7.5: challenge TTL 5 min | live 120 s, prefetched 24 h (`challenge-handler.ts`) | read from each challenge's own `expiresAt` |
| 5 | §7.5: an assertion rides on the evidence | `evidence` has **no** attestation field; the grade comes from `checkin-token`, which reads only `{challengeId, nonce, hardwareSupportsAttestation}` and **ignores any attestation token** (it grades every call "no token", a marked STUB) | evidence carries only the `checkinTokenJti`; redemption sends `hardwareSupportsAttestation` |
| 6 | §7.6: a check-in at a no-signal course consumes a challenge and is "submitted on reconnect at full weight" | the challenge must be **redeemed** (`checkin-token`, online, before it expires) and the evidence sent within the token's 15 minutes; the fix's `capturedAt` must lie inside the challenge's window | consumed offline (`held`), redeemed at send time; a challenge that expires before reconnect is dropped and the item takes the x0.6 path |
| 7 | §4.7: 10 unused prefetched challenges per device | the server counts a locally consumed but unredeemed challenge as still open | a top-up right after an offline round may get `429` until the outbox has sent it; reported, retried on the next sync |
| 8 | §7.6: batch is "sorted by event time" | `evidence-batch` answers 200 with a result per item and **no per-item HTTP status** (`{ok, result | error:{code}}`) | status inferred from the error code (`BATCH_CODE_STATUS`); an unknown code is a dead letter |
| 9 | §7.6: "any other 4xx" dead-letters | the server's 429 carries `Retry-After` only in `details.retryAfterSeconds`; a `401` for a good play is a bearer problem | 429 reads the body; 401 is a refresh-once-then-`retry` (above) |

## What P4.2b-2 (native attestation) must plug in

1. An `Attestor` implementation per platform in `src/attest/` (App Attest via DeviceCheck / `@expo/app-integrity`, Play Integrity), chosen in `runtime/services.ts` where
   `new UnattestableAttestor()` is today. Its `capability.hardwareSupportsAttestation` must be `true` on capable hardware **only if it then attests every request**
   (a token-less request on capable hardware is graded `failed` and opens a fraud signal).
2. **iOS key registration** (`POST devices-attest-key`: not called from the app yet): `generateKey()` → build S with `attestKeyChallengeString` → `attestKey(keyId, attestKeyBinding(...))`.
   Needs a LIVE challenge (`requestCheckinChallenges` with no `prefetchCount`) and the key id kept in the secure store.
3. **Reward activation** (`rewards-activate`: not called from the app yet): iOS `assert(keyId, iosActivationBinding(...))` + a DeviceCheck token; Android `integrityToken(androidRequestBinding(...))` + `installLinkId`.
4. **Check-in evidence**: the server's `checkin-token` handler must first learn to read and verify attestation material (today it ignores it). That is server work with no binding defined
   yet: P4.2b-2 needs the server's definition of the check-in request binding, then a `src/attest` builder for it and a field in the redemption call
   (`CheckinTokenRequest`, `evidence/send.ts` `redeem`). Until then nothing but `hardwareSupportsAttestation` can be sent.
5. A native dependency means a new prebuild: re-run the policy scans (permissions, manifest, no ads/analytics SDK) and the release-bundle grep.

## Not device-tested

**Nothing in `src/health-connect/reader.ts` has run on a real Android
device or emulator with Health Connect installed.** This container has no
Android device, no emulator, and no way to grant a runtime health
permission — so the reader's actual behavior against real Health Connect
data is `[unverified — training knowledge and the library's shipped
`.d.ts` only]`. What *is* verified in this repo: the reader typechecks
against `react-native-health-connect@4.1.3`'s real type definitions (pinned
in `package.json`; inspected directly from the published package, not
recalled from training), and the pure shaping logic (`shape.ts`) is
unit-tested with fabricated record objects.

**Matt runs the real X1 Android pass** (build plan §10 P0, row X1: "2
elapsed days... then an Android pass"). Exact steps:

1. **Get a dev build onto an Android phone with Health Connect installed**
   (Health Connect ships built into Android 14+; on older Android it's a
   separate Play Store app). Two ways to get this app running:
   - `npx expo run:android` from `apps/mobile/`, with an Android device
     connected via USB (developer mode + USB debugging on) or an emulator
     running, and the Android SDK installed locally; or
   - an EAS development build: `eas build --profile development --platform android`
     (needs an Expo account and `eas.json`, neither of which exist in this
     skeleton yet — `eas build:configure` sets that up), then install the
     resulting APK on the phone.
2. **Record at least one real golf round** with Garmin Connect Mobile (or
   another Health-Connect-writing golf app) so Health Connect actually has
   an `ExerciseSession` of type golf to read (build plan §10 P0, row X1:
   "one real round from 3 sources... on iOS, then an equivalent Android
   pass").
3. Open the app **in a development build**, go to **Me → Developer tools → "P0 check X1 (Health Connect)"** (Android only; the
   panel exists only in `__DEV__` builds: it, the X1 screen and the demo catalog are `require`d lazily under `__DEV__`, and
   an `expo export` of both platforms was grepped to confirm none of their strings is in the release bundle; the route
   `golfraven://dev/x1` is still deep-linkable in a release build but redirects to the home tab), and tap **"Run X1 Health Connect check"**. The button:
   - checks Health Connect's SDK status and initializes it — a
     `HealthConnectUnavailableError` here means Health Connect itself
     isn't usable on that device (not installed, or the provider needs an
     update);
   - triggers the Android system permission dialog for reading
     `ExerciseSession` data — accept it;
   - reads the last 30 days of `ExerciseSession` records, filters to golf,
     and shows the resulting JSON.
4. **Copy that JSON into the X1 memo** (`docs/p0/X1.md` — owned by
   whichever agent/session writes the P0 memos, not this skeleton). It has
   exactly what X1 needs per source: start/end, `dataOrigin` (the
   recording app's package name — this is what feeds the §7.3 lane-5
   source allow-list), and whether a route came back with points.
5. **Route data is the one real unknown.** The reader records
   `routePresent` (a route came back with points), `routePointCount`,
   and `routeRequiresConsent` (Health Connect reported
   `CONSENT_REQUIRED` — meaning the route exists but needs its own
   additional consent step this reader does not chase automatically,
   `[unverified — training knowledge on the Android permission model]`).
   Whichever shows up in a real run is itself part of X1's answer.

**Do not treat anything above as confirmed until that run happens.** If it
turns out Health Connect's actual runtime behavior differs from what the
library's types imply, that is exactly the kind of finding X1 exists to
surface — update `shape.ts`/`reader.ts` and this README once it's known.

## Everything else

Sync lanes 2-5, course-matching integration, evidence submission, the attestation client, check-in challenges and Wallet activation
are P4.2b / later P4 work; see "What is gated" above.
