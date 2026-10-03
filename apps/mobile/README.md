# @golfraven/mobile

GolfRaven's mobile app (Expo SDK 57 / React Native 0.86, build plan §3.1 row G, §7).

**Status: P4.1 first slice + P4.2a** — the app shell, the signed catalog cache, the outbox model, EN/FR-CA scaffolding and the
16+ age screen (P4.1), and, from P4.2a, a **real `ApiClient`** for the Edge Functions that exist (sign-in methods, delete,
export, push token), secure token storage, Sign in with Apple / email OTP sign-in, account linking, deletion and export. The
mock of `api.*` survives for tests and the `__DEV__` demo only. It started before M-freeze, the K3/K4 verdicts and the
production catalog keyset, on the owner's instruction; read **"What is gated"** below before relying on any of it.
**P4.2b-1 adds** real evidence submission (single and batch), prefetched check-in challenges and the attestation *seam* (below). **P4.2b-2 adds** the native attestor: a LOCAL Expo module (`modules/golfraven-attest`) over iOS App Attest + DeviceCheck and Android Play Integrity, and its wiring into check-in redemption (below). **P4.2b-3b adds** the offline TOTP code client (`src/offline-code/`: provisioning, the secure-store seed, the code) and reward activation (`src/attest/activator.ts`, `src/rewards/`), both behind NEW build-time switches that are `false` (`OFFLINE_CODE_UI_ENABLED`, `WALLET_ACTIVATION_UI_ENABLED`, below). **Still later:** the check-in screen, the staff side that accepts the offline code (P5), a Wallet that lists earned rewards (no server endpoint does yet). **`CHECKIN_UI_ENABLED`, `OFFLINE_CODE_UI_ENABLED` and `WALLET_ACTIVATION_UI_ENABLED` are all `false`, so none of the attestation, offline-code or activation code is reachable in a release build** (it is exercised by tests and by anything that calls the services directly).
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
modules/
  golfraven-attest/     P4.2b-2: the LOCAL Expo module (Swift: App Attest + DeviceCheck; Kotlin: Play Integrity standard requests). Autolinked from `modules/`
                        (`expo-module.config.json`); `app.plugin.js` sets the App Attest entitlement. Declarative: all logic is in `src/attest`.
src/
  attest/               the `Attestor` seam, the bindings, `NativeAttestor`, the per-key lock, the iOS key store, the check-in redeemer, the reward activator (below)
  offline-code/         P4.2b-3b: the offline staff code: TOTP, seed store (secure store only), provisioning manager, the launch gate (below)
  rewards/              P4.2b-3b: reward activation: the service, the outcome mapping, the copy (below)
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
| **Native attestation (P4.2b-2)** | See **"Native attestation (P4.2b-2)"** below. Unit-tested against a fake native module and the server's recorded answers; **no Swift or Kotlin line has been compiled or run** `[unverified]`. |
| **Attestation seam (P4.2b-1)** | `src/attest/`: the `Attestor` interface (`generateKey`/`attestKey`/`assert` for iOS, `integrityToken` for Android), typed results (`ok` / `unattestable` / `failed`, never thrown), the **server's** request bindings byte for byte (`binding.ts`, cross-checked with vectors the server's own functions produced), and `UnattestableAttestor`, the only implementation P4.2b-1 shipped (since P4.2b-2 the fallback for every build or device that cannot attest): every operation answers `unattestable`, `hardwareSupportsAttestation: false`, so a redemption is graded `unattestable` (G3-08), never `failed`. **No native dependency was added in P4.2b-1.** |
| **Offline code (P4.2b-3b)** | See **"Offline code (P4.2b-3b)"** below. `src/offline-code/`, `test/offline-code-*.test.ts`. Behind `OFFLINE_CODE_UI_ENABLED` (**false**). |
| **Reward activation (P4.2b-3b)** | See **"Reward activation (P4.2b-3b)"** below. `src/attest/activator.ts`, `src/rewards/`, `test/attest-activator.test.ts`, `test/rewards-activation.test.ts`. The Wallet card is behind `WALLET_ACTIVATION_UI_ENABLED` (**false**). |
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
| `EXPO_PUBLIC_PLAY_CLOUD_PROJECT_NUMBER` | (P4.2b-2) The Google Cloud project **number** Play Integrity standard requests are made for: 1–18 digits. **Public, not a secret** (it names a project and authorises nothing; the server decodes verdicts with its own Google credentials), so the env guard has nothing to flag. Unset: an Android build cannot attest (`UnattestableAttestor`, reason `not_configured`). It must be the same project the server's Play Integrity configuration uses. |
| `GOLFRAVEN_APP_ATTEST_ENV` | (P4.2b-2, **build time only**, not `EXPO_PUBLIC_*`, never in the bundle) `development` or `production`: the value of the iOS App Attest entitlement written by `modules/golfraven-attest/app.plugin.js` at `expo prebuild`. Unset: `production` (App Store / TestFlight). A development build that must attest sets `development`; any other value fails the prebuild. A key attested in one environment does not verify as the other at the server, so build and deployment must match. |

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
- **Still stubbed or not built (after P4.2b-3b):** the check-in screen (the native attestation client exists, P4.2b-2, and so do the offline code and reward activation clients, P4.2b-3b, but nothing can reach any of them in a release build); evidence submission and
  check-in challenges are built, but nothing in the UI creates evidence yet (`services.enqueueEvidence` is the entry point a check-in / import screen
  will call; the dev panel's `{ dev: true }` plays are refused locally as `unsendable` against a real server); no endpoint feeds `getPolicy` / plays / achievements / programmes, so the
  real client answers the compiled default and "nothing" with no request), share cards, the on-device matcher, file import, the user-pick
  flow (§4.3), the private-club trail note (O8). Effects worth
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
  into an earlier export on the same machine could otherwise ship again after the variable was unset; since P4.2b-2 `metro.config.js` also folds the values into
  Metro's `cacheVersion`, below) and then run `scripts/scan-bundle.mjs` over
  the output directory (`scripts/export-and-scan.mjs`, which forwards extra arguments such as `--output-dir` to `expo export` and scans the same
  directory; it has no `-o` branch, `expo export` has no such flag, and it prints `spawnSync`'s error and exits 2 when `expo` cannot be started): it fails on a JWT whose payload `role` is not `anon`, and on **any** occurrence of `sb_secret_`
  (no length threshold: the app's own parser builds the prefix from parts, `SB_SECRET_PREFIX` in `src/config-values.ts`, so a clean export has none; verified on real iOS and Android
  exports, with Hermes bytecode and with `--no-bytecode`), printing the file and the kind, never the value.
  The guard's exit codes: 1 a real finding, 2 the guard could not run (both block; the messages differ).
- Metro runs the public-env guard (`metro.config.js`, P4.2b-1): every bundling path (`expo start`, `expo export`, `expo run:*`, `eas update`, Gradle,
  Xcode) fails on a secret-shaped `EXPO_PUBLIC_*` value, naming the variable only. A guard that cannot run also blocks (fail closed), with its own message;
  a guard script that is MISSING is checked before it is spawned and reported as "could not run ... a broken checkout, not a finding" (not as a finding, and not as Node's own
  "Cannot find module"). The explicit scripts above remain.
- **Metro `cacheVersion` (P4.2b-2, carried from the #39 gate).** Metro inlines the raw value of every `EXPO_PUBLIC_*` variable into the transformed module but its transform cache key
  ignores the values, so on any path without `--clear` (`expo start`, Gradle, Xcode, `eas update`) a value inlined into a cached transform could ship again after it changed or was
  unset. `metro.config.js` sets `config.cacheVersion` to a SHA-256 over Metro's own version and the sorted `EXPO_PUBLIC_*` name/value pairs (JSON-encoded, one-way, never printed).
  **Verified by experiment** (private `TMPDIR`, no `--clear`, `expo export --platform android --no-bytecode`, using `EXPO_PUBLIC_STORE_URL`, which the app inlines): with the change, `=…/alpha`
  then `=…/beta` gave a second bundle containing `beta` and no `alpha`; the control (the `cacheVersion` line removed, same two runs, fresh private cache) shipped `alpha` again and no `beta`.
  `test/metro-cache-version.test.ts` pins the property (value change, add/remove, order independence, non-public variables ignored, no separator collision).
- Recorded evidence-lane fixtures: `pnpm --filter @golfraven/rules exec vitest run --config ../../apps/mobile/scripts/record-edge-contract.vitest.config.ts`
  re-runs the REAL server handlers over the server's fakes and **fails if `test/fixtures/edge-contract.json` is stale**; with `RECORD_EDGE_CONTRACT=1` it
  rewrites the evidence-lane entries (keys `challenge_*`, `token_*`, `evidence_*`, `batch_*`, `attestkey_*`, `offlineseed_*`, `activate_*`, and `vectors`; the P4.2a entries are kept byte for byte). See the
  header of `scripts/record-edge-contract.rec.ts` for what is real and the one thing replaced (`privileged.ts`: it needs Postgres). CI runs the verify
  mode in the `verify` job.
- `CHECKIN_UI_ENABLED` (`src/features.ts`, **still `false`**: P4.2b-2 added the native attestor but no check-in screen): while false the app does not prefetch check-in challenges at startup
  or after a sync (they would only expire unused and count against the hourly limit). The change that adds the check-in screen flips it. Until then nothing in a release build creates evidence,
  so nothing calls the attestor (`test/attest-setup.test.ts` pins the switch).
- `OFFLINE_CODE_UI_ENABLED` and `WALLET_ACTIVATION_UI_ENABLED` (`src/features.ts`, **both `false`**, P4.2b-3b): the first gates the Me → "Offline code" card AND the automatic seed provisioning (`offline-code/gate.ts`: a seed revealed into the keychain for no screen would only spend the server's 20-an-hour reveal limit; the staff side that accepts the code is P5); the second gates the Wallet's "Earned rewards" card with its Activate action (no endpoint lists earned rewards yet, so there is nothing to activate in a build, and the Wallet tab is a placeholder). `test/rewards-activation.test.ts` ("FLAGS OFF") pins the values, every place each is read, and that nothing else imports the two cards or starts a provisioning / an activation.
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
| 5 | §7.5: an assertion rides on the evidence | `evidence` has **no** attestation field; the grade comes from `checkin-token`. **Superseded by server PR #40:** `checkin-token` now verifies an `attestation` block over the check-in binding (it ignored it when P4.2b-1 was written) | evidence carries only the `checkinTokenJti`; redemption carries the attestation block (P4.2b-2, below) |
| 6 | §7.6: a check-in at a no-signal course consumes a challenge and is "submitted on reconnect at full weight" | the challenge must be **redeemed** (`checkin-token`, online, before it expires) and the evidence sent within the token's 15 minutes; the fix's `capturedAt` must lie inside the challenge's window | consumed offline (`held`), redeemed at send time; a challenge that expires before reconnect is dropped and the item takes the x0.6 path |
| 7 | §4.7: 10 unused prefetched challenges per device | the server counts a locally consumed but unredeemed challenge as still open | a top-up right after an offline round may get `429` until the outbox has sent it; reported, retried on the next sync |
| 8 | §7.6: batch is "sorted by event time" | `evidence-batch` answers 200 with a result per item and **no per-item HTTP status** (`{ok, result | error:{code}}`) | status inferred from the error code (`BATCH_CODE_STATUS`); an unknown code is a dead letter |
| 9 | §7.6: "any other 4xx" dead-letters | the server's 429 carries `Retry-After` only in `details.retryAfterSeconds`; a `401` for a good play is a bearer problem | 429 reads the body; 401 is a refresh-once-then-`retry` (above) |

### Plan vs server, found in P4.2b-2 (the server wins)

These are not contradictions of a written plan: they are assumptions the code could have made and the server's handlers (`token-handler.ts`, `attest-key-handler.ts`) rule out.

| # | Assumption | Server (handler, recorded) | What the app does |
|---|---|---|---|
| 10 | The module hashes the challenge string `S` (SPIKE F4: the Expo App Integrity module hashes a string) | The server verifies `clientDataHash = SHA-256(UTF-8(S))`; it cannot know who hashed | Our own module takes the 32 hash bytes (base64) and hashes nothing; JS computes `SHA-256(UTF-8(S))` and it is checked against the server's output |
| 11 | When the attestation cannot be produced, send the request without it | A token-less request from a device that has a registered key / an `attested` token is `failed` + fraud signal, whatever it claims (`deviceHasShownAttestation`) | Never token-less after that point; counted, bounded deferral, then the challenge is dropped (rule 2 below) |
| 12 | A presented attestation that does not verify can be retried on the same challenge | A PRESENTED attestation that does not verify is graded `failed` and the challenge is consumed (no free second guess); only a vendor 503 leaves it unconsumed | A 503 retries the same challenge; a `failed` grade is final for that challenge |
| 13 | Key registration can use the prefetched check-in challenge in hand | `devices-attest-key` accepts a LIVE challenge only (`consumeLiveChallenge`), 120 s, and the registration binding names the device | Registration requests its own live challenge (counts against the 30/h challenge and 10/h registration limits) |

### Plan vs server, found in P4.2b-3b (the server wins)

| # | Assumption (the task / the plan) | Server (handler, recorded) | What the app does |
|---|---|---|---|
| 14 | A repeat activation is a "409 already activated" | The idempotent answer is **200 `replay: true`** (already held, or already active on THIS device). A 409 is `reward_not_activatable` (redeemed, void, ...) or `reward_expired` | `replay: true` is a success ("Already activated" / still under review); 409s are `not_activatable` / `expired` (`rewards/outcome.ts`) |
| 15 | The answer says whether the device attested | `ActivationResult` is `{ id, kind, state, held, replay }`: **no grade**. A `held_review` may come from the bits, the account, the grade or the budget | `held_review` is shown as "under review", never as a device failure; `markAttestedActivation` is called on every NON-REPLAY answer to a request that carried a token (an `issued` / `redeemable` answer is attested by construction: the table activates only an attested grade; a hold may or may not be), which only ever makes the client more cautious |
| 16 | The reward kind is `special_marker` | The activation answer's `kind` is `"offer_code"` or **`"entitlement"`** (the table's own column says `special_marker`) | `RewardKind = "offer_code" \| "entitlement"` |
| 17 | The activation challenge can be a prefetched one | `consumeLiveChallenge`: a LIVE challenge (120 s), single use, issued to the device; `kind: "none"` needs none | A live challenge is requested inside the lock, after the key is known; a `kind: "none"` request asks for none |
| 18 | Android needs only a token | `installLinkId` is bound into the hash when sent, and **without it the server has no signal for the persistent bits and holds the reward** (the "no persistent signal" row) | The native module gained `installLinkId()` (the SSAID, `Settings.Secure.ANDROID_ID`, no permission); sent and bound whenever the device can give one |
| 19 | A held reward can be re-activated | `handleActivation` step 2: "a held reward waits for a human; activation never releases it" | A transient local failure on a device that CAN attest is a **deferral**, never a token-less request: a `none` request would turn a retry into a review-queue entry |
| 20 | `me-offline-seed`: register the device, then provision | The endpoint never creates a device: a foreign and an unknown device are the same 404 | `404` is `not_ready` (no loop; the automatic path waits 5 minutes between attempts). **With push unavailable (no `expo-notifications`) and `CHECKIN_UI_ENABLED` false, nothing in this build registers a device**, so the provisioning would answer 404 until the check-in screen exists |
| 21 | The server doc: "rotate on sign-out" | Sign-out has no session and may have no network | Sign-out keeps the seed (per user, dormant, like the outbox); the player rotates explicitly ("Reset code"); deletion wipes it |

## Before flipping the flags

`CHECKIN_UI_ENABLED`, `OFFLINE_CODE_UI_ENABLED` and `WALLET_ACTIVATION_UI_ENABLED` are all `false`. Do not flip one in a release build until its items are done. None of these can be checked from this repository; each is a store, deployment or product fact.

**Any flag that reaches attestation (check-in, Wallet activation)**

- [ ] **Play Console, Data safety form:** declare **"Device or other IDs": collected, purpose "Fraud prevention, security, and compliance"**. The Android install link is the `ANDROID_ID` (`Settings.Secure.ANDROID_ID`, read by `installLinkId()` in `modules/golfraven-attest`), sent as `installLinkId` on every Android activation; the server stores only its SHA-256.
- [ ] **App Store Connect, App Privacy (the privacy "nutrition label"):** update it to match what the build collects once attestation is reachable (the device identifiers the iOS side sends for fraud prevention: the DeviceCheck token and the App Attest key id; the Android `ANDROID_ID` above). Decide the exact data types with the privacy owner; the repository cannot say what the store will accept, and `docs/security/p3-money-path-requirements.md` is the reference for what the server stores.
- [ ] **Device registration is available** (item below): the server must be able to find this device, or the offline code never becomes ready.

**`OFFLINE_CODE_UI_ENABLED` (Me → Offline code, and the automatic seed provisioning)**

- [ ] **Device registration:** `me-offline-seed` answers 404 until the device row exists. With the flag on, the app registers it through `POST checkin-challenge` (see "Device registration" in the Offline code table). That needs `checkin-challenge` deployed and its 30-an-hour live-challenge limit not exhausted; if the server later gains a purpose-built registration endpoint, switch `deviceRegistrationFor` to it. Check on a real account that the first "Set up" yields a code, not "not ready".
- [ ] **The Vault secret `offline_seed_key` is provisioned** (migration 0045 DEPLOY note: `select vault.create_secret('<random, >= 32 bytes>', 'offline_seed_key')`), or `me-offline-seed` answers 503 `offline_seed_unavailable` and every attempt ends in "unavailable".
- [ ] **The P5 staff side is live:** the endpoint that VERIFIES the handle plus the code does not exist yet; until it does the card shows a code nobody can accept and each reveal spends the 20-an-hour limit.

**`WALLET_ACTIVATION_UI_ENABLED` (Wallet → Earned rewards → Activate)**

- [ ] **An earned-rewards listing endpoint exists.** No server endpoint lists a player's earned rewards: `listEarnedRewards` answers `[]` without a request, so the card has nothing to show and nothing to activate. Wire it in `src/api/http-client.ts` in the change that flips the flag. The Wallet tab itself is still a placeholder.

## Offline code (P4.2b-3b)

Build plan §7.6 "Offline staff path" (G-P1-07): a 6-digit TOTP (RFC 6238, **10-minute step**, **HMAC-SHA-256**, 6 digits) computed on the device from a 32-byte per-(account, device) seed the server provisions while the device is online. Staff enter the player's **handle** plus the code; the server accepts the step before and the step after its own. The server side is `me-offline-seed` + `_shared/offline-code/` (migration 0045); the staff verification endpoint is P5.

| Piece | Where | Notes |
|---|---|---|
| TOTP | `offline-code/totp.ts` | `counter = floor(t/600)` as **8 big-endian bytes**; `h = HMAC-SHA256(seed, counter)` with `@noble/hashes` (already a dependency; `hmac.js` + `sha2.js`); `offset = h[31] & 0x0f`; `bin = 31-bit big-endian word at offset`; `code = bin mod 10^6`, **zero-padded** (leading zeros kept). No BigInt (the counter is written as two 32-bit halves). `test/offline-code-totp.test.ts` imports the server's own `totp.ts` and compares on 400 random seeds and times, recomputes the RFC 6238 Appendix B SHA-256 vectors (30 s / 8 digits as published, and at the 600 s step against an independent `node:crypto` HMAC), and compares with the codes the server computed for the recorded seed (`vectors.offlineCode`). |
| Provisioning | `offline-code/manager.ts`, `api.provisionOfflineSeed` -> `POST me-offline-seed {deviceId, rotate?}` | Strict body. The answer is validated with the pinned `stepSeconds` 600 / `digits` 6 / `algorithm` "SHA256" as **literals** (another value is `bad_response`: the client never shows a code the server would not accept) and a 52-character base32 seed. Never retried by the HTTP client (every call is a seed reveal; 20 an hour, 5 rotations an hour). **Single-flight per USER, whatever the mode** (P4.2b-3c: a reset tapped while the automatic reveal is in flight WAITS for it and then runs, so the two answers can never land out of order; two taps, or a reveal while anything runs, share one request), and the store **never replaces a record with a higher `seedVersion` by a lower one** (a late answer is `failed` / `stale_seed`). Outcomes: `ready`, `not_ready` (404), `rate_limited` (429, Retry-After), `unavailable` (503 `offline_seed_unavailable`, 502/504/5xx), `offline`, `sign_in_required` (401), `signed_out`, and `failed` with a reason. |
| Storage | `offline-code/store.ts` | The seed **bytes** (hex) plus `seedVersion`, `issuedAt`, the receipt time, in **expo-secure-store only** (`AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY`, so not in an iCloud backup and not migrated), one item per (user, device): `gr.offline_seed.<userId>.<deviceId>`. Never SQLite (it is in the backup set), never a log, an error message, an outcome or a screen other than the six digits. The record names its user and device again, so a copy under another user's key is refused. A record that cannot be read back is "no seed" (re-provisioning returns the SAME seed); a store that cannot be read is "unavailable". |
| Per user | key + `OfflineCodeManager` | Every request is made as ONE owner with that owner's token (`session.accessTokenFor(owner)`), the token's `sub` must be that owner, and the answer is stored under that owner. Another user on the same device never sees the seed. |
| Sign-out / deletion | `AppProvider.tsx`, `account/delete.ts` | **Sign-out keeps the seed, dormant, per user** (the same policy as the outbox and the attestation state: the same player gets the same code back at the next sign-in, offline). **Account deletion wipes the deleted user's seed** (step `offline-seed`; another user's stays). |
| Rotation | "Reset code" -> `provision({rotate: true})` | The new seed and version replace the old; the old code stops working at once (server-side). A refused rotation (429, any 4xx) leaves the earlier record current; a rotation whose answer was lost is remembered **before** it is sent (`resyncNeeded`) and the next automatic provisioning fetches the server's current seed. |
| Clock | `offline-code/params.ts` | `issuedAt - device clock at receipt` is the offset estimate, **display only**: the code is always computed from the device clock. The screen warns from one step (600 s): below it the server's +-1 step window always accepts the code; at or above it, it may not. |
| Launch | `offline-code/gate.ts` | Provisioning on its own (no seed yet, or a rotation unconfirmed) only through `provisionOfflineSeedOnLaunch`, whose default is `OFFLINE_CODE_UI_ENABLED` (**false**: no request, no token fetch, no keychain read). After an attempt that could not finish (404, 503, offline, 429) the automatic path waits 5 minutes (or the server's longer `Retry-After`): one attempt per launch is not a loop. |
| Device registration | `offline-code/gate.ts` `deviceRegistrationFor`, `manager.ts` `registerDeviceOnce` | `me-offline-seed` never creates a device, and nothing else in the app registers one yet (challenge prefetch is gated off by `CHECKIN_UI_ENABLED`; push is not installed). So **while `OFFLINE_CODE_UI_ENABLED` is true** a 404 from the seed endpoint registers this device with `POST checkin-challenge { deviceId }` (the handler's `device.ensureOwn(deviceId, null)`; platform left unknown, set by the first platform-bearing use; it issues ONE live challenge that expires unused after 120 s) and asks again once. At most once per 5 minutes per user (it spends one of the account's 30 live challenges an hour, shared with live check-in). Not usable: `me-push-token` (the server refuses an empty `expoToken`, 400), `devices-attest-key` and `rewards-activate` (they need an attestation). While the flag is `false` no registration path exists and a 404 stays `not_ready`. Server-side limit that can still block it: 20 devices per account (`device_limit_exceeded`, 422). |
| UI | `screens/OfflineCodeCard.tsx` (Me tab, behind the switch) | Handle (when the app has one: none yet, the prop is optional), the code as `123 456`, a `m:ss` countdown, "Reset code" (confirmed), the clock warning, a note for each outcome; en and fr-CA. **The seed never reaches the component** (P4.2b-3c): the manager reads it from the secure store, computes the digits and drops it (`OfflineCodeManager.view()`); the card's state is only the derived digits, version and the end of their step (`offline-code/display.ts`, pure and tested), the countdown comes from the clock, and the digits are dropped when the Me tab loses focus or the app leaves the foreground (`AppState`). |

`[unverified]`: nothing here has run on a device, and the server side is `[unverified]` on a real Supabase project (its own doc). The Hermes behaviour of `Uint8Array` / `DataView` here is the same as the rest of the app's crypto.

## Reward activation (P4.2b-3b)

Build plan §7.5: a reward is **earned on the server and activated on a device** (`POST rewards-activate/{id}`); the decision table runs on that device's bits. `src/attest/activator.ts` builds the request; `src/rewards/` maps what comes back; `test/rewards-activation.test.ts` maps EVERY answer the real handler gave (the `activate_*` entries of the fixture).

- **Request** (strict, `request-shape.ts`): `{ deviceId, platform, challengeId?, nonce?, installLinkId?, attestation }`, the reward id **in the path only**. `attestation` is `ios { keyId, assertion, deviceCheckToken }`, `android { integrityToken }` or `none { hardwareSupportsAttestation: false, deviceCheckToken? }`.
- **iOS**: the key lifecycle is the check-in redeemer's (`NativeRedeemer.obtainIosAssertion`, shared: one implementation of the registration, the backoff, the `invalid_key` retry and the lock-abort rules); then the DeviceCheck token, the activation's OWN live challenge, and an App Attest assertion over `iosActivationBinding` (the token's SHA-256 is bound, so the token cannot be swapped).
- **Android**: the install link id (native `installLinkId()`: the SSAID), a live challenge, a Play Integrity token over `androidRequestBinding` (the link bound), `kind: "android"`.
- **ONE ASSERTION IN FLIGHT PER KEY, across both endpoints** (PR #40 gate LOW-1, mandatory): every activation runs inside `withAssertionLock` (the lock check-in redemption takes; `assertionLockKey`), on both platforms, **and so does every Android check-in redemption** (P4.2b-3c, PR #44 gate LOW-1: Android has no counter, but an activation's `attested` verdict and a check-in's "read the attested-before mark, then send token-less" raced; a token-less request graded `failed` + fraud signal is now impossible while a token-bearing one is in flight). `test/attest-activator.test.ts` proves a concurrent check-in redemption and activation are strictly sequential, in both directions.
- **Honest capability**: `activationWireRequest` is the single constructor; `none` always claims `false` (a claim of "I can attest" with no token is graded `failed` plus a fraud signal). A device that CAN attest never sends a token-less request because of a LOCAL failure (that is a deferral: a held reward waits for a human, and activation never releases it); `none` is sent only when the platform says it cannot attest at all, and on Android only if no token was ever graded `attested` on the device.
- **Android "attested before"**: `createAttestation().markAttestedActivation` after every non-replay answer to a request that carried a token, and after an outcome that is unknown once the token was sent (finding 15 above).
- **Outcomes** (`rewards/outcome.ts`, with the table in its header): `activated` (`alreadyActive` for the idempotent `replay`), `held_review` ("under review", not an error), `not_activatable`, `expired`, `conflict`, `not_found`, `not_allowed`, `platform_mismatch`, `device_limit`, `challenge_expired`, `rate_limited` (with a `source` of `challenge` or `registration` when the 429 came from `checkin-challenge` / `devices-attest-key` rather than the activation's own limit: each has its own line), `vendor_unavailable` (503 `attestation_unavailable`: nothing changed), `not_available` (503 `attestation_not_configured`, 501), `sign_in_required`, `signed_out`, `rejected`, `unknown_outcome` (a retry is safe at the server; a network failure BEFORE the activation request went out, on its own live challenge or a key registration, is `offline` instead), `deferred`, `offline`, `not_configured`, `unsupported_platform`, `unexpected_state`, `failed`. Every one has en and fr-CA copy.
- **Wallet**: `screens/EarnedRewards.tsx` lists earned-not-activated rewards (`api.listEarnedRewards`, which answers `[]` with no request: no endpoint) with an Activate button; rendered only while `WALLET_ACTIVATION_UI_ENABLED` (**false**).
- **Native**: `modules/golfraven-attest` gained `installLinkId` (Kotlin: `Settings.Secure.ANDROID_ID`, no permission; Swift: `unsupported`). `[unverified]`: not compiled, like the rest of the module.

## Native attestation (P4.2b-2)

What was built, how it behaves, and what has NOT been seen on a device.

**Layout.** `modules/golfraven-attest/` is a LOCAL Expo module (Expo Modules API; `expo-modules-core` stays a transitive dependency of `expo`, the JS reaches it through `expo`'s own
`requireOptionalNativeModule`, in one file: `src/attest/native-module-loader.ts`). **No third-party npm attestation package was added** (`test/native-module.test.ts` pins that, and that the
only new external dependency is the Gradle artifact below). It is discovered from `modules/` by Expo autolinking (`expo-module.config.json`; `expo-modules-autolinking resolve` lists both the
pod `GolfravenAttest` and the Android project). The Swift and Kotlin are minimal and declarative: each function calls ONE platform API and answers `{ ok:true, ... }` or `{ ok:false, code, message }`; they
hash nothing, keep no state and retry nothing. Contract: `src/attest/native-module.ts`.

| Platform | Platform API | Notes |
|---|---|---|
| iOS | `DCAppAttestService`: `isSupported`, `generateKey`, `attestKey`, `generateAssertion`; `DCDevice.current.generateToken` (DeviceCheck, for reward activation later) | The App Attest entitlement is written at `expo prebuild` by the module's config plugin from `GOLFRAVEN_APP_ATTEST_ENV` (default `production`). `DCError.invalidKey` is reported as `invalid_key`. |
| Android | Play Integrity **standard** requests: `StandardIntegrityManager.prepareIntegrityToken(cloudProjectNumber)` (cached, dropped after a failed request), then `request(requestHash)` | `com.google.android.play:integrity` **1.6.0**, pinned exactly. It is the `release` in Google's Maven metadata (`https://dl.google.com/dl/android/maven2/com/google/android/play/integrity/maven-metadata.xml`, read 2026-10-03: `latest` = `release` = 1.6.0, `lastUpdated` 20251120173431; the `.aar` answered a HEAD with 200). The Cloud project number is `EXPO_PUBLIC_PLAY_CLOUD_PROJECT_NUMBER`. No Android permission was added. |

**The hash is computed in JS, not in the module.** The task's wording ("pass `S` as the challenge string; the module hashes it") describes the Expo App Integrity module (SPIKE F4). Our own module takes
`clientDataHash` as base64 of the 32 bytes and hands it to `DCAppAttestService` unchanged, so `clientDataHash = SHA-256(UTF-8(S))` is computed by `@noble/hashes` in `src/attest/binding.ts`
and checked against the server's own output (below). Android: `requestHash` = base64url (no padding) of SHA-256(`canonical_body` ‖ raw nonce bytes), passed as the string Play Integrity takes.

**The check-in binding** (`src/attest/binding.ts`; server: `rewards/binding.ts`, `rewards/string-binding.ts`): purpose `golfraven/checkin-token/v1`, the challenge id, the device the CHALLENGE was issued to (the
payload's `deviceId`), the account (the access token's `sub`, bound as written; a token for another account, or one whose `sub` cannot be read, is never attested) and the raw nonce (a non-canonical
spelling is refused, as on the server). iOS: `S` = `{"challengeId","deviceId","nonce","platform":"ios","purpose","userId"}` canonical JSON. Recorded vectors (challenge `cccccccc-…`, device `bbbbbbbb-…`, user `uuuuuuuu-…`,
nonce `AQIDBAUG…HyA`): iOS `clientDataHash` `3c695d6c…77e5`, Android `requestHash` `8CGJ1X3iXQCcqYH4U7fjJrnceadzDEz5avKmy_idkl0`; the server's own functions, run by the recorder, produce exactly these
(`vectors.binding.checkin`), and the requests the recorder built for the real challenges (accepted by the real handler) carry the bytes this client computes (`test/attest-checkin.test.ts`).

**What a redemption carries** (`src/attest/redeemer.ts`; `evidence/send.ts` and `ChallengeManager.tryLive` both go through it):

1. **Honest capability.** `hardwareSupportsAttestation` is true if and only if the request carries an `attestation` block (`wireRequest` is the only constructor of the wire body). A claim of "I can attest" without a token is graded
   `failed` by the server and raises a fraud signal.
2. **Never token-less once the device has shown it can attest.** The server grades a token-less request `failed` + fraud signal, whatever it claims, when the device row has a registered App Attest key (iOS) or an earlier token
   graded `attested` (Android). So: iOS while a key is `registered` or `pending` (written right before a registration request is sent, so a registration whose outcome is unknown counts), Android once ONE token has been graded `attested` (persisted in the secure store, per user and device; also set when a token was SENT and its outcome is unknown, i.e. unless the failure is a DEFINITE non-application (any 4xx including 429 and 401, or a 503 with an `attestation_*` code): a network error, a 5xx, a 502 / 504 or a 503 without that code, or a 2xx whose body could not be read, since the server may have graded it `attested`):
   a local failure does **not** send a token-less request. It throws `AttestationDeferred`; `evidence/send.ts` counts it on the held challenge (`attestDeferrals`), persists it, and answers a retry.
   **The Android retry bound is `ATTEST_MAX_DEFERRALS = 8` deferrals per held challenge**: with the outbox backoff (15 s doubling, capped at 1 h, jittered) about 30 to 60 minutes of retrying; a prefetched challenge also expires on its own after 24 h.
   After that the next local failure DROPS the challenge (`none / attestation_unavailable`): the play goes with no challenge (x0.6, no co-signal) and **no token-less request is ever sent**, so an honest client never trips the
   "attested before, now no token" rule. (A device that has never attested and cannot get a token sends token-less with the claim `false`: `unattestable`, the case the task describes.)
3. **One assertion in flight per key (iOS).** App Attest's counter is strictly monotonic at the server and shared by `checkin-token` and (later) `rewards-activate`; two overlapping assertions that arrive out of order would grade an
   honest client `failed`. A per-(user, device) async mutex (`src/attest/mutex.ts`) is taken before the key is read or registered and released when the HTTP response of the request carrying the assertion returns or fails.
   **The hold timeout (90 s) ABORTS the holder, it does not abandon it** (PR #42 gate HIGH-1: an abandoned holder kept registering keys and sending requests outside the lock, leaving the client with key A and the server with key B,
   and every later check-in `failed` with a fraud signal). The holder calls `guard.check()` before EVERY side effect (state write, native call, HTTP request) and runs a SENT request (the registration, the request carrying the assertion)
   through `guard.effect(...)`: **a lock is never released while its holder has a request in flight** (the 20 s HTTP timeout bounds that), and a holder that finishes after the abort still returns its real answer. Each native call
   also has its own 30 s timeout (a transient local failure; its late result is discarded), so a stuck platform call cannot use up the lock. Different keys never wait for each other. Android has no key and no counter, so it takes no lock.
   **Activation seam (P4.2c; used by `activator.ts`, P4.2b-3b):** `rewards-activate` must take its assertions through `createAttestation(...).withAssertionLock(userId, deviceId, fn)` (or `withAssertionLock(locks, ...)` / `assertionLockKey`): the EXACT lock
   check-in uses. An attested activation, or one whose outcome is unknown after the request was sent, must also call `createAttestation(...).markAttestedActivation(userId, deviceId)`: the server grades a token-less
   check-in `failed` once the device has an `attested` activation verdict (0043) as well as an `attested` token.
4. **A 503 `attestation_unavailable` / `attestation_not_configured` from `checkin-token`** is the vendor being down: the server did not consume the challenge. It reaches `evidence/send.ts` as the `ApiError` it is and is answered as a
   retry; the held challenge is untouched (not dropped, not rewritten) and the same one is redeemed next time. It is never a dead letter. (Recorded answers: `token_503_attestation_*`.)
5. **iOS key lifecycle.** No registered key: a LIVE challenge, `generateKey`, `attestKey` over the registration binding, `POST devices-attest-key`, then the key id is kept in the secure store
   (`AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY`) as `gr.attest.ios_key.<userId>.<deviceId>`. The server binds a key to the device row of ONE account, hence per user and device. `pending` is written right BEFORE the registration request is sent (it may be applied
   although its answer is lost; a local failure before that leaves no record). The key is made BEFORE the live challenge is requested, so a local failure never spends a live challenge (the 30/h limit is shared with live check-in);
   a key whose `attestKey` failed only because Apple's service was unavailable is kept (`gr.attest.ios_unattested.…`) and the SAME key retried next time;
   a 503 `attestation_not_configured` from `devices-attest-key` (answered before anything is read or written: nothing was applied) clears `pending` when there was no earlier key, the check-in goes token-less with the claim `false`,
   and registration is not retried for `REGISTRATION_BACKOFF_MS` = 1 h (persisted, `gr.attest.ios_reg_backoff.…`; the same backoff follows a refusal of the key and a device that cannot do App Attest at all), so a deployment
   without App Attest does not cost a live challenge and an Apple `attestKey` on every outbox retry (PR #42 gate MEDIUM-2); a 409 `key_already_registered` counts as registered; a refusal of the key itself (422 `attestation_rejected` / `platform_mismatch`) with no earlier key clears the record and the check-in goes
   token-less with the claim `false`. `DCError.invalidKey` on an assertion (a reinstall destroys the Secure Enclave key; the Keychain item survives): the record is downgraded to `pending` (the server still holds the old key), a fresh key is registered ONCE per redemption, and the assertion is made again. A
   registration-phase answer that is about the registration (a used live challenge: 422 `challenge_not_consumable`) is a deferral, never read as a refusal of the held check-in challenge. A grade `unattestable` for an assertion we presented
   (the server holds no key) drops the local record so the next redemption registers again. Account deletion removes the deleted user's records.

**Selection.** `createAttestation` (`src/attest/setup.ts`) uses `NativeAttestor` + `NativeRedeemer` only when the module is linked, the platform supports it (an iOS simulator does not) and, on Android, the Cloud project number is
set. Everything else (Expo Go, web, tests, simulators) keeps `UnattestableAttestor` + `PlainRedeemer` (claim `false`, no block). `test/attest-setup.test.ts`.

**Prebuild policy** (a native module means a new prebuild; re-run offline: `CI=1 expo prebuild --no-install`, then `CI=1 pnpm test`; the generated files are gitignored, delete them afterwards): the policy test now also allow-lists the local
plugin, scans the GENERATED entitlements (only Sign in with Apple and App Attest `development | production`) and the GENERATED manifest's granted permissions (only INTERNET, VIBRATE and the one Health Connect read; the module adds none).
`[unverified]`: the Play Integrity library's own manifest is merged only in a real Gradle build, which was not run here; run `./gradlew :app:processReleaseMainManifest` and re-scan the merged manifest before shipping.

**What the server does NOT tell the client (PR #42 gate finding, (d)).** The `checkin-token` answer is `{jti, expiresAt, attestationGrade}`; the reason for a `failed` (`key_id_mismatch`, `counter_replay`,
`counter_out_of_order`, `rp_id_mismatch`, ...) goes only to the `fraud_signal` detail (`token-handler.ts`, `app-attest.ts#verifyAppAttestAssertion`), never to the client. So a client cannot tell "my key is stale"
(`key_id_mismatch`) from any other `failed`, and **does not guess**: it keeps the key unless the platform says `invalid_key` or the server answers `unattestable`. The only way a client could create a `key_id_mismatch` by itself (the lock
abandonment above) is closed. A mismatch from another cause (a key replaced from elsewhere) stays permanent until the server exposes the reason, or a client-visible signal, in the answer: a server follow-up, not done here.

**Unverified on a real device (all of it `[unverified]`).** The Swift and Kotlin were never compiled (no Xcode, no Android toolchain); the Expo Modules API usage (`AsyncFunction` with a trailing `Promise`, zero-argument forms,
`appContext.reactContext`) and the Play Integrity class and method names are written from the documented APIs, not checked against a build. No App Attest key was generated, no assertion verified by Apple's chain, no Play
Integrity token decoded by Google; the server's verification of real artifacts is `[unverified]` too (its own header says so). The recorder's Apple / Google PORTS are scripted (they accept exactly the base64url of the binding the real
code computed), so what the fixtures prove is the binding bytes, the strict request shape, the grading table and the 503 / counter / rule behaviour of the real handlers, not Apple's or Google's own verification. App Attest
`isSupported` on the simulator, key invalidation by an uninstall, the Keychain surviving a reinstall, Play Integrity provider invalidation, rate limits (Play Integrity standard requests have a per-app quota) and the
real latency of an assertion are unobserved. The 90 s lock hold, the 30 s native-call timeout, the 1 h registration backoff and the 8-deferral bound are chosen, not measured. The Kotlin error-code mapping (`PERMANENT_CODES` -> `unsupported`, the rest `unavailable`) and the `StandardIntegrityException.errorCode` accessor are written from the documented table, not checked against the library.

**Not done here:** reward activation was done in P4.2b-3b (above). Still not done: the
check-in screen and `CHECKIN_UI_ENABLED`, a cooldown on repeated registration refusals (each refused attempt costs a live challenge; the server's own limits, 10 per hour per user, bound it), and an EAS / Gradle build of the module.

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
