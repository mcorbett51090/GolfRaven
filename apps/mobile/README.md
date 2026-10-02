# @golfraven/mobile

GolfRaven's mobile app (Expo SDK 57 / React Native 0.86, build plan §3.1 row G, §7).

**Status: P4.1 first slice** — the app shell, the signed catalog cache, the outbox model, EN/FR-CA scaffolding and the
16+ age screen, all running against a **mock of `api.*`**. It started before M-freeze, the K3/K4 verdicts and the
production catalog keyset, on the owner's instruction; read **"What is gated"** below before relying on any of it.
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
  age-gate.tsx sign-in.tsx force-update.tsx dev/x1.tsx
src/
  catalog/              signed-catalog verifier + cache (the fail-closed core)
  outbox/               §7.6 outbox: pure state machine, stores, runner
  db/                   SqlDatabase interface, migrations, expo-sqlite adapter
  age/ signin/          O18 age gate; stub sign-in providers; startSignIn()
  api/                  ApiClient interface + the in-memory mock of api.*
  wallet/               O17 visibility rule
  browse/               pure selectors for the guest screens
  i18n/                 en + fr-CA catalogues, plural rules, locale resolution
  runtime/              composition root and React context (the only place that wires things)
  screens/ ui/ demo/    shared screen pieces, components, a labelled dev-only demo catalog
  health-connect/       P0 X1 reader (below)
test/                   vitest; test/support has the real-signer fixtures and the node:sqlite adapter
```

## What is built

| Area | State |
|---|---|
| **Navigation** | expo-router tabs + stack. Typechecks and **bundles for Android and iOS** (`expo export`, Metro + Hermes). Never run on a device or simulator `[unverified — needs a device]`. |
| **Guest browse (P4 AT 13)** | Trails list, Directory, region filter, Trail page (roster stops, `0 of n`), Facility page, Course page with booking rail, all with no account. "Near me" and "in progress" are not built. |
| **Signed catalog cache (AT 12)** | Fetches `catalog/v1/{manifest,manifest.sig,versions,versions.sig}.json` from `EXPO_PUBLIC_CATALOG_BASE_URL`; verifies the Ed25519 signatures over the exact bytes with the **same** canonical-JSON / domain-tag code the signer uses (`@golfraven/catalog-tools/manifest-core`); honours `minAppVersion` (force-update screen, cached catalog stays readable) and `revokedKids`; checks every shard's SHA-256 and length before swapping the cache atomically; re-verifies the cache on every load. A bad signature is never applied and raises the "catalog out of date" banner. **Rollbacks:** a manifest older than the highest `catalogVersion` this install has ever verified (`maxVerifiedCatalogVersion`, its own SQLite row, raised on every verified manifest — including `update_required` and same-version ones) is refused, and that floor survives the cache being dropped (revocation, keyset change, corruption). It does **not** survive an uninstall / "clear data" or the in-memory fallback store (SQLite could not be opened); an optional compiled-in `MIN_CATALOG_VERSION` (`src/catalog/keys.ts`, empty for now) bounds those cases once set. `refresh()` is single-flight and the floor is re-checked inside the save transaction. A corrupt revoked-set or floor row refuses every catalog (`TRUST_STATE_CORRUPT`) instead of reading as empty; recovery is clearing the app data. Fetches have a timeout, a streamed size cap and refuse redirects `[the stream cap and redirect refusal are unverified on a device — RN's own fetch may not expose a body stream]`. |
| **Outbox (AT 11)** | `pending → sent → accepted \| queued \| retry \| needs_attention` as a pure, tested state machine; SQLite persistence behind `OutboxStore`; a runner with crash recovery, backoff + jitter + `Retry-After`, 422 `catalog_stale` re-match, "Unlisted course" hold, 90-day dead letters. Matching is stubbed (see below). |
| **Age gate (AT 20)** | Neutral birth-year screen, runs before any provider; under the minimum only a device-local flag is kept and the retry is refused; the year is never stored. Providers are **stubs** that sign in to a local mock session. |
| **i18n (EN / FR-CA)** | Typed catalogues with a parity test; French is machine-drafted and unreviewed. Catalog `nameFr` / `blurbFr` are used in fr-CA. |
| **Wallet (O17)** | Tab hidden unless some trail's mock programme status is `pilot`/`live`; contents are placeholders. |
| **Policy gates** | `test/policy.test.ts`: no `app.config.*` (a dynamic config could hide things from a scan of `app.json`); the static **and** Expo-resolved config is clean; no background-location / `SYSTEM_ALERT_WINDOW` permission, permission names compared short or qualified; config plugins limited to an allow-list; `android.allowBackup` is `false`; the **generated** `AndroidManifest.xml` and `Info.plist` are clean (AT 5); no ads/analytics SDK in the lockfile (AT 7). The generated-file tests skip locally unless you ran `expo prebuild --no-install`, and **fail** under `CI` if the files are missing; the `verify` job runs prebuild first. |

## Configuration

| Variable | Purpose |
|---|---|
| `EXPO_PUBLIC_CATALOG_BASE_URL` | `https://host[/path]` serving `catalog/v1/`. Unset: no network refresh; in a `__DEV__` build the screens show a labelled **demo** catalog (it never touches the verifier). |
| `EXPO_PUBLIC_STORE_URL` | `https://…` store listing for the force-update screen. |

Public values only; nothing secret belongs here. `src/catalog/keys.ts` ships an **empty** keyset until the production
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
- **Stubbed on purpose:** real `api.*`, sign-in, deletion, push, share cards, the on-device matcher, file import,
  the user-pick flow (§4.3), the private-club trail note (O8), App Attest. Effects worth knowing, in `src/runtime/services.ts`:
  `rematch` only checks the stored course still exists in the current catalog and, with no verified snapshot (every build
  until the keyset exists), returns `{ ok: false }` — so a 422 `catalog_stale` answer **dead-letters** the play;
  `findCourseForUnlisted` always returns `null`, so an "Unlisted course" play never becomes sendable; `resolveQueued`
  (`src/outbox/machine.ts`) has **no caller**, so a `queued` play never leaves `queued` on the device.
- **`expo-secure-store` (P4.2):** not installed. The stub sign-in keeps its mock session in memory only. Real sign-in needs a
  hardware-backed store for the refresh token, and nothing secret may go in SQLite, `AsyncStorage` or the `EXPO_PUBLIC_*` env.
- **Backups (P4.2, iOS):** `android.allowBackup` is `false`, so Android does not copy `golfraven.db` (and the device-local
  under-age flag in it) off the device `[Android 12+ device-to-device transfer: unverified]`. **iOS is not closed:** `expo-sqlite`
  57.0.3 stores the file in `Documents/SQLite`, which iCloud/iTunes backups include, and offers no way to exclude it
  `[checked in the installed package; the iOS behaviour itself is unverified — never run on a device]`. P4.2 item: set
  `NSURLIsExcludedFromBackupKey` on it (small native module / `expo-file-system`) or keep the flag elsewhere.
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
- Local checks that are not in CI: `pnpm exec expo export --platform android` (and `ios`) proves Metro can bundle the
  app (`--no-bytecode` and a grep show what a release bundle contains). CI **does** run
  `expo prebuild --no-install` before the tests, so the policy test scans the **generated** `AndroidManifest.xml` and
  `Info.plist` (AT 5, `allowBackup`); run the same locally before `pnpm test` to get those two tests instead of skips.
  Delete the generated `android/` and `ios/` afterwards (they are gitignored).
- This package needs `pnpm -r build` first: it imports the built `dist/` of `@golfraven/catalog` (types) and
  `@golfraven/catalog-tools`.

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

Sync lanes 2-5, course-matching integration, the attestation client and real sign-in are later P4 work; see "What is
gated" above.
