# P4.1 React Native library spike — Expo SDK 57 / React Native 0.86.3

- **Status:** builder recommendation for owner review. Nothing here is an accepted decision.
- **Date:** 2026-10-02
- **Scope:** build plan §10 P4 pre-build gate "the RN library spike done (the first week of P4)", and §7.1's list of
  libraries that are `[unverified — training knowledge]`. The owner chose to start P4.1 before M-freeze and before the
  K3/K4 verdicts; this spike is therefore the first thing P4.1 produces, and **the gates it feeds are still open** (see
  "What remains gated").
- **Where this lives:** `apps/mobile/SPIKE.md`, next to the code it constrains. `docs/decisions/NNNN-*.md` is for owner
  decisions (Status / Decider); parallel builders are adding records there and a sequence number would collide.
  Promote it to a numbered record if the owner wants it ratified.

## How to read the evidence tags

| Tag | Meaning |
|---|---|
| **[verified]** | Observed in this container this session: the package's published tarball or `.d.ts` read directly, a registry query, a Metro bundle, an Expo autolinking run, `expo prebuild`, or a test that ran. The check is named. |
| **[unverified — training knowledge]** | Recalled, not checked. Do not build on it without a check. |
| **[unverified — needs a device]** | Plausible from the types and the code, but only a real iOS/Android device or simulator can confirm it. This container has neither. |

Registry queries used `registry.npmjs.org` (`npm view`, `npm pack`). SDK 57's own certified versions come from
`expo@57.0.24`'s `bundledNativeModules.json`. **[verified]**

## Recommendation table

Versions are exact (the repo's `save-exact=true`). "In slice" means installed and used by P4.1's first slice.

| Concern | Recommendation | In slice? | Status |
|---|---|---|---|
| Navigation | `expo-router` **57.0.22** (+ `expo-linking` 57.0.10, `expo-constants` 57.0.19, `@expo/metro-runtime` 57.0.16, `react-native-screens` 4.26.0, `react-native-safe-area-context` 5.7.0), **with the `packageExtensions` entry in `pnpm-workspace.yaml`** (finding F1) | yes | bundles on Android and iOS **[verified]**; runtime on device **[unverified — needs a device]** |
| SQLite (catalog cache, outbox, device flags) | `expo-sqlite` **57.0.3** | yes | API **[verified]**; SQL tested on Node's SQLite, not the on-device engine |
| i18n EN / FR-CA | `expo-localization` **57.0.2** for device locale + a small typed translator (no i18n library) | yes | **[verified]** |
| Ed25519 + SHA-256 for the signed catalog | `@noble/curves` **2.4.0** + `@noble/hashes` **2.4.0** | yes | interop with the Node signer **[verified]** (finding F5) |
| Secure storage (refresh token) | `expo-secure-store` **57.0.4**, plugin option `faceIDPermission: false` | **no** (no token exists yet) | API and plugin **[verified]**; Keychain/Keystore behaviour **[unverified — needs a device]** |
| Sign in with Apple | `expo-apple-authentication` **57.0.2** | **no** (stub providers) | API and plugin **[verified]**; flow **[unverified — needs a device]** |
| App Attest / Play Integrity | `@expo/app-integrity` **57.0.2** **plus a small local Expo module for DeviceCheck**, and a server/client binding decision (finding F4) | **no** | API **[verified]**; **gaps found** |
| HealthKit | `@kingstinct/react-native-healthkit` **16.0.0** + `react-native-nitro-modules` **0.37.1**, plugin options `background: false`, `NSHealthUpdateUsageDescription: false` | **no** (counsel L7) | plugin source **[verified]**; reads **[unverified — needs a device]** |
| Health Connect | `react-native-health-connect` **4.1.3** (already present, unchanged) | already there | manifest output **[verified]** |

## Findings that changed what was built

### F1. `expo-router` + pnpm `autoInstallPeers` silently adds three off-SDK native modules

`expo-router@57.0.22` depends on `react-native-drawer-layout`, whose peers `react-native-reanimated` and
`react-native-gesture-handler` are not optional. This repo's lockfile has `autoInstallPeers: true`, so a plain
`pnpm add expo-router` installed **`react-native-reanimated` 4.7.1, `react-native-gesture-handler` 3.3.0 and
`react-native-worklets` 0.13.0** (and a mismatched `@react-native/metro-config` 0.87.1 against RN 0.86.3). Expo SDK 57's
certified set is gesture-handler `~2.32.0`, reanimated `4.5.1`, worklets `0.10.1`. **[verified]**

Worse, `expo-modules-autolinking react-native-config --platform android` listed all of them, so they would be compiled
into the binary although no code imports them. **[verified]**

**Fix:** `pnpm-workspace.yaml` `packageExtensions` marks those two peers optional on `react-native-drawer-layout` (the
drawer navigator is not used). After a clean re-resolve the autolinked React Native modules are exactly
`@react-native-masked-view/masked-view` (a hard dependency of expo-router), `react-native-health-connect`,
`react-native-safe-area-context` and `react-native-screens`; the Expo modules include `@expo/ui` (also a hard
dependency of expo-router). **[verified]** This is a repo-level setting: anyone merging another Expo package should
re-run `pnpm install` and re-check that list.

**Alternative, if native footprint matters more than file-based routing:** `@react-navigation/native` 7.5.0 +
`@react-navigation/bottom-tabs` 7.20.0 + `@react-navigation/native-stack` 7.20.0 (registry latest, **[verified]**)
declare only `react-native-screens` and `react-native-safe-area-context` as native peers (from the three packages' own
registry peer lists, **[verified]**; their `@react-navigation/elements` dependency was not inspected and nothing was
built with them). Rejected for now only because §7.1 names `expo-router` and the Expo SDK template and docs
assume it.

`expo-router` 57.0.24 is the registry's latest, but needs `expo-constants ^57.0.20` and `expo-linking ^57.0.11`,
above what SDK 57 certifies (`~57.0.19`, `~57.0.10`). The recommendation stays on SDK-certified 57.0.22. **[verified]**

Two more routing facts that bit during the build: `expo-router` treats **`src/app/` as the route root if it exists**
(observed: "Using src/app as the root directory"), so application code must not live there; and the old P0 module's
`./types.js`-style relative imports **cannot be resolved by Metro** (observed), so `src/health-connect/*` and its test
now import extensionless. **[verified]** Both Android and iOS bundles then built (`expo export`, 1326 modules on
Android, Hermes bytecode compiled).

### F2. `@golfraven/catalog` cannot be imported at runtime by the app today

Its entry point re-exports `ids.ts` (`import { randomBytes } from "node:crypto"`) and `load.ts` (`node:fs/promises`).
A probe route importing `TrailSchema` failed Metro with `Unable to resolve module node:crypto from
packages/catalog/dist/ids.js`. **[verified]** The app therefore uses `import type` only from `@golfraven/catalog`
(erased at build time) and parses shard contents with light guards; the contents are already authenticated by SHA-256
against the signed manifest. **Follow-up for the catalog owner:** split `mintId`/`loadCatalog` out of the entry point
(or add a `./schema` subpath export) so the app can run the Zod schemas.

### F3. The signing algorithm is shared, not copied

`tools/catalog/src/manifest.ts` imported `node:crypto` and used `Buffer`, so Metro/Hermes could not bundle it. Its
platform-neutral part (canonical JSON, the domain tags, the statement shapes, the strict parser, the Zod schemas) moved
**verbatim** to `tools/catalog/src/manifest-core.ts`; `manifest.ts` re-exports it and keeps the three Node members
(`sha256Hex`, the two `*StatementBytes`, the Buffer-taking `strictParseAndValidate`). The existing catalog-tools tests pass unchanged
(240 pass with the new test added, 1 skipped as before), and a new test (`manifest-core-neutral.test.ts`) fails if `manifest-core.ts` ever imports a
`node:*` module or `Buffer`. The app imports `@golfraven/catalog-tools/manifest-core`; Metro bundled it. **[verified]**
The supabase import function still carries its own port of the same algorithm
(`supabase/functions/_shared/catalog/manifest-artifact.ts`); that is out of scope here.

### F4. App Attest: the Expo module hashes the challenge itself, so the plan's binding does not map onto it

`@expo/app-integrity` 57.0.2 exposes, on iOS, `isSupported`, `generateKeyAsync`, `attestKeyAsync(keyId, challenge)`
and `generateAssertionAsync(keyId, challenge)`; on Android `prepareIntegrityTokenProviderAsync(cloudProjectNumber)`,
`requestIntegrityCheckAsync(requestHash)`, `isHardwareAttestationSupportedAsync`, `generateHardwareAttestedKeyAsync`
and `getAttestationCertificateChainAsync`. **[verified, from the published `.d.ts`]**

1. **Binding mismatch.** The Swift source computes `clientDataHash = SHA256(Data(challenge.utf8))` internally, from a
   JavaScript **string**. The server (`supabase/functions/_shared/rewards/binding.ts`) expects
   `clientDataHash = SHA-256(canonical_body ‖ RAW nonce bytes)`. Raw nonce bytes are not valid UTF-8, so they cannot be
   passed through a JS string unchanged. Either the server binds `utf8(canonical_body ‖ base64url(nonce))` instead, or
   the client passes a pre-hash and the server double-hashes, or a local module takes bytes. **[verified]** (both
   source files read) — **this needs a decision from whoever owns §7.5 / P3 attestation before P4.2.**
2. **No DeviceCheck.** The module imports `DeviceCheck` only for `DCAppAttestService`; there is no
   `DCDevice.generateToken()`, which §7.5's two persistent bits need. A ~10-line local Expo module (Swift) is required.
   **[verified]**
3. **No config plugin.** The package ships none, so the App Attest entitlement must be set through
   `ios.entitlements` (key `com.apple.developer.devicecheck.appattest-environment`
   **[unverified — training knowledge]**).
4. Native module: dev client only, no Expo Go.

### F5. Ed25519 on Hermes

Hermes has no `crypto.subtle`, and `expo-crypto` 57.0.3 has digests but no Ed25519 verification
(**[verified]** against its types). `@noble/curves` 2.4.0 verifies signatures made by `node:crypto` (the real signer):
every genuine fixture verifies, every tampered one fails, in `test/catalog-verify.test.ts`. Verification uses
`{ zip215: false }` (strict RFC 8032). The artifact signature is **standard padded base64** (what `signBytes`
emits) while public keys are unpadded base64url; the app decodes each correctly. **[verified]** Verification speed
on a phone is **[unverified — needs a device]**; the cache is re-verified on every load, so measure it.

## Per-concern notes

### Secure storage — `expo-secure-store` 57.0.4 (not installed yet)

- API: `setItemAsync` / `getItemAsync` / `deleteItemAsync` (+ sync variants), `isAvailableAsync`,
  `keychainAccessible` option with `AFTER_FIRST_UNLOCK`, `AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY`, `WHEN_UNLOCKED`,
  `WHEN_UNLOCKED_THIS_DEVICE_ONLY` (and deprecated `ALWAYS*`, `WHEN_PASSCODE_SET_*`). **[verified]**
- **Config plugin side effects (verified by reading the plugin):** it writes a default `NSFaceIDUsageDescription`
  ("Allow $(PRODUCT_NAME) to access your Face ID biometric data.") even if biometrics are never used — a purpose string
  the app does not need, in a plan that already worries about purpose-string rejection. `faceIDPermission: false`
  removes it (`@expo/config-plugins` `Permissions.js` deletes a key whose value is `false`). It also points Android's
  `fullBackupContent` / `dataExtractionRules` at `secure_store_*` rules so items stay out of backups. **[verified]**
- Recommended for the refresh token: `AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY` **[unverified — training knowledge]**.
  Whether the iOS Keychain item survives an uninstall/reinstall, and the Android Keystore-backed encryption details,
  are **[unverified — needs a device]**. This matters for the age gate (§7.8): that flag deliberately lives in SQLite
  (removed on uninstall), not here.

### SQLite — `expo-sqlite` 57.0.3

Used for the catalog cache, the outbox and `device_flags`. API used: `openDatabaseAsync`, `execAsync`, `runAsync`,
`getAllAsync`, `withExclusiveTransactionAsync` (`withTransactionAsync` is documented as non-exclusive, so other queries
can interleave; the app uses the exclusive form). **[verified]** The stores are written against a four-method
`SqlDatabase` interface; tests run the real SQL (including `ON CONFLICT … DO UPDATE`, transactions, rollback,
`PRAGMA user_version` migrations) on Node's `node:sqlite` (SQLite 3.51.2). The engine bundled in `expo-sqlite` is
**[unverified — needs a device]**; avoid SQL newer than that engine until checked.

### Sign in with Apple — `expo-apple-authentication` 57.0.2 (not installed yet)

- `signInAsync` returns a credential with nullable `identityToken` and `authorizationCode` (both needed: the first for
  the Supabase id-token flow, the second to obtain the grant that §7.8 revokes on deletion). **[verified]**
- The plugin adds the `com.apple.developer.applesignin: ["Default"]` entitlement and
  `CFBundleAllowMixedLocalizations`. **[verified]**
- The module is iOS-only (`isAvailableAsync`). Apple on Android, Google, and email OTP are not covered by it. Registry
  versions for the next slice, none evaluated: `expo-auth-session` 57.0.13 (SDK-certified `~57.0.12`),
  `@react-native-google-signin/google-signin` 16.1.5, `@supabase/supabase-js` 2.117.2. Supabase's native id-token
  sign-in is **[unverified — training knowledge]** (plan A77).

### HealthKit — `@kingstinct/react-native-healthkit` 16.0.0 (not installed; counsel L7)

- Peers: `react` ≥19, `react-native` ≥0.79, `react-native-nitro-modules` ≥0.35 (registry latest 0.37.1). It is a
  Nitro module, so it needs the new architecture (already on). **[verified]**
- **Its Expo plugin turns HealthKit background delivery on by default** (`com.apple.developer.healthkit.background-delivery`,
  unless `background: false`) and writes `NSHealthUpdateUsageDescription` (a *write* purpose string) unless it is set to
  `false`. The app only reads, so install it with `background: false` and `NSHealthUpdateUsageDescription: false`, and an
  explicit `NSHealthShareUsageDescription`. **[verified, from the published plugin source]**
- The README documents `queryWorkoutSamples` and `workout.getWorkoutRoutes()`; the shape of route points and whether
  they give what lane 1 needs is **[unverified — needs a device]** (the P0 X1 export read is the real test).
- **Do not ship a HealthKit read before counsel L7 signs** (§10 P4 gates); installing it is a separate step.

### Health Connect — `react-native-health-connect` 4.1.3 (already in the app)

`expo prebuild` generates the permission-rationale intent filter and the `ViewPermissionUsageActivity` alias, and
`android.permission.health.READ_EXERCISE` is in the manifest. **[verified]** Runtime behaviour is still
**[unverified — needs a device]** (check X1, `README.md`).

### i18n — `expo-localization` 57.0.2, no library

`getLocales()` supplies the device's preferred tags; the plugin writes `CFBundleLocalizations` and Android's
`locales_config.xml` for `en` and `fr-CA`. **[verified]** (`expo prebuild` output). Message catalogues are typed objects:
`fr-CA` is checked against `en` at compile time, and `test/i18n.test.ts` checks identical keys and `{placeholders}` and
that no string is empty. French plurals (0 and 1 are singular) are hand-rolled rather than `Intl.PluralRules`
(Hermes Intl coverage for `fr-CA` is **[unverified — training knowledge]**).

Libraries considered and not installed: `i18next` 26.4.2 + `react-i18next` 17.0.15, `i18n-js` 4.5.3 (registry
**[verified]**). Add `i18next` only if ICU plurals, gender, lazy namespaces or number/date formatting appear.
**The French copy is machine-drafted and unreviewed by a native fr-CA speaker**, and Bill 96 legal text is a separate
P4 deliverable.

### Not evaluated in depth (registry facts only)

`@tanstack/react-query` 5.104.1 (named in §7.1; unneeded until the real `api.*` client), `react-native-view-shot` (SDK
57 certifies 5.1.0, registry latest 6.1.0 — use the SDK's), `@maplibre/maplibre-react-native` 11.4.1 (peers: expo ≥54,
RN ≥0.80). Share cards and maps are outside this slice. Component tests would need `jest-expo` (SDK-certified `~57.0.5`)
and `@testing-library/react-native`; vitest cannot render React Native.

## What is installed in the slice, and why

`expo-router`, `expo-linking`, `expo-constants`, `@expo/metro-runtime`, `react-native-screens`,
`react-native-safe-area-context` (navigation, F1); `expo-sqlite`; `expo-localization`; `@noble/curves`,
`@noble/hashes`; workspace links to `@golfraven/catalog` (types) and `@golfraven/catalog-tools` (the shared
verifier core); dev: `@types/node` (tests only — the app's `tsconfig.json` sets `types: []` so a Node-only API in app
code fails to typecheck). Everything else above is deliberately **not** installed.

## What remains gated

| Gate | Blocks |
|---|---|
| **M-freeze** (`contractVersion 1`) | `SUPPORTED_CONTRACT_MAJOR` is `0` in `src/config-values.ts`; the freeze moves it to `1` and may change shard shapes. |
| **Production catalog keyset** (§3.5, P3 pre-build gate, ≥ 2 keys) | `src/catalog/keys.ts` ships an **empty** keyset on purpose, so a build verifies nothing and every manifest fails closed. `assertReleaseKeyset` is the gate to wire into the release build. |
| **K3 / K4 verdicts** | Whether lane 1 / lane 5 ship (HealthKit and Health Connect imports) and K4b's Connect IQ shape. Nothing built here depends on them. |
| **Counsel L7** | The first HealthKit read. |
| **§7.5 attestation decisions (F4)** | The App Attest client. |
| **Real `api.*`, sign-in, deletion, push, share cards, matching integration, file import** | P4.2 and later slices. |

The review of this spike's `[unverified — needs a device]` rows needs a dev build on a real iPhone and Android phone
(`npx expo run:ios` / `run:android`, or an EAS development build); none exists yet.
