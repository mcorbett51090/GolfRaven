# @golfraven/mobile

GolfRaven's mobile app (Expo/React Native, build plan §3.1 row G, §7). The
**P0 skeleton's only real work here is the Android Health Connect reader**
for check **X1** (build plan §10 P0, row X1) — everything else (the real
screens, §7.2) starts in later phases.

## What's here

- `src/health-connect/` — the X1 reader:
  - `types.ts` — result shapes, plus a locally-declared `RawExerciseSessionRecord`
    narrowed to only the fields the reader uses (so the shaping logic has
    zero import-time dependency on the native package — see below).
  - `shape.ts` — **pure** filter/shape logic (no native calls): takes raw
    `ExerciseSession` records, keeps `exerciseType === GOLF` (32), and
    produces the per-session summary (`start`, `end`, `dataOrigin`,
    `routePresent`, `routePointCount`, `routeRequiresConsent`).
  - `reader.ts` — the thin native-calling wrapper: SDK availability check,
    `initialize()`, `requestPermission()` for `ExerciseSession`, `readRecords()`
    over the last N days, then `shapeGolfSessions()`.
- `App.tsx` / `index.ts` — a placeholder screen with one button ("Run X1
  Health Connect check") that calls the reader and shows the JSON output.
  Everything else in §7.2's real screens is unbuilt.
- `test/shape.test.ts` — unit tests for the **pure** shaping logic only
  (see "Not device-tested" below for why nothing else is tested here).

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
3. Open the app, tap **"Run X1 Health Connect check"**. The button:
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

## Everything else (not P0 scope)

The real screens (Trails / Played / Achievements / Wallet / Me — build
plan §7.2), sync lanes 2-5, course matching integration, offline outbox,
attestation, and sign-in all start later (P3/P4). `App.tsx` is a
placeholder, not a preview of the real app.

## Scripts

- `pnpm build` — no-ops. Real EAS/`expo export` builds start in P4; there
  is nothing to build yet in the P0 skeleton beyond what `typecheck`
  already proves compiles.
- `pnpm typecheck` — `tsc --noEmit`. This is the meaningful gate for this
  package right now.
- `pnpm test` — `vitest run` over `shape.ts`'s pure logic only.
