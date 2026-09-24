# K4b feasibility memo — Connect IQ sync lane

Prerequisites-only research pass (plan §10 P0, `docs/p0/K4.md`, `docs/owner/x1-k4b-device-protocol.md` §3).
No device test was run here — this answers "is the K4b device test worth setting up," not K4b itself.
Network this session: `github.com`/`raw.githubusercontent.com`/`registry.npmjs.org` + WebSearch reachable;
`developer.garmin.com` and plain `github.com` HTML pages returned `403`/CONNECT-tunnel failures on every
direct probe (see Open questions §1) — all Garmin-primary-doc claims below rest on WebSearch snippets of
those pages, not fetched bodies, and are marked accordingly.

## Summary

Connect IQ (watch-app SDK, free signup) and the Garmin **Connect Developer Program** (Health/Activity APIs,
paused) are confirmed-separate programs — K4b's developer-signup prerequisite is unaffected by the freeze.
Garmin ships official, license-gated (not OSS) Mobile SDKs for both Android (Maven Central) and iOS
(GitHub), and one community MIT-licensed React Native wrapper exists (published 2025-05-13, single
maintainer, Expo-untested). The crux — whether a third-party component can get position fixes **while
Garmin's own native Golf activity is running** — is undocumented in every source reachable this session;
the plan's own `[unverified]` flag stands. A background-service + temporal-event path (≥1 fix per 5-minute
tick, independent of the foreground activity) looks more plausible than a data-field hosted inside Golf
itself, but neither is confirmed. Cheapest falsifier: an on-watch-only widget/background-service probe,
zero phone code, before any RN/Expo bridge work.

## 1. Connect IQ app types — what can run alongside native Golf, and the crux

Documented app types (Watch App, Widget, Data Field, Watch Face, Glance, Background Service) come only from
WebSearch snippets of `developer.garmin.com` pages and secondary write-ups — the primary pages were
unreachable (403) this session, so treat the shapes below as **plausible-but-unverified** even though
multiple independent snippets agree on them:

- **Watch App** — a full activity-equivalent; owns button input and its own data recording. Not a way to
  attach to Garmin's _own_ Golf activity, since it would be a separate activity.
- **Data Field** — the thing shown on an activity's data screen; can be added to **an** activity, but
  whether Garmin's own native Golf activity accepts third-party data fields is the one question no source
  answers either way this session. `[unverified — training knowledge, matches plan §7.3's own flag]`
- **Widget** — lighter-weight, glance-accessible, cannot record data continuously; separate from whatever
  activity is running.
- **Background Service** — a delegate invoked on a **temporal event**; per one forum answer (secondary,
  primary page 403'd) a background-service-backed data field is capped at "a position every 5 minutes...
  for battery," and Toybox.Background's own doc snippet confirms **temporal events cannot re-fire less than
  5 minutes apart**, with only one temporal event registrable at a time. A widget host is reported as
  **not** subject to that 5-minute cap in the same secondary thread. `[unverified — secondary/forum source,
not the primary API doc body]`
- **Permissions**: manifest-declared via `<iq:uses-permission id="…"/>` — `Background`, `Communications`,
  `Positioning` are the three relevant ones. One documented constraint: **Positioning is invalid for
  `WATCH_FACE`**, and watch faces also cannot use `Communications`. Whether Positioning/Background can be
  combined on a **Widget** or **Data Field** specifically (as opposed to Watch App) was not confirmed this
  session — plausible by omission (only watch faces are called out as restricted) but not stated positively.

**Crux, stated precisely:** nothing fetched this session confirms or denies that (a) Garmin's native Golf
activity hosts third-party data fields, or (b) a background service can obtain GPS fixes via
`Toybox.Position` while a _different_, Garmin-native activity (Golf) is simultaneously recording and
presumably already holding the GPS chip. Both are structurally plausible (background services are
documented as independent of the foreground activity, and a data field host is a separate integration point
from GPS access) but neither is confirmed. This is the same gap the plan itself flags as `A47` (fail is the
pre-planned expected case).

## 2. Phone side — Connect IQ Mobile SDK

- **Android**: official artifact on Maven Central — `com.garmin.connectiq:ciq-companion-app-sdk:2.2.0`
  (Gradle: `implementation("com.garmin.connectiq:ciq-companion-app-sdk:2.2.0@aar")`); source/sample at
  `github.com/garmin/connectiq-android-sdk`. Per a search-snippet summary, Android Mobile SDK apps
  communicate **through Garmin Connect Mobile (GCM)** as an intermediary — i.e. GCM must be installed and
  the watch paired through it. `[unverified — snippet summary, GCM-dependency wording not independently
confirmed against the primary page body]`
- **iOS**: official repo `github.com/garmin/connectiq-companion-app-sdk-ios` ("Connect IQ Companion App
  SDK"), sample at `github.com/garmin/connectiq-companion-app-example-ios`. Per the same snippet, **iOS
  Mobile SDK apps are standalone and do not directly depend on GCM** — a real platform asymmetry if
  accurate. `[unverified — same caveat]`
- **License**: both SDKs are gated by Garmin's own **Connect IQ Developer Agreement**, not a standard OSS
  license (MIT/Apache) — accepting that agreement is part of the SDK download, per the GitHub repo's own
  framing in search results. Full agreement text not fetched this session.
- **Message delivery / backgrounding**: the watch side sends via `Toybox.Communications`; the phone side
  registers a listener (`registerForAppMessages` on iOS) once device state is `.connected`. On iOS, a
  search-summary states "the iOS system allows apps that communicate with Bluetooth devices to be woken up
  to execute in the background when a connected device has data to send" — this is standard **CoreBluetooth
  background-central-role wake**, which would satisfy K4b's "phone app backgrounded" bar if it applies here.
  A separate forum thread (title only, not fetched) flags user reports of the iOS companion app **not
  launching when fully killed** — consistent with "backgrounded works, killed doesn't," which is exactly
  what K4b requires (backgrounded, not killed) but is not a confirmed guarantee. `[unverified — both points
rest on WebSearch snippets, not the fetched primary doc or forum thread body]`
- No Garmin Connect Mobile dependency is documented for the **iOS** companion bridge specifically (see
  above); Android's dependency on GCM, if the snippet summary is accurate, is a real extra moving part for
  the Android side of K4b's test.

## 3. React Native / Expo

- **`react-native-connect-iq-mobile-sdk`** (`github.com/cjsmith/react-native-connect-iq-mobile-sdk`) — npm
  registry (fetched directly, `registry.npmjs.org`, 200 OK): latest **0.3.0**, published **2025-05-13**,
  license **MIT**, 9 published versions since **2023-10-30** (npm `created` timestamp). Wraps both Android
  and iOS Garmin Mobile SDKs per its own description. GitHub star count / last-commit date could not be
  confirmed — every direct fetch of `github.com` HTML pages returned `HTTP 403` this session (see Open
  questions §1), and the `github` MCP tool errored with "GitHub access to this repository is not enabled for
  this session." Single npm maintainer (`cj2smith`) — a **one-person community wrapper**, not Garmin-owned.
  `[unverified — stars/commit-recency specifically]`
- A derivative fork, **`@mzhu22-mayo/react-native-connect-iq-mobile-sdk`**, is published under a different
  npm scope, latest **0.2.7**, published **2024-07-08** — older than upstream's current 0.3.0, i.e. it has
  fallen behind the base package rather than tracking it.
- A second, differently-scoped package, **`react-native-garmin-connect`**
  (`github.com/malgorzatamaz/react-native-garmin-connect`) — npm latest **0.3.0**, published **2024-07-30**,
  MIT — is a **different tool**: per its own description it needs a **custom Garmin watch app** sending
  messages, i.e. device-to-app messaging plumbing, not a wrapper around Garmin's own Companion App SDK
  pairing/discovery flow. Not a substitute for `cjsmith`'s package for K4b's purposes.
- **No package found this session is described as, or ships, an Expo config plugin** for Connect IQ. Expo's
  own docs (fetched via WebSearch, `docs.expo.dev`) are unambiguous on the general mechanics: **custom
  native libraries cannot run inside Expo Go**; a config plugin customizes the native Android/iOS projects
  generated by `expo prebuild`, and consuming a native module needs an **Expo dev-client build (EAS)**, not
  Expo Go. Concretely, an Expo config plugin for this bridge would need to: (Android) add the Maven Central
  coordinate `com.garmin.connectiq:ciq-companion-app-sdk` as a Gradle dependency (via `expo-build-properties`
  `extraMavenRepos` or a raw plugin); (iOS) vendor the Garmin framework/CocoaPod and add whatever
  URL-scheme / `LSApplicationQueriesSchemes` Info.plist entries the iOS Companion App SDK's own pairing flow
  needs (not confirmed from a primary source this session — `[unverified]`, inferred from the general
  pattern other BLE/companion-app RN wrappers use).
- **Net feasibility for this piece**: plausible-but-unverified. The pieces exist (official SDKs + one
  community wrapper + standard Expo config-plugin mechanics), but no one has already built "Connect IQ +
  Expo" — this would be first-of-its-kind integration work, not a drop-in.

## 4. Developer program — is K4b's signup prerequisite affected by the freeze?

**Confirmed separate, this session.** Multiple independent secondary sources (`sahha.ai`, `the5krunner.com`,
`themomentum.ai`) describe Garmin's **Connect Developer Program** (Health, Activity, Training, Courses,
Women's Health APIs) as paused for new applicants since ~mid-September 2026, no reopening date given — this
is the same freeze `research/golf-app-sync.md` already documented for the K1–K4a sync-source survey. One of
those summaries states explicitly: _"this pause affects the Connect Developer Program (the API side), while
Connect IQ — which covers watch faces, data fields, widgets, and on-device apps — is still open."_ Garmin
also runs a **separate, standing Connect IQ developer-registration form**
(`garmin.com/en-US/forms/ciq-registration/`, found via WebSearch, not itself fetched) distinct from the
Developer Portal application the freeze targets. `[unverified — the distinct-program claim rests on a
secondary blog's summary, not Garmin's own program-scope statement, which was unreachable; but two
independent secondary sources agree on the same split]` **Working conclusion: K4b's developer-signup
prerequisite is not blocked by the freeze**, consistent with the plan already treating the two as unrelated.

## 5. Verdict for planning (feasibility of the _prerequisites_, not K4b itself)

| Sub-question                                                      | Rating                                                                    | Why                                                                                                                                    |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Connect IQ app-type taxonomy exists, permissions model exists     | documented-feasible                                                       | Multiple independent snippets agree on shapes + manifest permission mechanics, though primary doc bodies unfetched                     |
| Data field hosted inside native Golf activity                     | plausible-but-unverified (leaning toward the plan's own pre-planned fail) | No source, this session, confirms or denies it                                                                                         |
| Background-service GPS fix while a different native activity runs | plausible-but-unverified                                                  | Background/temporal-event mechanics are documented; interaction with a concurrently-running native Golf activity is not                |
| Phone SDKs exist, are current, are usable without GCM on iOS      | documented-feasible (Android GCM-dependency point stays unverified)       | Official GitHub/Maven Central artifacts found and linked                                                                               |
| Backgrounded (not killed) delivery to phone                       | plausible-but-unverified                                                  | BLE background-wake mechanism is standard and plausible; explicit Garmin confirmation not fetched; killed-state is reported unreliable |
| RN/Expo wrapper exists and is usable                              | plausible-but-unverified                                                  | One MIT, still-updated (2025-05-13) community wrapper exists; no Expo config plugin found; would be first-of-kind integration          |
| Expo dev-build (not Expo Go) required                             | documented-feasible                                                       | Expo's own docs are explicit and unambiguous                                                                                           |
| Developer signup unaffected by API freeze                         | documented-feasible                                                       | Two independent secondary sources agree the freeze is Developer-Program-only, not Connect IQ                                           |

**Single most likely failure point:** whether Garmin's own native Golf activity will host a third-party data
field, or (the more promising alternate path) whether a background service can pull `Toybox.Position` fixes
on its own temporal-event cadence while that native Golf activity runs and presumably already owns the GPS
chip. This is undocumented everywhere reachable this session and is exactly the gap the plan pre-flags as
`A47`.

**Cheapest test that would falsify it first (before any phone/RN work):** on one borrowed watch, using only
the free Connect IQ SDK + simulator (no companion app, no RN bridge yet), build a minimal **widget or
background-service** component with `Positioning` + `Background` permissions that logs a fix count to its
own on-watch view. Start Garmin's native Golf activity, then check whether the widget/background service
still receives `Toybox.Position` updates. This isolates the crux (can any third-party component get GPS
data at all while native Golf owns the activity) at zero phone-app cost, before spending effort on the
Mobile SDK bridge, the RN wrapper, or an Expo config plugin — all of which are wasted work if this step
fails.

**What the owner must do before the K4b device test:**

1. Connect IQ developer signup (`garmin.com/en-US/forms/ciq-registration/`) — free, unaffected by the API
   freeze (§4).
2. Borrow ≥2 current Garmin golf watch models (already tracked as a checklist item in
   `docs/owner/x1-k4b-device-protocol.md` §1, shared with X1).
3. Install the free Connect IQ SDK (Monkey C toolchain) + simulator on a dev machine, for the cheapest
   falsifier above.
4. Stand up an Expo dev-client (EAS) build target before attempting the phone-side companion bridge — Expo
   Go cannot host this native module (§3).

## Claims table

| Claim                                                                                                                                                                                                                   | Kind                                                                                                     | Source URL                                                                                                                                                                                                | Retrieved  |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `developer.garmin.com` is unreachable this session (`CONNECT tunnel failed, response 403`)                                                                                                                              | Observation                                                                                              | (this-session probe, no URL — `curl` to `https://developer.garmin.com/connect-iq/api-docs/`)                                                                                                              | 2026-09-24 |
| Direct HTML fetch of `github.com` repo pages returns `HTTP 403` this session                                                                                                                                            | Observation                                                                                              | (this-session probe — `curl -L https://github.com/cjsmith/react-native-connect-iq-mobile-sdk`)                                                                                                            | 2026-09-24 |
| GitHub API/MCP access to arbitrary repos is not enabled for this session ("Use add_repo to request access")                                                                                                             | Observation                                                                                              | (this-session tool error, `api.github.com/repos/cjsmith/react-native-connect-iq-mobile-sdk`)                                                                                                              | 2026-09-24 |
| Connect IQ app types include Watch App, Widget, Data Field, Watch Face, Glance                                                                                                                                          | Observation (WebSearch snippet, primary page body not fetched)                                           | https://fellrnr.com/wiki/Connect_IQ ; https://codingricky.com/garmins-connect-iq/                                                                                                                         | 2026-09-24 |
| Widgets cannot record data continuously / integrate with external sensors the way watch apps can                                                                                                                        | Observation (secondary snippet)                                                                          | https://fellrnr.com/wiki/Connect_IQ                                                                                                                                                                       | 2026-09-24 |
| Whether a third-party data field can be added to Garmin's native Golf activity specifically                                                                                                                             | Unverified — no source confirmed or denied this session                                                  | [unverified — training knowledge, matches plan §7.3's own flag]                                                                                                                                           | 2026-09-24 |
| Connect IQ temporal events cannot re-fire less than 5 minutes apart; only one may be registered at a time                                                                                                               | Observation (WebSearch snippet of Garmin's own Background module doc, body not fetched — domain blocked) | https://developer.garmin.com/downloads/connect-iq/monkey-c/doc/Toybox/Background.html                                                                                                                     | 2026-09-24 |
| A background-service-backed data field is limited to sending a position update every 5 minutes for battery; a widget host does not have this limitation                                                                 | Observation, secondary/forum source                                                                      | https://forums.garmin.com/developer/connect-iq/f/discussion/5443/background-temporal-event                                                                                                                | 2026-09-24 |
| Connect IQ manifest permissions (`Background`, `Communications`, `Positioning`) are declared via `<iq:uses-permission id="…"/>`; `Positioning` is invalid for `WATCH_FACE`, and watch faces cannot use `Communications` | Observation (WebSearch snippet)                                                                          | https://developer.garmin.com/connect-iq/core-topics/manifest-and-permissions/                                                                                                                             | 2026-09-24 |
| Connect IQ Mobile SDK for Android is distributed on Maven Central as `com.garmin.connectiq:ciq-companion-app-sdk`, current version 2.2.0                                                                                | Observation                                                                                              | https://central.sonatype.com/artifact/com.garmin.connectiq/ciq-companion-app-sdk ; https://github.com/garmin/connectiq-android-sdk                                                                        | 2026-09-24 |
| Connect IQ Companion App SDK for iOS is an official Garmin GitHub repo with an accompanying example app                                                                                                                 | Observation                                                                                              | https://github.com/garmin/connectiq-companion-app-sdk-ios ; https://github.com/garmin/connectiq-companion-app-example-ios                                                                                 | 2026-09-24 |
| Both Mobile SDKs are gated by Garmin's own Connect IQ Developer Agreement, not a standard OSS license                                                                                                                   | Observation (WebSearch snippet of the repo page, license file body not fetched)                          | https://github.com/garmin/connectiq-companion-app-sdk-ios                                                                                                                                                 | 2026-09-24 |
| Android Mobile SDK apps communicate through Garmin Connect Mobile (GCM); iOS Mobile SDK apps are standalone and do not directly rely on GCM                                                                             | Observation (WebSearch snippet, not independently corroborated against the primary page body)            | https://developer.garmin.com/connect-iq/core-topics/mobile-sdk-for-android/ ; https://developer.garmin.com/connect-iq/core-topics/mobile-sdk-for-ios/                                                     | 2026-09-24 |
| iOS allows apps that communicate with Bluetooth devices to be woken in the background when the connected device has data to send                                                                                        | Observation (WebSearch summary)                                                                          | https://developer.garmin.com/connect-iq/core-topics/mobile-sdk-for-ios/                                                                                                                                   | 2026-09-24 |
| Users have reported the iOS Connect IQ companion app not launching when fully killed                                                                                                                                    | Observation, forum report (title only, thread body not fetched)                                          | https://forums.garmin.com/developer/connect-iq/f/discussion/4502/ios-companion-app                                                                                                                        | 2026-09-24 |
| `react-native-connect-iq-mobile-sdk` latest version is 0.3.0, published 2025-05-13, MIT license, first published 2023-10-30                                                                                             | Observation (fetched directly from `registry.npmjs.org`)                                                 | https://registry.npmjs.org/react-native-connect-iq-mobile-sdk ; https://github.com/cjsmith/react-native-connect-iq-mobile-sdk                                                                             | 2026-09-24 |
| `@mzhu22-mayo/react-native-connect-iq-mobile-sdk` (a fork) latest version is 0.2.7, published 2024-07-08 — behind upstream's 0.3.0                                                                                      | Observation                                                                                              | https://registry.npmjs.org/@mzhu22-mayo/react-native-connect-iq-mobile-sdk                                                                                                                                | 2026-09-24 |
| `react-native-garmin-connect` (a different package, requires a custom Garmin watch app) latest version is 0.3.0, published 2024-07-30, MIT license                                                                      | Observation                                                                                              | https://registry.npmjs.org/react-native-garmin-connect ; https://github.com/malgorzatamaz/react-native-garmin-connect                                                                                     | 2026-09-24 |
| GitHub star count and last-commit date for `cjsmith/react-native-connect-iq-mobile-sdk`                                                                                                                                 | Unverified — GitHub HTML/API fetch blocked this session (403 / no session access)                        | [unverified]                                                                                                                                                                                              | 2026-09-24 |
| Custom native libraries cannot run inside Expo Go; a config plugin customizes native projects generated by `expo prebuild`; a dev-client (EAS) build is required to use a custom native module                          | Observation                                                                                              | https://docs.expo.dev/config-plugins/plugins/ ; https://docs.expo.dev/modules/third-party-library/                                                                                                        | 2026-09-24 |
| `expo-build-properties` supports `extraMavenRepos` for adding Android Maven dependencies via a config plugin                                                                                                            | Observation                                                                                              | https://docs.expo.dev/versions/latest/sdk/build-properties/                                                                                                                                               | 2026-09-24 |
| iOS config-plugin dependencies can be vendored as a framework via `vendored_frameworks`, or added via CocoaPods/Podfile modification                                                                                    | Observation                                                                                              | https://docs.expo.dev/modules/third-party-library/                                                                                                                                                        | 2026-09-24 |
| Garmin's Connect Developer Program (Health, Activity, Training, Courses, Women's Health APIs) is paused for new applicants since ~mid-September 2026, no reopening date given                                           | Observation, secondary reporting                                                                         | https://sahha.ai/blog/garmin-developer-program-paused/ ; https://the5krunner.com/2026/09/14/garmin-developer-api-access-paused/ ; https://www.themomentum.ai/blog/garmin-developer-program-closed-roadmap | 2026-09-24 |
| The Connect Developer Program freeze is separate from Connect IQ (watch faces, data fields, widgets, on-device apps), which remains open                                                                                | Observation, secondary source summary                                                                    | https://sahha.ai/blog/garmin-developer-program-paused/                                                                                                                                                    | 2026-09-24 |
| A standing Connect IQ developer-registration form exists at `garmin.com/en-US/forms/ciq-registration/`, separate from the Connect Developer Program application                                                         | Observation (found via WebSearch; form page itself not fetched)                                          | https://www.garmin.com/en-US/forms/ciq-registration/                                                                                                                                                      | 2026-09-24 |

## Open questions

1. **This session's network access could not reach any `developer.garmin.com` page directly** (every probe
   returned `403`/CONNECT-tunnel-failed), and direct `github.com` HTML fetches also 403'd — every Garmin
   primary-source claim above is a WebSearch snippet summary, not a fetched page body. Re-run this memo's
   claims against the actual page bodies once network access allows, before treating any "documented" rating
   above as final.
2. **The crux question (§1) has no source either way.** It can only be resolved empirically — the cheapest
   path is the on-watch-only widget/background-service probe in §5, run before any phone-side work.
3. **GitHub star count / commit recency for `cjsmith/react-native-connect-iq-mobile-sdk`** — needed to judge
   whether it's a live, responsive maintainer or an abandoned single-commit-per-release project; npm publish
   cadence (9 releases since 2023-10-30, most recent 2025-05-13) is a partial proxy but not a substitute.
4. **Android's reported GCM dependency for the Mobile SDK bridge** is stated only in a secondary snippet
   summary and could materially change the Android side of the K4b device test (an extra app that must be
   installed/running) if confirmed.
5. **iOS Info.plist / URL-scheme requirements for the Companion App SDK pairing flow** were inferred from
   general BLE/companion-app RN-wrapper patterns, not confirmed from Garmin's own iOS Mobile SDK doc body.
6. Whether the Garmin Golf Premium API freeze (a separate open question already flagged in
   `research/golf-app-sync.md` open question 1) has any bearing on Connect IQ specifically was not
   re-examined here — K4b does not depend on that API, only on the free Connect IQ SDK track, per §4.
