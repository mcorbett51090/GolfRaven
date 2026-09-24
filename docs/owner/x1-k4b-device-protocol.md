# X1 / K4b device protocol — borrowing, round protocol, Health export, Connect IQ

Covers plan §10 P0 checks **X1 (=K4a)** and **K4b**, and the "Test devices, borrowed first" non-gating P0
item. Thresholds and consequences are quoted verbatim in `docs/p0/X1.md` and `docs/p0/K4.md` — this file is
the how-to.

## 1. Borrowing checklist (plan §10 P0, "Test devices, borrowed first")

Borrow, by **day 5**, from golfing friends, a local club, or a retailer demo pool, at **$0**:

- [ ] **≥ 2 current Garmin golf watch models** (needed for K4b's "≥ 2 current Garmin golf watch models" bar,
      and for X1's Garmin + Connect Mobile source)
- [ ] **1 Apple Watch + 1 iPhone** (X1's Apple Watch Workout source)
- [ ] **1 Android handset with Health Connect** (X1's Android pass)
- [ ] Also needed for X1 but not device-borrowed: **18Birdies** (the named phone golf app — decision 0001,
      Addendum D, R6). If it cannot be installed, or offers no Apple Health / Health Connect write setting,
      **Hole19** replaces it; log the reason in `docs/p0/X1.md` before the round. Any other app (TheGrint,
      Golfshot, SwingU) tried alongside is supplementary data only, never the source verdict.

### Day-5 fallback rule (verbatim from plan §10 P0)

> If borrowing falls short by day 5, the owner chooses, in writing: (a) the **upgrade path** — ≈ $1,500 of
> the ≈ $2,500 buys the missing devices `[inference]`; or (b) X1 runs on the sources that were borrowed (it
> needs 2 of 3 to pass), and a K4b that could not run is recorded as **"not run — treated as fail"**, which is
> the pre-planned expected case (A47), with the written Garmin statement sent before P1. Without either, X1
> and K4b cannot finish in the P0 window.

Record the day-5 decision (borrow succeeded / upgrade path taken / running on partial sources) in
`docs/p0/X1.md`'s and `docs/p0/K4.md`'s logs when it happens — do not pre-fill it here.

## 2. X1 round protocol, per source

**Log the round window (decision 0001 Addendum F) — now a LABEL, not a gate (decision 0005).** Before
teeing off, note the round's start time (UTC), and its end time once it's over — then add BOTH to
`docs/p0/X1.md`'s "## Round windows" section (one bullet, `<START> to <END>`, strict
`YYYY-MM-DDThh:mm:ssZ`), ideally before the export is read on either device, though this no longer
gates anything. `x1-ios-export` and `x1-verdict` **no longer refuse to run** if this is blank
(decision 0005 supersedes Addendum F's refusal): every golf workout already on the device counts, not
just ones from this round — a workout/session whose start time falls inside a logged window, with 60
minutes of slack either side, is only tagged `testRound: true` in the output, and everything else is
tagged `testRound: false`. Do this once per round (iOS pass and Android pass each get their own
window/bullet if they happen on different days) if you want the tagging; skipping it just means every
workout reads `testRound: false`.

**Log the "Recorded export" UTC date FIRST instead (decision 0005) — this is what now gates the
tools.** Before reading either OS's export, add that OS's UTC date to `docs/p0/X1.md`'s "## Recorded
export" section. `x1-ios-export --os ios` and `x1-verdict` (which now takes `--ios-export <dir>`
and/or `--android <json>` — no `--os` flag any more) both refuse to produce the RECORDED X1 result for
an OS whose date there is still blank; pass `--informational` to run anyway, but **only against a
synthetic fixture under `tools/p0/test/fixtures/`, never real device data, while that OS is unbound**
(round-3 Opus-gate correction, post-8e5a29b, superseding round 2's narrower "only in the logged-but-
unbound gap" — now it's "no informational runs on real data while unbound," full stop; once an OS is
bound, `--informational` may run against any path). Each tool binds ITS OWN OS's export by a fresh UTC
date + SHA-256 match. **A recorded X1 verdict is decided per OS, RECOMPUTED FRESH from that OS's bound
file every single time `x1-verdict` runs — nothing about the result is ever stored in
`docs/p0/X1.md` or read back from it** (round-3 Opus-gate correction, post-8e5a29b, simplifying round
2's `result:pass`/`result:kill`-line design and its accompanying git-history tampering scan, per the
gate's explicit "fix by simplifying" instruction). Run `x1-verdict --ios-export <dir>` after the iOS
pass and `x1-verdict --android <json>` after the Android pass (or both together, once both are
bound) — each call verifies and recomputes whichever OS(es) it's given, and the overall result is
"pass if any of them recomputed to pass." **The run that performs an OS's FIRST bind prints no verdict
at all (round-4 Opus-gate correction, post-4279773)** — it stops at "bound: commit and push
docs/p0/X1.md, then re-run" without computing or writing anything else; commit, push, then run the
SAME command again to get the actual result. Deleting/reverting a bound `sha256:` line does **not**
quietly reopen that OS for a re-bind — the tools check `docs/p0/X1.md`'s own git history first and
refuse with "re-binding needs an owner decision" if it was ever bound before; ask Matt before trying
to force one. Every recorded run also refuses outright if `docs/p0/X1.md` has uncommitted changes, or
if git itself isn't available. **The real protection against a rewritten local git history is
procedural, not automatic:** commit AND PUSH `docs/p0/X1.md` to GitHub immediately after any run that
binds a new hash — the same discipline decision 0001 Addendum F relies on for K2's exclusion dating.

Play **one real round (~4 h)** carrying all three iOS sources simultaneously where possible (Garmin watch +
Apple Watch + phone with a golf app), so one round covers all three:

### 2a. Garmin watch + Garmin Connect Mobile

1. Start Garmin's native **Golf** activity on the watch before teeing off.
2. Carry the paired phone with Garmin Connect Mobile running (foreground or background per Garmin's own
   sync behavior).
3. End the activity after 18 (or 9) holes; let it sync to Garmin Connect.
4. Garmin Connect writes the workout to Apple Health (if HealthKit write permission was granted during Garmin
   Connect setup) — this is what X1 actually inspects, not the Garmin app's own data.

### 2b. Apple Watch Workout

1. Start a Workout on the Apple Watch — Golf, if offered as an activity type, else the closest available
   `[unverified — training knowledge: whether `HKWorkoutActivityType` includes a dedicated golf case;
   `research/golf-app-sync.md` flags this as unverified]`.
2. Keep the watch on-wrist for the round; end the workout afterward.

### 2c. One phone golf app — 18Birdies (Hole19 pre-round fallback)

1. Start a round in **18Birdies** (decision 0001, Addendum D, R6 — the plan names it, alongside Hole19,
   TheGrint, Golfshot and SwingU, as having no public API; X1 is checking whether it at least writes to
   platform Health, not whether it exposes an API). If 18Birdies cannot be installed, or has no Apple Health
   / Health Connect write setting, use **Hole19** instead and log the substitution and its reason in
   `docs/p0/X1.md` before the round.
2. Complete the round in the app; confirm (in the app's own settings) that it has HealthKit write permission
   enabled, if such a setting exists.

### 2d. iOS Health export steps

`[unverified — training knowledge, per plan G-P0-06]`

1. On the iPhone: **Settings → tap your name/profile → Health → tap your profile icon (top right) → Export
   All Health Data**.
2. This produces `export.zip`. Unzip it. It should contain:
   - `export.xml` — the full health record, including `<Workout>` elements.
   - `apple_health_export/workout-routes/` — one GPX file per workout that has an associated
     `HKWorkoutRoute`.
3. **What to inspect, per workout, in `export.xml`:**
   - `workoutActivityType` — confirms what activity type each source logged the round as.
   - `HKSource.bundleIdentifier` (the app that wrote the workout) — this is what separates "Garmin Connect
     wrote it" from "the phone golf app wrote it" from "the Watch's own Workout app wrote it," and is also
     the field the §7.3 source allow-list will key on later.
   - Whether a matching GPX file exists under `workout-routes/` for that workout ⇒ `HKWorkoutRoute` present
     (the "with routes" part of the pass bar).

### 2e. Android Health Connect pass

Uses "a minimal Health Connect reader built in the P0 skeleton (0.5 pw, reused by P4)" — as of 2026-09-23
**this reader is built** (`apps/mobile/src/health-connect/`; typechecks, and its pure shaping logic is
unit-tested), but it is **not device-tested**: nothing in it has run on a real Android device or emulator
with Health Connect installed (see `apps/mobile/README.md` "Not device-tested"). Running the round on
Android is the device test this reader still needs. Once a real round has been recorded and the app run on
a real device, use the reader to inspect, per source app installed on the Android phone: the Health
Connect **exercise type**, whether a **route** is present, and the **`dataOrigin`** (the Health Connect
analogue of `HKSource.bundleIdentifier`).

### 2f. What to inspect, restated (both OSes)

| Field | iOS | Android |
|---|---|---|
| Activity/exercise type | `workoutActivityType` | Health Connect exercise type |
| Route present | GPX file in `workout-routes/` (⇒ `HKWorkoutRoute`) | Health Connect route record present |
| Source app | `HKSource.bundleIdentifier` | Health Connect `dataOrigin` |

## 3. K4b protocol (Connect IQ)

1. **Garmin Connect IQ developer signup** — register as a Connect IQ developer at Garmin's developer portal
   (a prerequisite, not the pass bar).
2. **Sample companion** — start from Garmin's sample Connect IQ data-field/widget + companion-app project as
   scaffolding for a "Trail Check-in" component (a prerequisite, not the pass bar). Expo native-module
   feasibility for the companion bridge is also a prerequisite, per plan §7.1 ("The Connect IQ Mobile SDK
   bridge is a native module (feasibility: P0 K4b).").
3. **The actual pass bar** (on ≥ 2 current Garmin golf watch models):
   - Install the Connect IQ component; start Garmin's **native** Golf activity (not a custom activity — the
     plan is explicit that a data field hosted only inside a third-party activity is a de facto fail, since
     Garmin's native Golf activity "may not host third-party data fields `[unverified — training
     knowledge]`", making a fail the pre-planned expected case, A47).
   - Confirm the component records **≥ 1 GPS fix inside a course polygon** while that native Golf activity
     runs.
   - Confirm the fix **reaches the phone companion app with the phone app backgrounded** — test this
     explicitly on both **iOS and Android**; foreground-only delivery is a fail.
4. Record a pass/fail per watch model tested, and note whether delivery worked backgrounded on each OS.

## 4. Results table (fill in per source per OS — do not pre-fill values)

The "CONSENT_REQUIRED + follow-up read" column (decision 0001, Addendum D, R6) applies only on Android: for a
session Health Connect reports as `CONSENT_REQUIRED`, record whether a follow-up `requestExerciseRoute` call
for that session's record id returned ≥ 1 point (**Y** — counts as "route present"), returned none (**N** —
counts as "not present"), or the session never hit `CONSENT_REQUIRED` at all (**N/A**).

| Source | OS | Workout/exercise written? | Route present? | CONSENT_REQUIRED + follow-up read | Source id (`bundleIdentifier`/`dataOrigin`) | Verdict |
|---|---|---|---|---|---|---|
| Garmin watch + Connect Mobile | iOS | | | N/A (iOS) | | |
| Garmin watch + Connect Mobile | Android | | | | | |
| Apple Watch Workout | iOS | | | N/A (iOS) | | |
| Apple Watch Workout | Android | N/A | N/A | N/A | N/A | N/A (no Apple Watch on Android) |
| Phone golf app (18Birdies, or Hole19 if substituted) | iOS | | | N/A (iOS) | | |
| Phone golf app (18Birdies, or Hole19 if substituted) | Android | | | | | |

| K4b | Watch model 1 | Watch model 2 |
|---|---|---|
| Fix recorded inside polygon during native Golf activity? | | |
| Delivered to phone app backgrounded — iOS? | | |
| Delivered to phone app backgrounded — Android? | | |
| Verdict | | |

Copy final values into `docs/p0/X1.md` and `docs/p0/K4.md`'s MEASURED VALUE / VERDICT / Log sections once run.
