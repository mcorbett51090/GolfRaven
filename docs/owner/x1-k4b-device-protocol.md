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
- [ ] Also needed for X1 but not device-borrowed: **one phone golf app** (18Birdies, Hole19, TheGrint,
      Golfshot, or SwingU — any one, installed on either phone)

### Day-5 fallback rule (verbatim from plan §10 P0)

> If borrowing falls short by day 5, the owner chooses, in writing: (a) the **upgrade path** — ≈ $1,500 of
> the ≈ $2,500 buys the missing devices `[inference]`; or (b) X1 runs on the sources that were borrowed (it
> needs 2 of 3 to pass), and a K4b that could not run is recorded as **"not run — treated as fail"**, which is
> the pre-planned expected case (A47), with the written Garmin statement sent before P1. Without either, X1
> and K4b cannot finish in the P0 window.

Record the day-5 decision (borrow succeeded / upgrade path taken / running on partial sources) in
`docs/p0/X1.md`'s and `docs/p0/K4.md`'s logs when it happens — do not pre-fill it here.

## 2. X1 round protocol, per source

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

### 2c. One phone golf app

1. Start a round in any one of: 18Birdies, Hole19, TheGrint, Golfshot, SwingU (the plan names these as having
   no public API — X1 is checking whether they at least write to platform Health, not whether they expose an
   API).
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

Uses "a minimal Health Connect reader built in the P0 skeleton (0.5 pw, reused by P4)" — **this reader does
not exist in the repo yet as of 2026-09-23** (checked: no `apps/mobile` directory exists). Building it is a
separate P0 engineering task, out of scope for this runbook (which only covers `docs/owner/`). Once it
exists, run the equivalent round on Android and use the reader to inspect, per source app installed on the
Android phone: the Health Connect **exercise type**, whether a **route** is present, and the **`dataOrigin`**
(the Health Connect analogue of `HKSource.bundleIdentifier`).

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

| Source | OS | Workout/exercise written? | Route present? | Source id (`bundleIdentifier`/`dataOrigin`) | Verdict |
|---|---|---|---|---|---|
| Garmin watch + Connect Mobile | iOS | | | | |
| Garmin watch + Connect Mobile | Android | | | | |
| Apple Watch Workout | iOS | | — (Android N/A) | | |
| Phone golf app | iOS | | | | |
| Phone golf app | Android | | | | |

| K4b | Watch model 1 | Watch model 2 |
|---|---|---|
| Fix recorded inside polygon during native Golf activity? | | |
| Delivered to phone app backgrounded — iOS? | | |
| Delivered to phone app backgrounded — Android? | | |
| Verdict | | |

Copy final values into `docs/p0/X1.md` and `docs/p0/K4.md`'s MEASURED VALUE / VERDICT / Log sections once run.
