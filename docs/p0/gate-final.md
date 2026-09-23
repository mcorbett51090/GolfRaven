# Final gate: round-3 fixes, Addendum F conformance, new attack surface

- **Scope:** `apps/signup-worker/**`, `apps/landing/**`, `tools/p0/**`, docs changes, and decision 0001
  Addenda E and F (`docs/decisions/0001-owner-decisions-and-p0-thresholds.md`).
- **Branch:** `claude/golf-trails-golfnow-app-lumnqo` at `4e581ea`. The diff was read against `origin/main`.
- **Order of commits:** Addendum F was committed in `592d076` (20:25Z). The tool changes that implement it
  came later, in `2a91b31` (20:54Z). No X1 round window, X5 measured value or K2 day 0 exists anywhere, so
  Addendum F was pinned before any data existed.
- **Method:**
  - Every probe was a scratch node script or vitest file under the session scratchpad. They import the
    repo's `src/*.ts` or built `dist/*.js`.
  - K2 dating was tested with the real `scripts/k2-count.mjs` and `dist/` copied into throwaway git repos.
    Commits there used controlled `GIT_AUTHOR_DATE` / `GIT_COMMITTER_DATE`.
  - The X5 live path was tested against a local HTTP stub standing in for Overpass. No real Overpass call
    was made.
  - No repo file other than this report was written. `git status --short` was empty after every run
    (ignored `*.tsbuildinfo` / `dist/` only).
- **Date:** 2026-09-23.

## Commands

| command | result |
|---|---|
| `pnpm install --frozen-lockfile --config.engine-strict=false` | exit 0 ("Lockfile is up to date") |
| `pnpm --config.engine-strict=false -r typecheck` | exit 0 |
| `pnpm --config.engine-strict=false -r build` | exit 0 |
| `pnpm --config.engine-strict=false -r test` | exit 0. signup-worker 16 files / 197 tests; tools/p0 5 files / 96 tests; mobile 8; catalog 3; matching 1; rules 1; landing smoke checks pass. |
| `git status --short` after the test run | empty. The working tree is clean. |

`test/k2-git-integration.test.mjs` really runs (3 tests, verified with `--reporter=verbose`). It skips itself
when `dist/` is not built (see NIT F-N8).

---

## 1. Round-3 findings: status

| id | r3 severity | now | evidence (file:line) and probe result |
|---|---|---|---|
| B-1 | BLOCKING | **CLOSED** | `overpass-geo.ts:163-176` assembles `outer`-role way members, and `joinSegmentsIntoRings` (`:115-146`) joins open segments, reversing them where needed. **Probe:** a relation whose outer ring is split into 2 segments, one reversed, plus an `inner` member and a `node` member: knownPoint inside → `"point"`. The same relation with the approximate location inside it, name path → `"name"` (distance 0). 3 scrambled segments form one closed ring of 5 points → `"point"`. Two disjoint outer rings, point in the second → `"point"`. Residual: F-N2. |
| B-2 | BLOCKING | **CLOSED** | `distanceToPolygonMeters` (`overpass-geo.ts:195-207`) returns 0 inside, otherwise the distance to the nearest edge. It is used at `x5-overpass.ts:259-260`. **Probe:** an approximate location inside a same-named 1.3 km polygon near its edge → `"name"`. 499 m north of the edge → `"name"` (499.00 m). 501 m → `null`. 499 m / 501 m east → `"name"` / `null`. Residual: F-N1. |
| B-3 | SHOULD-FIX | **PARTIAL** | The normalisation is pinned in F and implemented literally (`overpass-geo.ts:243-265`; probes in §2). **Not pinned:** which X2 fields count as a "known point". The branch selection the tool uses also contradicts F's literal text. See **F-S1**. |
| B-4 | SHOULD-FIX | **CLOSED** | `remark` throws (`x5-overpass.ts:123-130`). Probe: HTTP 200 with a `remark` → exit 1. A missing saved response → throws (`:494-500`); probe exit 1. An empty course list → throws (`:452-459`); probe exit 1. A non-JSON body → exit 1. `{"elements":"x"}` → exit 1. Residual: a missing `golf=hole` count element is still read as 0 (F-N3; quality-only). |
| B-5 | SHOULD-FIX | **PARTIAL** | Live mode now writes `<out>-responses.json` (`:523-529`). **The tool cannot replay it**, and `n-osm` saves nothing. See **F-S4**. |
| B-6 | SHOULD-FIX | **CLOSED** | `x1-verdict.ts:299-304` counts passes per OS and returns `ios >= 2 \|\| android >= 2`. `sourcesPassingByOs` is emitted. This matches F literally. |
| B-7 | SHOULD-FIX | **CLOSED** | Both CLIs read `docs/p0/X1.md` "Round windows" and refuse when none is logged (`round-windows.ts:105-114`; `x1-ios-export.ts:100-106`; `x1-verdict.ts:200-205`). `x1-verdict` also re-filters both OS inputs itself (`:241-244`). Slack probe: window 13:00Z-17:30Z, start `2026-09-20 08:00:00 -0400` → in, `07:59:59 -0400` → out, `18:30:00Z` → in, `18:30:01Z` → out. Residual: the parser robustness gap in **F-S6**. |
| B-8 | SHOULD-FIX | **CLOSED** | A sibling `<WorkoutRoute>` now throws `HealthExportShapeError` (`health-export-xml.ts:130,172-183,217-228`), and the fixture `export-sibling-workout-route.xml` is tested. Residual: GPX files that no workout references are not checked (F-N7). |
| B-9 | NIT | **CLOSED** | `x1-verdict.ts:187-236` rejects the other app's identifiers. |
| B-10 | NIT | **CLOSED**, but the fix introduced a crash | The contact comes from `X5_CONTACT`. The default contact string contains U+2014, which crashes every live run. See **F-S5**. |
| B-11 | NIT | **CLOSED** | The bbox is centred on `knownPoint` (`x5-overpass.ts:506`). All three CLIs compare `realpath`s. |
| B-12 | NIT | **CLOSED** | Keys come from `courseKey` (`id ?? name`, `x5-overpass.ts:220-222`). |
| A-1 | SHOULD-FIX | **CLOSED** | The confirm hash is persisted only after `sendConfirmationEmailAndLog` returns true (`index.ts:300-315`). **Probe** (resend after cooldown, Resend returns 500): 1 attempt; the first email's unsubscribe → 200, confirm → 200, `confirmed_at` set. |
| A-2 | NIT | **CLOSED**, with a residual | The unsubscribe token is now derived and stable (`tokens.ts:57-64`, `index.ts:303,352`). **Probe** (two successful resends): all 3 emails carry the same token; confirm from email 3 → 200; unsubscribe from email 1 → 200, `unsubscribed_at` set; unsubscribe from email 1 again → 200. Residual: the problem returns after a pepper rotation (**F-S7**). |
| A-3 | SHOULD-FIX | **CLOSED** | `K2_DAY0` is required, and `K2_GATE_CLOSES_AT` must equal day 0 + 42 d exactly (`config.ts:215-257`; `index.ts:580-605`). **Probe**, day 0 = 2026-11-20 typed into `K2_GATE_CLOSES_AT`: `deletedUnsubscribed=0` at 12-25, 01-30, 01-31 and 03-01, both with `K2_DAY0` set and with it unset. The close date typed into `K2_DAY0` → 0. A roll-over `K2_DAY0=2026-11-31` → 0. Consistent pair (2026-11-20 / 2027-01-01): 0 until gate + 30 d, then 2. |
| A-4 | NIT | **CLOSED** | Round-trip check at `config.ts:194-196`. Probe: `2026-11-31T00:00:00Z` and `2026-11-20T24:00:00Z` → no deletion. |
| A-5 | SHOULD-FIX | **PARTIAL** | Probes S2 (reformat after day 0 → still excluded) and S6 (shallow clone → refuses, exit 1) are fixed. **S5 (deletion after day 0) still un-excludes silently**, which F explicitly forbids. See **F-S2**. There is also a new case and substring defect in the pickaxe (**F-S3**). |
| A-6 | SHOULD-FIX | **PARTIAL** (carried as open SHOULD-FIX) | Runbook step 9 (`apps/signup-worker/README.md:251-265`) now orders the steps "commit+push the address → e2e test → log day 0". It never says the commit must fall on an **earlier UTC date**. Day 0 is the date of the test, so a same-day commit is not "before day 0 00:00 UTC". **Real-git probe:** exclusion committed 2026-10-10T10:00Z, e2e at 11:00Z, day 0 = 2026-10-10 → `test-e2e@golfraven.example` **not excluded**, `distinct confirmed 1`. Fix: step 9.1 must say "commit and push on a UTC date **before** the e2e test day (the test day becomes day 0)". |
| A-7 | NIT | **CLOSED** | The known limit is stated verbatim (`k2-count.mjs:48-51`; README "Timestamp tamper limit"). |
| A-8 | NIT | **CLOSED** | `- _a2@x.com_ (owner)` → `a2@x.com`; `- _a5@x.com (owner)_` → `a5@x.com`; `test_user@x.com` is preserved. |
| A-9 | NIT | **CLOSED** | `docs/p0/K2.md:66-77` now points at the built `apps/signup-worker`. |
| A-10 | NIT | **CLOSED** | `apps/landing/src/index.html:143` now reads "about 30 days after the K2 test closes (or 30 days after you unsubscribe, whichever is later)". This matches `index.ts:593-595`. |

### Regressions from earlier rounds (re-run)

N1 and N2 below are the two BLOCKING findings from the earlier re-verification round (`signup-worker-reverify.md`).

**N1 (skipped send must not kill the delivered links).** Each case signs up, then re-submits from a different
IP, then uses the last **delivered** email's links.

```
N1 cooldown:        202 | sends 1->1 | last-delivered unsubscribe 200 | confirm 200 | confirmed_at set
N1 email-daily-cap: 202 | sends 3->3 | last-delivered unsubscribe 200 | confirm 200 | confirmed_at set
N1 global-cap:      202 | sends 1->1 | last-delivered unsubscribe 200 | confirm 200 | confirmed_at set
A-1 resend-500:     1 failed attempt | FIRST email unsubscribe 200 | confirm 200 | confirmed_at set
```

**N2 (retention gate).** Each run has one row confirmed then unsubscribed, and one active row.
`K2_DAY0` = `K2_GATE_CLOSES_AT` − 42 d wherever a consistent pair was possible.

```
unset / "" / "2026" / "1" / "2026-11-21" / day0-typed "2026-10-10T00:00:00Z"   -> deleted 0
pre-floor "2026-11-15T23:59:59Z" / ".000Z" form / 11-31 roll-over / T24:00     -> deleted 0
valid, now = gate+7d / gate+30d-1s                                             -> deleted 0
valid, now = gate+30d                                                          -> deleted 1 (unsubscribed row only; active row kept)
valid K2_GATE_CLOSES_AT but K2_DAY0 unset                                      -> deleted 0
```

Both hold.

---

## 2. Conformance to Addendum F, read literally

| F rule | verdict | evidence |
|---|---|---|
| X5 geometry: a way **or relation**, outer ring | conforms | B-1 probes above. Inner rings are deliberately not subtracted (`overpass-geo.ts:148-156`), which matches "outer-ring geometry". Probe: a knownPoint inside an inner hole → `"point"`. |
| X5 distance: shortest distance to the polygon, 0 inside, ≤ 500 m | conforms | B-2 probes above. |
| X5 normalisation (NFKD, diacritics removed, lower-case, non-letter/digit → space, whitespace collapsed), equality **or** whole-word containment, nothing more | conforms | Probes: `Hammock's`=`Hammock’s` ✓; NBSP / double space ✓; `Café Links`=`CAFE LINKS` ✓; `Naïve`=`naive` ✓; ligature `ﬁeld`=`field` ✓ (NFKD). `Golf Club`≠`Golf Course` ✓. `Ridge Golf` is not in `Pilot Ridgegolf` ✓ (whole-word). `Pilot Ridge Golf Course` is not in OSM `Pilot Ridge` ✓ (containment is one-way, OSM ⊇ course, as F says). `Straße`≠`strasse` ✓ (lower-case only, no case-folding, as F says). Empty-after-normalisation names never match ✓. Only the combining marks U+0300–036F are stripped (F-N4). |
| X5: the **either (a) or (b)** match structure | **does not conform** | **F-S1.** F says either (a) the known point is inside, or (b) the names match within 500 m. The code runs (b) only when there is **no** known point (`x5-overpass.ts:248-253`). The README restates F with an added "with no known point" clause (`tools/p0/README.md:174`). |
| X5 run integrity: remark / missing / unparseable / empty list → non-zero exit | conforms | Every probe exited 1 (see B-4). |
| X5: "every live response is saved … so the verdict can be replayed offline" | **partial** | **F-S4.** The coverage responses are saved, but `--responses` rejects the saved file. `n-osm` saves nothing. |
| X1 single OS: ≥ 2 of 3 on one OS; sources on different OSes do not combine | conforms | `x1-verdict.ts:299-304`. Apple Watch on Android is `not-applicable` and never counts. |
| X1 round window: start inside a logged window ± 60 min; refuse when none is logged; older workouts ignored | conforms, with a robustness gap | B-7 probes above. A blank section → refusal. A window logged with a `-04:00` offset instead of `Z` is not parsed. If it is the only line, the result is a refusal (loud). A **malformed or reversed** `Z` window is accepted and silently matches nothing (**F-S6**). |
| K2: first appearance via `git log -S` over the full history, **committer** time, strictly before day 0 00:00 UTC | conforms | `k2-count.mjs:375-378` (`%cI`, `--reverse`, first line). `k2-blame.ts:87` (`<` cutoff). Probes: S1 excluded; reformat after day 0 still excluded; removed before day 0 and re-added after → excluded (the first appearance is before day 0, as F says). A pre-day-0 branch commit merged after day 0 → excluded. That last case is F's committer-time rule plus its stated known limit. |
| K2: "so later reformatting **or deletion** does not change it" | **does not conform** | **F-S2.** Only addresses **currently** listed are ever checked (`k2-count.mjs:435-437`). |
| K2: refuse in a shallow clone | conforms | `k2-count.mjs:409-418`. Probe: `clone --depth 1` → "This is a shallow git clone … Refusing to run", exit 1. |

---

## 3. New-code attack surface

**Derived unsubscribe token** (`tokens.ts:57-64`, `index.ts:303,352,502-510`):

- **Keying and domain separation are sound.**
  - The token is HMAC-SHA256 with key = pepper over `golfraven-unsubscribe-v1:<email_lc>`.
  - Everything else uses a different construction: `SHA-256(pepper ":" value)` with `ip:` and `email:` prefixes.
  - The stored value is `SHA-256(pepper ":" token)`, so D1 holds no raw token.
- **Without the pepper, nothing can be derived.** HMAC is a PRF, so knowing one's own token reveals nothing
  about anyone else's.
- **The new thing it adds:** every subscriber now holds a known-message HMAC output. That is an **offline
  oracle for brute-forcing the pepper**, which the old random tokens never gave. The pepper is safe only if it
  is high-entropy. The runbook suggests `openssl rand -hex 32` (`README.md:211`), but the code enforces only 16
  characters and does not check `TOKEN_PEPPER_PREVIOUS` at all (F-N6). A recovered pepper would allow mass
  unsubscription, and an unsubscribe-endpoint oracle for whether an address has signed up.
- **Timing and enumeration.** The `TOKEN_PEPPER_PREVIOUS` fallback adds a second D1 lookup only on a miss
  under the current pepper. Every invalid token and every previous-pepper token takes the same 2-lookup path,
  so the difference reveals nothing an attacker without the pepper could use. The signup path is unchanged:
  its enumeration and timing uniformity was established in round 3, and all case-dependent work is still in
  `waitUntil`.
- **Defect:** after a rotation, new emails to existing rows carry a dead link (**F-S7**, reproduced below).

**`git log -S` invocation** (`k2-count.mjs:375-379`):

- It is `execFileSync("git", [..., "-S", address, "--", path])`: argv elements only, no shell, so shell
  metacharacters cannot be interpreted. `EMAIL_TOKEN_RE` also admits none.
- **Option-injection probe:** addresses `-d@x.com`, `-p@x.com` and `--all@x.com` were listed before day 0.
  All were excluded correctly. git 2.43 takes the next argv element as `-S`'s required value, even when it
  starts with `-`. `--output=@x.com` is rejected by the bullet parser ("does not contain exactly one parseable
  email address"), exit 1.
- **Semantic defect:** the pickaxe counts **case-sensitive substrings**, not addresses (**F-S3**).

**Relation ring assembly:**

- It is robust to split, reversed and scrambled members and to multiple outer rings (probes above).
- Open chains that never close are treated as implicitly closed. For a relation with a gap, that means a
  chord. It only affects malformed data.
- Members with an empty role are ignored (F-N2).

**Round-window parser:** see **F-S6** and F-N5.

**Live X5 path** (local stub endpoint):

| input | result |
|---|---|
| `X5_CONTACT` unset | every live run crashes (**F-S5**) |
| `X5_CONTACT` set | coverage → `1/1 PASS`, exit 0; `n-osm` → `N_osm 18`, exit 0 |
| `remark` in response | exit 1 |
| HTML body | exit 1 |

---

## 4. Findings still open

| id | severity | file:line | finding | fix |
|---|---|---|---|---|
| **F-S1** | **SHOULD-FIX** (X5 correctness; must be settled before the first X5 run) | `tools/p0/src/x5-overpass.ts:248-253` (comment `:236-240`); `tools/p0/README.md:174`; test `x5-overpass.test.ts:136` | **The match rule does not follow Addendum F's literal text.** F: a polygon matches "when **either** (a) the course's known point lies inside the polygon, **or** (b) the names match **and** the shortest distance from the course's point to the polygon is ≤ 500 m". The code returns `null` as soon as a `knownPoint` is outside every polygon, and never tries (b). The README adds "with no known point", which F does not say. The code cites X5.md's older "when no point is available" wording. But the code's own header (`:181`) says F supersedes X5.md where they differ. **Probe:** knownPoint 50 m outside a same-named polygon → `null`. F literal → match. This is kill-biased. It is the likely case whenever X2's point is a clubhouse or street address just outside the `leisure=golf_course` outline. It is the B-2 failure mode, reached through the known-point path. | Choose one before any X5 data: (i) implement F literally, trying (b) whenever (a) fails; or (ii) add a dated addendum saying "(b) applies only when X2 supplies no known point", and state which X2 fields make a "known point" (B-3 residual). Then make the README and the test say what was chosen. |
| **F-S2** | **SHOULD-FIX** (K2 correctness, pass-favouring) | `apps/signup-worker/scripts/k2-count.mjs:435-437`; `src/k2-blame.ts:83-99`; the claim at `README.md:305` | **Deleting an excluded address after day 0 still un-excludes it, silently.** F: "found from the file's full history (`git log -S`), so later reformatting **or deletion** does not change it". The candidate set is only the addresses in the **current** K2.md, so a deleted address is never looked up. **Real-git probe (S5):** `a@x.com` and `b@x.com` committed 10-05, day 0 10-10, `a@` line deleted 10-20 → "excluded addresses (1): b@x.com", `a@` counts, and the output never mentions it. The README says "or even its deletion cannot change when the address first appeared". That is true of the date and false of the outcome. | Build the candidate set from history, not from HEAD. Parse the Excluded section (same parser) at every revision of `docs/p0/K2.md` (`git log --format=%H -- docs/p0/K2.md` + `git show <sha>:docs/p0/K2.md`) and take the union. Then date each address as now. Print addresses that are excluded but no longer listed. Add an S5 case to `k2-git-integration.test.mjs`. |
| **F-S3** | **SHOULD-FIX** (K2 correctness) | `apps/signup-worker/scripts/k2-count.mjs:375-378` | **The pickaxe matches raw case-sensitive substrings, not the parsed address.** (a) The parser lower-cases (`:261`), but `-S` runs on the lower-cased string. **Probe:** `- A@X.com` committed 10-05, day 0 10-10 → "not excluded (first committed on/after day 0, or no commit history found)", so the address counts. `git log -i -S a@x.com` finds the commit. (b) `-S a@x.com` also counts occurrences inside a longer address. **Probe:** `ba@x.com` listed 10-05, `a@x.com` first added 10-20 → **both excluded**. (a) inflates the count; (b) deflates it. Both exit 0. | Date by parsed identity, not by pickaxe. The per-revision parse from F-S2 gives each address's first revision directly, with the same lower-casing and decoration stripping the count uses. That removes both (a) and (b). At minimum, add `-i` and reject a candidate whose earliest `-S` commit does not contain it as a whole token. |
| **A-6** (open) | SHOULD-FIX (K2, +1 address) | `apps/signup-worker/README.md:251-265`; `docs/p0/K2.md:54-58` | Following step 9 on one UTC day still counts the test address. Probe in §1. | Require the exclusion commit and push on a UTC date **before** the e2e test day. |
| **F-S4** | SHOULD-FIX (auditability) | `tools/p0/src/x5-overpass.ts:486,509` vs `:476,494-501`; `tools/p0/README.md:186-188`; `:433-444` | **The saved live responses cannot be replayed by the tool.** Live mode writes `{key: {query, fetchedAt, response}}`, but `--responses` uses each value as an Overpass response directly. **Probe:** a live run (stub endpoint) writes `live-responses.json`. `coverage --responses live-responses.json` then gives "unparseable — missing an "elements" array", exit 1. The README says the file is "keyed the same way `--responses` expects". Separately, `n-osm` saves neither the raw response nor N_osm (F: "every live response is saved"). It fails loudly, so the verdict is not corrupted. | Accept both shapes in `--responses` (unwrap `.response` when present), or save unwrapped values with a sidecar for the metadata. Add a live-save → replay round-trip test. Have `n-osm` write `<out>-n-osm.json` (query, timestamp, raw response). |
| **F-S5** | SHOULD-FIX (the live X5 path is broken by default) | `tools/p0/src/x5-overpass.ts:44,46-49,402` | **The default User-Agent is not a ByteString, so every live run crashes when `X5_CONTACT` is unset.** `DEFAULT_CONTACT` contains "—" (U+2014), and `fetch` rejects header values above 0xFF. **Probe:** `coverage` against the stub with no `X5_CONTACT` → "Cannot convert argument to a ByteString because the character at index 116 has a value of 8212", exit 1. The message does not point at the cause. `n-osm` fails the same way. The README says the default "defaults to a generic project URL". It fails closed, so no verdict is wrong. | Use ASCII only in `DEFAULT_CONTACT`. Reject a non-Latin-1 `X5_CONTACT` with a clear message. Add a test that constructs a `Headers` from `buildUserAgent()`. |
| **F-S6** | SHOULD-FIX (X1 correctness under a logging typo, kill-biased) | `tools/p0/src/round-windows.ts:23-24,59-63,82-86,105-113` | **A malformed or reversed window is accepted, then silently matches nothing, and the "none logged" refusal does not fire.** The regex admits any `\d{2}` hour, and ordering is never checked. `isWithinRoundWindow` quietly treats a `NaN` bound as "no match". **Probes:** `13:00:00Z to 25:30:00Z` → parsed (1 window), so no refusal, and a 14:00Z workout → **not in window**. `17:30Z to 13:00Z` → parsed, and nothing ever matches. `x1-ios-export` then only warns "N excluded", `x1-verdict` reports `fail-not-written` → KILL, exit 0. The same file otherwise refuses on bad input. | In `parseRoundWindows`, round-trip each bound (`toISOString` equality, as `config.ts:194` does), require `end > start`, and throw on any line in the section that matches neither a valid window nor blank or placeholder text. |
| **F-S7** | SHOULD-FIX (the one-click unsubscribe must work in every email; only after a pepper rotation) | `apps/signup-worker/src/index.ts:303,502-510`; `README.md:103-125` | **After the documented `TOKEN_PEPPER` rotation, every new email to an existing row carries a dead unsubscribe link.** A row keeps `unsubscribe_token_hash = SHA256(old : HMAC(old, email))` forever. A resend after rotation emails `HMAC(new, email)`, which hashes to neither stored value. **Probe:** sign up under the old pepper, rotate (PREVIOUS = old), resend → **new email's unsubscribe 400**, old email's → 200. After `TOKEN_PEPPER_PREVIOUS` is unset, the row can **never** be unsubscribed by any link (probe: 400). This is A-2's defect again, reached through the runbook the README presents as safe. | When sending to an existing row, email the derivation that matches the row's stored hash: try the current pepper, then the previous. That keeps one link per row for the row's lifetime. Alternatively, put the row id in the link and verify `token == HMAC(current\|previous, row.email_lc)` in constant time. Add a "rotate, then resend, then use the new email's link" test. Correct the README's cutover advice. |
| F-N1 | NIT | `tools/p0/src/overpass-geo.ts:213-218` | The point-to-edge distance uses a flat 111 320 m/deg. The haversine value for the same pair is 499.44 m where the code reports 500.00 m. That is up to about 0.1–0.3 %, or ≤ 2 m at the 500 m boundary, in the kill direction. | Use 111 195 m/deg (R = 6 371 km, matching `haversineMeters`), or compute the final distance with haversine. |
| F-N2 | NIT | `overpass-geo.ts:172` | A relation member with an empty `role` (legacy multipolygon tagging) is ignored. The probe gives `null`. It is rare in current OSM. | Treat `role === ""` as `outer` when the relation has no `outer` members, and warn. |
| F-N3 | NIT | `x5-overpass.ts:175` | A missing `golf=hole` count element is still recorded as 0 (B-4 d). It is quality-only. | Record `null` (unknown). |
| F-N4 | NIT | `overpass-geo.ts:246` | Only combining marks U+0300–036F are stripped. Other combining blocks become spaces (`a᪰b` → `a b`). This is irrelevant for US/CA course names. | Strip `\p{M}` after NFKD. |
| F-N5 | NIT | `round-windows.ts:61`; `x1-verdict.ts:241-244` | Only the first window on a line is read. `x1-verdict`'s own window filter drops records without adding a warning. | Use `matchAll`, or refuse a second window on one line. Push a count of dropped items into `warnings`. |
| F-N6 | NIT | `apps/signup-worker/src/config.ts:260,283` | Now that each subscriber's own token is an offline oracle for the pepper, the 16-character minimum is the only enforced strength. `TOKEN_PEPPER_PREVIOUS` is not length-checked. | Require ≥ 32 characters for both. Say in the README that the pepper must be random, not a passphrase. |
| F-N7 | NIT | `tools/p0/src/health-export-xml.ts` | B-8 residual: GPX files in `workout-routes/` that no workout references are not checked. | Count them and throw if the count is non-zero (round-3 fix, second half). |
| F-N8 | NIT | `apps/signup-worker/test/k2-git-integration.test.mjs:25,64` | The only real-git K2 test skips itself when `dist/` is absent. So `pnpm -r test` without a prior build passes without running it. | Build inside the test's `beforeAll`, or fail when `CI` is set and `dist/` is missing. |

**Totals, open:** 0 BLOCKING, 8 SHOULD-FIX (F-S1 to F-S7 plus the A-6 residual), 8 NIT.

## Verdict

Both round-3 BLOCKING findings (B-1 relation geometry, B-2 polygon distance) are closed, and so are the
signup-worker regressions (A-1, A-2, A-3, N1, N2). The build, typecheck and tests are green, and the tree is
left clean.

Three open SHOULD-FIX findings bear directly on the correctness of a pre-registered verdict, and they conflict
with Addendum F's literal text:

- **F-S1:** X5's either/or match rule.
- **F-S2:** a K2 exclusion is still lost when the address is deleted after day 0.
- **F-S3:** the case-sensitive substring pickaxe mis-dates K2 exclusions.

The A-6 runbook residual and F-S6 (X1 window typo → silent kill) also bear on K2 and X1. F-S7 breaks the
unsubscribe guarantee after a pepper rotation. Every one of these is cheap to fix, and none needs data to
exist first.

PR: FIX REQUIRED
