# @golfraven/catalog-tools

Catalog governance CLIs for the P1 catalog contract (build plan §3.5,
§4.1, §10 P1, §15): `verify-catalog` and `verify-contract`. Kept out of
`packages/catalog` deliberately — that package "Never does: Hold data or
fetch" (build plan §3.1 row A), and these two tools read `data/`-shaped
input and write `contract/catalog.schema.json`.

## Build ordering (gate-review fix, post-e9b3ab0)

This package depends on `@golfraven/catalog`'s compiled `dist/` output.
Both `tsconfig.json` (typecheck) and `tsconfig.build.json` (build) declare
a TypeScript **project reference** to
`../../packages/catalog/tsconfig.build.json`, and both scripts run via
`tsc -b`. That means `tsc` builds `packages/catalog` first automatically
whenever it's missing or stale — typechecking or building this package
alone, from a clean checkout with no `dist/` anywhere, works without
needing `pnpm -r build` to have run first in some particular order.
`.github/workflows/ci.yml` still runs Build before Typecheck as a second,
belt-and-suspenders safeguard.

## `verify-contract`

Generates `contract/catalog.schema.json` from `@golfraven/catalog`'s Zod
schema (via Zod v4's native `z.toJSONSchema`) and checks the committed file
against it (build plan §3.5: "CI regenerates `contract/catalog.schema.json`
and fails on any diff").

```shell
# Check (default) — exits 1 if the committed file is missing or stale.
node dist/verify-contract.js

# Regenerate the committed file.
node dist/verify-contract.js --write

# Point at a different file (mostly for tests).
node dist/verify-contract.js --contract-path /path/to/file.json
```

Wired into `pnpm -r test` (`test/contract-freshness.test.ts` checks the
real committed file) and into CI directly (`.github/workflows/ci.yml`),
so a stale schema fails the build both ways.

## `verify-catalog`

The P1 AT(1)/(5)/(7)/(8) gate — every rule listed in build plan §10 P1's
Acceptance tests that concerns catalog records (the `RuleExpr`/achievements
fixtures are part B, `packages/rules`, per this task's own scope cut).

Takes a **catalog bundle** — one self-contained JSON file holding every
facility, trail, designer, offerTerms and the ID ledger a check run needs
(see `src/bundle.ts`'s module doc for why this, rather than scanning a
multi-file `data/` tree, is P1a's input format).

```shell
node dist/verify-catalog.js --bundle path/to/bundle.json

# The geometry-diff, contact-field-diff, roster-version-immutability and
# ledger-append-only gates need the last published catalog to diff against:
node dist/verify-catalog.js --bundle current.json --base previous.json

# PR labels for this run (geometry-reviewed / contact-reviewed):
node dist/verify-catalog.js --bundle current.json --base previous.json --labels geometry-reviewed,contact-reviewed

# Override the booking-host allow-list (defaults to config/booking-hosts.json):
node dist/verify-catalog.js --bundle current.json --booking-hosts path/to/hosts.json
```

Exits 0 and prints `PASS` with no issues; otherwise exits 1 and prints
every issue as `[CODE] path: message`.

### Self-approval fix (gate review, post-e9b3ab0, blocking #2)

Earlier, a bundle could carry its own `labels[]` and `bookingHostAllowList[]`
fields — meaning a PR could assert its own `geometry-reviewed`/
`contact-reviewed` review labels, or add its own booking host to its own
allow-list, and pass its own gate. Neither is possible any more:

- **Labels** come only from the CLI's `--labels` flag (real PR labels, set
  by CI from the actual GitHub PR — e.g.
  `--labels "${{ join(github.event.pull_request.labels.*.name, ',') }}"`).
  An omitted flag and an explicitly empty `--labels ""` both mean "no
  labels" — there is no other source to fall back to.
- **The booking-host allow-list** comes only from the committed
  `config/booking-hosts.json` (`src/config.ts`), synthetic/test hosts only
  for now (the real list waits on X4/X6, decision 0003 S2's carve-out).
- `CatalogBundleSchema` (`src/bundle.ts`) no longer even has `labels` or
  `bookingHostAllowList` fields — a bundle carrying either is rejected
  outright (`SCHEMA_INVALID: Unrecognized key`). `mf-bundle-cannot-self-label`
  and `mf-bundle-cannot-self-allow-booking-host` prove it.

### `OfferTerms` (S6, gate review post-e9b3ab0)

`OfferTerms` needs no `RuleExpr` (only DB-side offer *instances* do, §4.1)
and is implemented in `packages/catalog`. `bundle.offerTerms[]` carries any
for a run; `OFFER_TERMS_QC_MISSING_FR` fires when one is linked to a trail
whose `regions` include `CA-QC` and it has no `termsFr`.

### `tz` "wrong zone" (blocking #3, gate review post-e9b3ab0)

No longer a longitude heuristic. `@golfraven/catalog`'s `tzLikelyContainsCoordinates`
uses the pinned `tz-lookup@6.1.25` npm package (CC0-1.0, ~152 KB, zero
deps; boundary data vintage: "last updated on 6 Jan 2019" per its own
README) — see `packages/catalog/src/geo.ts`'s module doc for the full
license/vintage/size writeup. `IanaTimeZoneSchema` (name-only validity)
also no longer uses `Intl.supportedValuesOf('timeZone')`; it uses
`new Intl.DateTimeFormat('en', { timeZone })` in a try/catch, which is
more portable across runtimes/ICU versions. A **stub** facility (no
`lat`/`lng` of its own) is checked using its joined OSM coordinates
(`bundle.osm[facility.seed.osmRef]`, plan line 578).

### Cross-reference checks (S4, gate review post-e9b3ab0)

`checkCrossReferences` in `verify-catalog.ts` adds: `CROSS_REF_DANGLING_HOLE_ID`,
`CROSS_REF_DANGLING_ANYOF_ID`, `CROSS_REF_COMPOSITE_DANGLING`,
`CROSS_REF_UNKNOWN_DESIGNER`, `CROSS_REF_ID_NOT_IN_LEDGER`,
`CROSS_REF_SLUG_MISMATCH`, `LEDGER_KEY_MISMATCH`,
`ROSTER_DUPLICATE_VERSION_NUMBER`. With `--base`, the ledger itself must be
append-only: `LEDGER_ENTRY_REMOVED` (an id disappeared), `LEDGER_UNTOMBSTONED`
(a tombstone was reversed), `LEDGER_TRANSITIONS_NOT_APPEND_ONLY` (a base
entry's `transitions[]` is not a prefix of the current one's), and
`ROSTER_TRAIL_REMOVED` (a published trail vanished).

### Geometry gate (S1, gate review post-e9b3ab0)

Two checks, both under `GEOMETRY_DIFF_UNREVIEWED`, both needing `--base`
and the `geometry-reviewed` label: a **coordinate-move** check
(`Facility.lat`/`lng` moved > 150 m — the renamed original check) and a
**field-change** check (any change to a course's `geometry.ref`/`file`/
`layer`/`checkedAt`/`sharedWithFacility`). **TODO, tied to the geometry
pipeline:** area-change (> 25%) is not implemented — it needs real
polygon data from `scripts/seed-osm.mjs`'s geometry pipeline (`data/osm/geometry/*`),
which is out of P1a's scope (no real data, no network fetch).

### `https:`-only URLs (S7)

`Facility.url` and `booking[].url` are `HttpsUrlSchema` — `http:`,
`javascript:` and any other scheme fail at parse time (`SCHEMA_INVALID`).

### Fixtures

`test/fixtures/*.json` — one committed bundle per AT(1) must-fail case
(`mf-*.json`, each test asserting the **exact** set of `{code, path}`
issues it produces — S5, gate review post-e9b3ab0 — never just "it
fails"), the must-pass cases (`mp-*.json`), and AT(5)'s "way→relation
remap" / "never overwrites a verified field" / "whole-ledger already-known
lookup" cases as raw OSM-input fixtures (`at5-*.json`, consumed directly
by `@golfraven/catalog`'s `reseedFacility`, not through `verify-catalog`
itself). Every id in every fixture is synthetic — see the repo root
README and `data/README.md` for why no real course or trail data lives
anywhere in this phase.

**S10 (gate review, post-e9b3ab0): AT(5) needs strengthening once
`seed-osm` exists.** `at5-reseed.test.ts`'s fixtures are hand-built ledger
states and OSM-input objects, which prove `reseedFacility` itself is
correct. They do not exercise the real `scripts/seed-osm.mjs` pipeline
(P1.1+, out of P1a scope) end to end — a skipped test,
`[STRENGTHEN ONCE seed-osm EXISTS] a re-seed of records seed-osm.mjs
actually emits never overwrites a verified field`, is left in that file
under exactly that name so it shows up in `vitest run`'s skip list as a
standing reminder, rather than this limitation only living in a report.
