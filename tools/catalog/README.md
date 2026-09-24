# @golfraven/catalog-tools

Catalog governance CLIs for the P1 catalog contract (build plan §3.5,
§4.1, §10 P1, §15): `verify-catalog` and `verify-contract`. Kept out of
`packages/catalog` deliberately — that package "Never does: Hold data or
fetch" (build plan §3.1 row A), and these two tools read `data/`-shaped
input and write `contract/catalog.schema.json`.

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
facility, trail, designer and the ID ledger a check run needs (see
`src/bundle.ts`'s module doc for why this, rather than scanning a
multi-file `data/` tree, is P1a's input format).

```shell
node dist/verify-catalog.js --bundle path/to/bundle.json

# The geometry-diff, contact-field-diff and roster-version-immutability
# gates need the last published catalog to diff against:
node dist/verify-catalog.js --bundle current.json --base previous.json

# PR labels for this run (geometry-reviewed / contact-reviewed) — a
# bundle may also carry its own `labels[]` for a self-contained fixture:
node dist/verify-catalog.js --bundle current.json --base previous.json --labels geometry-reviewed,contact-reviewed
```

Exits 0 and prints `PASS` with no issues; otherwise exits 1 and prints
every issue as `[CODE] path: message`.

### Fixtures

`test/fixtures/*.json` — one committed bundle per AT(1) must-fail case
(`mf-*.json`, each asserted against its own specific issue code, never
just "fails"), the must-pass cases (`mp-*.json`), and AT(5)'s "way→relation
remap" / "never overwrites a verified field" cases as raw OSM-input
fixtures (`at5-*.json`, consumed directly by `@golfraven/catalog`'s
`reseedFacility`, not through `verify-catalog` itself). Every id in every
fixture is synthetic — see the repo root README and `data/README.md` for
why no real course or trail data lives anywhere in this phase.
