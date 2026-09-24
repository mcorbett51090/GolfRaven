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

## Round 2 (gate review, post-2ad202f)

- **Time zones.** `packages/catalog/src/geo.ts`'s `tzLikelyContainsCoordinates`
  now (1) canonicalizes both `tz-lookup`'s answer and the facility's
  declared `tz` through a vendored tzdb backward-links table
  (`packages/catalog/src/tzdb-backward-links.json`, pinned to tzdb
  `2026d`, sourced from the `tzdata-backward` npm package), so a legacy
  alias (`America/Indianapolis`) or a pre-2022-merge Canadian name
  `tz-lookup`'s bundled data still returns (`America/Thunder_Bay`,
  `America/Pangnirtung`) compares equal to its modern canonical name; and
  (2) accepts a ~5 km border tolerance by also looking up 4 points offset
  north/south/east/west of the declared coordinate, so a point `tz-lookup`'s
  simplified polygons misattribute near a real boundary (Rainy River, ON
  reads as `America/Chicago`) still passes if the correct zone shows up
  within 5 km. `IanaTimeZoneSchema` no longer uses
  `Intl.supportedValuesOf('timeZone')`.
- **`TZ_UNVERIFIABLE`.** A facility with no coordinates of its own AND no
  OSM join now fails closed with this code, instead of the tz check being
  silently skipped.
- **Merge re-parenting (§4.2 row 2).** `mergeIntoSurvivor` now moves a
  merged facility's course(s) under the survivor (updates each course's
  `facilityId` link; the course's own id never changes).
  `findLedgerIdBySeedRef` prefers the course entry that actually carries a
  ref (resolved through its own `mergedInto`), so a survivor with more
  than one course (its own + a re-parented one) resolves each ref to the
  RIGHT course, not just "any" course under that facility.
- **Ledger append-only, extended.** `checkLedgerAppendOnly` also forbids
  changing a published slug (`LEDGER_SLUG_CHANGED`) and removing/rewriting
  a `seedRefs[]` entry (`LEDGER_SEEDREFS_REMOVED`) vs `--base`.
- **`LEDGER_MERGE_CYCLE`.** `resolveMergedId` no longer throws on a cycle
  (it stops and returns a best-effort id); `detectMergeCycle` + a new
  `checkMergeCycles` gate check report a cycle as an ordinary issue
  instead of crashing the run.
- **Nits.** `CompositeSchema` rejects `[X, X]`; `RegionCodeSchema` now
  validates against a pinned ISO 3166-2 US/CA list
  (`packages/catalog/src/region-codes.json`, 69 codes) instead of a
  shape-only regex; `ROSTER_LATEST_CONTAINS_CLOSED_FACILITY` catches a
  closed Facility in the latest roster (previously only `Course.closed`
  was checked).

## `emit-catalog` and `verify-artifact` (P1 part B-2: artifact emitter + signing)

The build plan's artifact emitter and Ed25519 `kid` signing (§3.3 "Catalog
flow", §3.5 "Signing", §4.1 "ODbL layer split", §4.8 "Keys, secrets and
rotation", §10 P1 AT(2): "The signature verifies per `kid`, a tampered
shard fails, and a manifest whose `kid` is in `revokedKids` is refused.").
Three modules, split by concern:

- `src/manifest.ts` — the `CatalogManifest`/`VersionEntry` shapes,
  deterministic canonical-JSON (`canonicalStringify`, sorted object keys),
  and the `versions.json` append-only checks (`assertVersionsAppendOnly`,
  `appendVersion`).
- `src/sign.ts` — Ed25519 signing/verification over `node:crypto` only (no
  dependency added), `signManifest`, and `verifyArtifact(dir, trustedKeys)`
  — the AT(2) gate itself. Also the `verify-artifact` CLI.
- `src/emit-catalog.ts` — `emitCatalogArtifact(bundle, opts)`, which writes
  the signed `catalog/v1/*` tree to a caller-supplied output directory, and
  the `emit-catalog` CLI.

### Artifact tree

```
<out>/catalog/v1/
  manifest.json        # unsigned; contractVersion, catalogVersion, minAppVersion, kid, revokedKids[], shards[]
  manifest.sig.json     # {catalogVersion, manifestSha, kid, sig} — mirrors §3.3's manifestSig shape
  versions.json          # append-only: [{version, publishedAt, kid, sha256}, ...]
  trails.json
  id-ledger.json         # the FULL ledger, for the import function (§3.3)
  designers.json          # only if bundle.designers is present
  offer-terms.json        # only if bundle.offerTerms is present
  facilities/<ISO-region>.json   # sharded by region (§5.2: "Directory JSON is sharded by ISO region")
  osm/content.json        # only if bundle.osm is present — separately licensed, ODbL-1.0 (§4.1)
  osm/ATTRIBUTION.txt      # ditto
```

Every shard in `manifest.json`'s `shards[]` carries its `path`, `sha256`
and `bytes`; an `osm/*` shard also carries `license: "ODbL-1.0"`. Output is
deterministic: object keys are sorted recursively, arrays are sorted by
`id` (or `path`, for the shard list) before being written, and
`revokedKids[]` is sorted too — two emits of the same bundle with the same
options are byte-identical (`test/emit-catalog.test.ts`).

### Signing key (never in the repo)

`emit-catalog` takes the Ed25519 private key from `--key-file <path>` or,
if that's omitted, the `GOLFRAVEN_CATALOG_SIGNING_KEY` env var (PEM text;
literal `\n` escapes are un-escaped automatically, since most CI secret
stores can't hold a real multi-line value in one variable). Neither
defaults to anywhere inside this repo. **The real signing key lives only
in a protected CI environment** (§4.8: "Signing runs in a GitHub protected
environment with required reviewers... Actions are SHA-pinned") — nothing
here ever writes a key to disk or logs its contents, and every test
generates its own throwaway keypair in-process
(`crypto.generateKeyPairSync('ed25519')`).

**Pre-P3 keyset (§3.5).** "P1–P2 ... sign with a pre-P3 keyset that no app
build ever compiles in." Every `kid` produced by this emitter before the
P3 gate is one of those pre-P3 keys; at the P3 pre-build gate, the
production keyset is generated under the §4.8 runbook and every pre-P3
`kid` is added to `revokedKids[]` before the first app build or production
import. Nothing in this module hard-codes that transition — it's a
run-time argument (`--kid`, `--revoked-kids`) supplied by whoever runs the
emitter at that gate.

### CLI usage

```shell
# Emit an artifact from a verified bundle (verify-catalog's bundle shape):
node dist/emit-catalog.js \
  --bundle path/to/bundle.json \
  --out dist/artifact \
  --key-file /path/outside/the/repo/signing-key.pem \
  --kid pre-p3-key-1 \
  --min-app-version 0.1.0 \
  --catalog-version 20260101-abc0001 \
  --revoked-kids old-kid-1,old-kid-2 \
  --previous-versions path/to/last-published/versions.json

# Or with the key from the env instead of --key-file:
GOLFRAVEN_CATALOG_SIGNING_KEY="$(cat signing-key.pem)" node dist/emit-catalog.js \
  --bundle path/to/bundle.json --out dist/artifact \
  --kid pre-p3-key-1 --min-app-version 0.1.0 --catalog-version 20260101-abc0001

# Verify a previously emitted artifact against a trusted keyset:
node dist/sign.js --dir dist/artifact --trusted-keys path/to/trusted-keys.json
# <trusted-keys.json> is [{"kid": "...", "publicKeyPem": "..."}, ...]
```

`emit-catalog` never writes anywhere but `--out`; it never defaults `--out`
to a path inside this repo, and no test in this package writes into
`dist/catalog` in the repo — every test uses `os.tmpdir()`.

### Tests → AT(2)

`test/sign.test.ts`'s "AT(2) — verifyArtifact over a real emitted
artifact" suite emits a real artifact (via `emitCatalogArtifact`) and then
verifies it, covering: a valid verify; a tampered shard; a tampered
manifest (edited in place, still valid JSON); a signature that fails
against a swapped-in wrong public key for a trusted `kid`; an unknown
`kid`; and a manifest whose `kid` is in its own `revokedKids[]` (the
literal AT(2) fixture) — plus that a *different* `kid` appearing in
`revokedKids[]` does NOT, by itself, refuse this manifest (see "Resolved
ambiguities" below). `test/manifest.test.ts` covers `versions.json`
append-only at the unit level (drop / rewrite / reorder, each refused) and
`test/emit-catalog.test.ts` covers it at the integration level (two real
emits into the same `outDir`, and via `--previous-versions`).

### Resolved ambiguities

- **What "a manifest whose `kid` is in `revokedKids` is refused" means.**
  AT(2)'s wording is literal: `verifyArtifact` refuses a manifest whose OWN
  signing `kid` appears in that same manifest's `revokedKids[]` (a
  self-revoking manifest). §3.5/§4.8 also describe `revokedKids[]` as how
  a *surviving* key tells the app/import function to stop trusting some
  *other*, compromised `kid` going forward across future manifests — that
  cross-manifest propagation is the app/import function's own bookkeeping
  (maintaining a running "don't trust this kid any more" set across
  imports), not something one `verifyArtifact(dir, trustedKeys)` call over
  a single directory can determine by itself, since its only inputs are
  the artifact on disk and the caller-supplied `trustedKeys`.
- **Shard layout: region, not geohash.** The task's build step names both
  ("geohash-sharded or per-entity JSON shards, as the plan describes").
  The plan shards geometry by geohash specifically because raw polygon
  data can be large per region (§5.2); this bundle format carries no
  geometry payload (`Course.geometry` is a pointer, not inline polygon
  data — the geometry pipeline is P1.1+, already out of `bundle.ts`'s
  scope). `facilities/<ISO-region>.json` shards by region instead, which
  §5.2 already names directly ("Directory JSON is sharded by ISO region").
- **`--catalog-version` is a required, explicit flag**, not computed from
  `git rev-parse` inside the emitter. The plan's format is
  `yyyymmdd-gitsha7` (§3.5), but making the emitter shell out to git would
  couple it to running inside a git checkout with a readable `HEAD` for no
  testability benefit; the CLI's caller (CI) is better positioned to
  compute it and pass it in.
- **`versions.json`'s append-only check is scoped to what this run can
  see** — the file already at `<outDir>/catalog/v1/versions.json`, or
  `--previous-versions` if given. There's no persistent store this module
  reads from on its own; a CI pipeline that wants the full history
  enforced needs to seed one of those two inputs from the last publish.
