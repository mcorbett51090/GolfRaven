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
flow", §3.3(ii) the `manifestSig` shape, §3.5 "Signing", §4.1 "ODbL layer
split", §4.8 "Keys, secrets and rotation", §10 P1 AT(2)).

**Rewritten after an Opus security-gate review of the first version
(commit 7692919, 4 blocking findings).** The load-bearing correction: a
verifier must check the EXACT raw bytes that were signed, never a
re-serialized/re-canonicalized form of a parsed object — re-canonicalizing
before hashing would silently absorb a whitespace-level tamper, since
re-serializing normalizes it back to the same canonical bytes. Everything
below reflects the rewritten design; the four "Blocking" fixes are cited
by finding number where relevant.

- `src/manifest.ts` — shapes (`CatalogManifest`, `VersionEntry`, the
  domain-separated statements), Zod schemas for all of them, a
  **hand-rolled strict JSON parser** (`parseStrictJson`) that rejects
  duplicate keys, `__proto__`/`constructor`/`prototype` keys, and `-0`
  at parse time (`JSON.parse` can't catch duplicates — they've already
  collapsed to "last wins" by the time you have an object), deterministic
  canonical-JSON (`canonicalStringify`, code-point key order, rejects
  non-finite numbers and `-0`), and `versions.json` append-only checks.
- `src/sign.ts` — Ed25519 over `node:crypto` only (no dependency added):
  `signManifest`/`signVersions` (each builds and signs a small,
  domain-separated statement) and `verifyArtifact(dir, opts)` — the AT(2)
  gate. Also the `verify-artifact` CLI.
- `src/emit-catalog.ts` — `emitCatalogArtifact(bundle, opts)`: validates
  and signs everything **in memory first**, then writes the whole tree to
  a temp directory and atomically renames it into place. Also the
  `emit-catalog` CLI.

### Artifact tree

```
<out>/catalog/v1/
  manifest.json              # contractVersion, catalogVersion, minAppVersion, kid, revokedKids[], generatedAt, shards[]
  manifest.sig.json           # {catalogVersion, contractVersion, kid, manifestSha, sig} — the §3.3(ii) statement + sig
  versions.json                # append-only: [{version, publishedAt, kid, sha256}, ...]
  versions.sig.json             # {kid, versionsSha, sig} — versions.json's OWN signature (finding #4)
  trails.json
  id-ledger.json                 # the FULL ledger, for the import function (§3.3)
  designers.json                  # only if bundle.designers is present
  offer-terms.json                 # only if bundle.offerTerms is present
  facilities/<region>.json          # sharded by region, path lower-cased (facilities/us-tn.json)
  osm/directory/<region>.json        # ODbL-1.0, sharded by the region of the referencing facility/course
  osm/attribution.txt                 # ODbL-1.0 attribution text
```

Every shard in `manifest.json`'s `shards[]` carries `path`, `sha256` and
`bytes`; an `osm/*` shard also carries `license: "ODbL-1.0"`. Shard paths
are validated against `^[a-z0-9][a-z0-9/_.-]*\.(json|txt)$` (no `..`, never
absolute) — the shard-path VALUE inside a facility record is untouched
(still upper-case `"US-TN"`); only the on-disk filename is lower-cased, to
satisfy that allowlist. Output is deterministic: object keys sorted by
code point, arrays sorted by `id`/`path` before writing, `revokedKids[]`
sorted — two emits of the same bundle with the same `--generated-at` are
byte-identical (`test/emit-catalog.test.ts`).

### Signing scheme (findings #1, #2)

Nothing signs or verifies `manifest.json`'s bytes directly. Instead:

1. `manifestSha` = sha256 of `manifest.json`'s raw bytes.
2. The **statement** `{catalogVersion, contractVersion, kid, manifestSha}`
   is canonicalized and prefixed with a domain tag —
   `"golfraven/catalog/v1/manifest\n"` — before signing.
3. `manifest.sig.json` carries the statement's fields plus `sig`.

`versions.json`/`versions.sig.json` follow the same pattern with their own
domain tag (`"golfraven/catalog/v1/versions\n"`) and a `{kid, versionsSha}`
statement, so a `versions.json` signature can never be replayed as a
manifest signature or vice versa.

**`verifyArtifact` reads `manifest.json`'s raw bytes, hashes THOSE, and
compares to `manifest.sig.json`'s `manifestSha` — it never re-derives
canonical bytes from a parsed object and checks the signature against
that.** A byte-for-byte-identical whitespace change, a duplicate JSON key,
an injected `__proto__` key, and a `-0` numeric literal are each their own
probe test in `test/sign.test.ts` / `test/manifest.test.ts`.

### Revocation (finding #3)

`verifyArtifact(dir, { trustedKeys, revokedKids, minCatalogVersion?,
supportedContractMajor? })` — `revokedKids` is a `Set<string>` (or array)
the CALLER maintains: the verifier's own compiled denylist, unioned with
every `revokedKids[]` a *previous* `verifyArtifact` call already accepted.
On success, the result carries `revokedKids: string[]` — the just-verified
manifest's own list — so the caller can union it in before the next run.
Two refusal paths, both named `REVOKED_KID`: the manifest's signing `kid`
is in the CALLER's `revokedKids` set (catches a compromised key that
leaves itself off its own manifest's list — §3.5's actual threat model),
and separately, the manifest lists its own signing `kid` in its own
`revokedKids[]` (a self-revoking manifest — AT(2)'s literal fixture).

### Write-to-temp-then-rename (finding #4)

`emitCatalogArtifact` runs every check — schema validation, the
canonical-round-trip self-check, both signatures, `versions.json`
append-only (strict-increase, finding #5) — **before opening a single
file for writing**. The whole tree is then written under
`catalog/.v1.tmp-<random>/`; any existing `catalog/v1/` is renamed to a
`.v1.backup-<random>` sibling; the temp dir is renamed into `catalog/v1/`;
the backup is removed only after that succeeds. A failure during the
write-to-temp phase cleans up the orphaned temp dir and leaves
`catalog/v1/` completely untouched; a failure at the final rename rolls
the backup back into place. `test/emit-catalog.test.ts` proves this with a
genuine mid-write failure (a mocked `node:fs/promises.writeFile` that
throws on its second call — this session runs as `root`, where a
chmod-based permission-denial probe would NOT reliably fail, since root
bypasses DAC checks).

### Rollback and contract major (findings #6, #9)

`verifyArtifact`'s `minCatalogVersion` refuses anything older
(`CATALOG_VERSION_ROLLBACK`); `supportedContractMajor` refuses a
`contractVersion` that isn't an exact match (`CONTRACT_MAJOR_MISMATCH`).
`contractVersion` is a plain non-negative integer in this schema (see
`packages/catalog`'s `CONTRACT_VERSION`) and IS the "MAJOR" §3.5 describes
("A MAJOR bump publishes `/catalog/v2/`") — there's no separate
minor/patch component here to strip.

### Stray files and read-order (findings #7, #8)

The verifier walks `catalog/v1/` after the signature verifies and reports
(`STRAY_FILE`) any file not listed in `manifest.shards[]` or one of the
four root documents. Every shard is `lstat`'d first and refused if it's a
symlink (`SHARD_SYMLINK`). **No shard file is opened at all** until the
manifest's signature, `kid` trust and revocation checks have all passed —
proven by a test that deletes a shard and confirms `SHARD_MISSING` never
appears when the failure is `UNKNOWN_KID` instead.

### Keys (finding #10)

`privateKeyFromPem`/`publicKeyFromPem` both assert
`asymmetricKeyType === 'ed25519'`. `signManifest`/`signVersions`
self-check the signature against the public key derived from the private
key before returning, and — when `--kid-public-key <pem-file>` is given —
cross-check it against that expected public key, refusing to sign if they
don't match (catches "the wrong key for this `kid` label" at emit time).
`loadSigningKeyPem` refuses a `--key-file` whose mode is group- or
world-readable (`mode & 0o077 !== 0`).

### Determinism (finding #11)

`--generated-at <iso8601>` (or the `SOURCE_DATE_EPOCH` env var) pins
`generatedAt`/`publishedAt`. Absent both, the wall clock is used ONLY for
a `catalogVersion` that has never been published before; re-emitting an
ALREADY-published version with no pinned time source is refused outright
("refusing a non-deterministic re-emit...") rather than silently producing
different bytes.

### Signing key (never in the repo)

`emit-catalog` takes the Ed25519 private key from `--key-file <path>` or
the `GOLFRAVEN_CATALOG_SIGNING_KEY` env var (PEM text; literal `\n`
escapes are un-escaped automatically). Neither defaults to anywhere
inside this repo. **The real signing key lives only in a protected CI
environment** (§4.8) — nothing here ever writes a key to disk or logs its
contents, and every test generates its own throwaway keypair in-process
(`crypto.generateKeyPairSync('ed25519')`).

**Pre-P3 keyset (§3.5).** "P1–P2 ... sign with a pre-P3 keyset that no app
build ever compiles in." Every `kid` produced by this emitter before the
P3 gate is one of those pre-P3 keys; at the P3 pre-build gate the
production keyset is generated under the §4.8 runbook and every pre-P3
`kid` is added to `revokedKids[]` before the first app build or production
import — this is a run-time argument (`--kid`, `--revoked-kids`), not
hard-coded here.

### CLI usage

```shell
# Emit an artifact from a verified bundle (verify-catalog's bundle shape).
# Use an absolute path for --out — never a path inside this repo checkout.
node dist/emit-catalog.js \
  --bundle /tmp/golfraven-artifact/bundle.json \
  --out /tmp/golfraven-artifact/dist \
  --key-file /path/outside/the/repo/signing-key.pem \
  --kid-public-key /path/outside/the/repo/signing-key.pub.pem \
  --kid pre-p3-key-1 \
  --min-app-version 0.1.0 \
  --catalog-version 20260101-abc0001 \
  --revoked-kids old-kid-1,old-kid-2 \
  --previous-versions /tmp/golfraven-artifact/last-published-versions.json \
  --generated-at 2026-01-01T00:00:00Z

# Or with the key from the env instead of --key-file:
GOLFRAVEN_CATALOG_SIGNING_KEY="$(cat signing-key.pem)" node dist/emit-catalog.js \
  --bundle /tmp/golfraven-artifact/bundle.json --out /tmp/golfraven-artifact/dist \
  --kid pre-p3-key-1 --min-app-version 0.1.0 --catalog-version 20260101-abc0001

# Verify a previously emitted artifact against a trusted keyset + revoked-kids state:
node dist/sign.js --dir /tmp/golfraven-artifact/dist \
  --trusted-keys /path/trusted-keys.json \
  --revoked-kids-file /path/persisted-revoked-kids.json \
  --min-catalog-version 20260101-abc0001 \
  --supported-contract-major 0
# <trusted-keys.json> is [{"kid": "...", "publicKeyPem": "..."}, ...]
# <persisted-revoked-kids.json> is ["kid-1", "kid-2", ...] — the CALLER's
# own compiled + persisted denylist; PASS prints the manifest's own
# revokedKids[] so the caller can union it in for next time.
```

`emit-catalog` never writes anywhere but `--out`; it never defaults `--out`
to a path inside this repo, and no test in this package writes into
`dist/catalog` in the repo — every test uses `os.tmpdir()`.

### Append-only: what this module checks vs. what CI must check

`emit-catalog` enforces append-only and strict-increase (version AND
`publishedAt`) against whatever `versions.json` it can see — the file
already at `<outDir>/catalog/v1/versions.json`, or `--previous-versions`
if given; a missing or malformed `--previous-versions` THROWS rather than
silently starting over from `[]` (finding #5). **This module has no
persistent store of its own.** The AUTHORITATIVE append-only check —
the one that can't be fooled by a CI run that forgot to pass
`--previous-versions` — runs in `deploy-site` against the live,
already-published `/catalog/v1/versions.json`, fetched over HTTPS,
immediately before publishing a new version.

### Tests → AT(2) + the security gate

`test/sign.test.ts`'s "AT(2) + security-gate" suite emits a real artifact
(via `emitCatalogArtifact`) and verifies it, covering: a valid pass; a
tampered shard; a whitespace-only manifest tamper (finding #1); the four
`PROBE` fixtures (duplicate key, `__proto__`, `-0.0e0`, plus the two G3-10
far-future-`catalogVersion` forgery shapes); a swapped-in wrong public key
for a trusted `kid`; an unknown `kid`; a self-revoking manifest; the
finding-#3 "revoked key omits itself from its own list" probe; rollback
(finding #6); contract-major mismatch (finding #9); a stray file (finding
#7); `versions.json`'s own tamper and last-entry-mismatch checks (finding
#4); and that no shard is ever read when the signature fails (finding #8).
`test/manifest.test.ts` covers `canonicalStringify`'s `-0`/non-finite
rejection, `parseStrictJson`'s duplicate/forbidden-key/`-0` probes, and
`versions.json` append-only + strict-increase at the unit level.
`test/emit-catalog.test.ts` covers region/ODbL sharding, full
determinism, the write-to-temp-then-rename partial-failure probe, and the
finding-#11 non-deterministic-re-emit refusal.

### Resolved ambiguities

- **Shard layout: region, not geohash.** The task's build step names both
  ("geohash-sharded or per-entity JSON shards, as the plan describes").
  The plan shards geometry by geohash specifically because raw polygon
  data can be large per region (§5.2); this bundle format carries no
  geometry payload (`Course.geometry` is a pointer, not inline polygon
  data — the geometry pipeline is P1.1+, already out of `bundle.ts`'s
  scope). `facilities/<region>.json` shards by region instead, which §5.2
  already names directly ("Directory JSON is sharded by ISO region").
- **`--catalog-version` is a required, explicit flag**, not computed from
  `git rev-parse` inside the emitter — the CLI's caller (CI) is better
  positioned to compute it and pass it in than the emitter is to shell out
  to git.
- **`osm/*` region sharding.** `bundle.osm` is keyed by `OsmRefId`, not by
  region, so it's grouped by the region of whichever facility/course's
  `seed.osmRef` references each entry; an entry no known `osmRef` points
  at lands in `osm/directory/unassigned.json` rather than being dropped.
- **`contractVersion` as "MAJOR".** §3.5 calls `contractVersion` "semver",
  but this schema (`packages/catalog`'s `CONTRACT_VERSION`) implements it
  as a plain integer. `supportedContractMajor` compares against that
  integer directly — there is no minor/patch to separate out yet.
