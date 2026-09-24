# data/

`data/` is the git-held content SSOT (build plan §3.1 row B): trail,
facility, course, hole, region, achievement-def and offer-template content;
roster versions; the append-only ID ledger (`data/id-ledger.json`, build
plan §3.5); and redirects. A PR is the only write path — this directory
never holds user data.

**P1a status.** `data/id-ledger.json` exists in the format `@golfraven/catalog`'s
`IdLedgerSchema` defines (`packages/catalog/src/ledger.ts`) — currently
empty (`{"entries": {}}`), because no id has been minted for real content
yet. No real facility, course or trail content is authored here in P1a
(scope: "the ledger format and synthetic fixtures; no real course or trail
records") — every fixture exercising the ledger and the catalog schema
lives under `tools/catalog/test/fixtures/` instead, so this file stays
genuinely empty rather than holding synthetic data mixed in with the real
append-only record.

**Still to come (P1.1+).** Real facility/trail content arrives seeded from
OSM via `scripts/seed-osm.mjs` (which will write `unverified` facility/course
stubs here and their OSM content to `data/osm/`), verified and gated through
`tools/catalog`'s `verify-catalog` (build plan §4, §10, §15).
