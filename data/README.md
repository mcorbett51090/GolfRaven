# data/

Placeholder. `data/` is the git-held content SSOT (build plan §3.1 row B):
trail, facility, course, hole, region, achievement-def and offer-template
content; roster versions; the append-only ID ledger (`data/id-ledger.json`,
build plan §3.5); and redirects. A PR is the only write path — this
directory never holds user data.

**Catalog data arrives in P1** (build plan §4, §10), seeded from OSM via
`scripts/seed-osm.mjs` (which writes `unverified` facility/course stubs here
and their OSM content to `data/osm/`) and verified through
`verify-catalog.mjs` (build plan §15).

Nothing is authored here in P0 beyond this placeholder.
