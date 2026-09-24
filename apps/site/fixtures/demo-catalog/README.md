# Synthetic demo catalog — NOT real content

`bundle.json` in this directory is a **fully fictional** catalog dataset:
fictional trails, fictional golf facilities, fictional operators, fake
`example.com`/`example.org`/`example.ca` URLs. No name here refers to a
real golf course, trail, operator or person.

It exists so `apps/site` has something to build against while the real
`data/` directory carries no facility/trail content yet (see
`../../../../data/README.md`; build plan §5, this repo's stage-1
instructions item 3: "Real `data/` is empty today ... add a clearly
labelled synthetic demo dataset").

**It is loaded only when:**

- `GOLFRAVEN_DEMO=1` is set, or
- the real `data/` directory has no facilities/trails yet
  (`isCatalogEmpty()`, `packages/catalog/src/load.ts`).

See `apps/site/src/lib/derive.ts`'s `loadSiteCatalog()`.

**It is never published.** `loadSiteCatalog()` throws if
`GOLFRAVEN_ENV=production` and the build would fall back to this dataset —
a production build must be pointed at real `data/` content, never at this
fixture.
