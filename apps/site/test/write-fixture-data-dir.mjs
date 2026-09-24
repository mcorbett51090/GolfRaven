/**
 * Writes the demo fixture's own content out as a real `data/`-shaped
 * directory (`facilities/*.json`, `trails/*.json`, `regions/*.json`,
 * `designers.json`, `id-ledger.json` — `@golfraven/catalog`'s
 * `loadCatalogFromDataDir` layout), so the test suite's "real" build
 * (`test/paths.mjs`'s `BUILDS.real`) takes the genuine real-data code
 * path rather than the `GOLFRAVEN_DEMO=1` fallback — see `paths.mjs`'s
 * doc for why that distinction matters for B2/B3.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { demoBundleForSite } from "../fixtures/demo-catalog/build-bundle.mjs";

export async function writeFixtureDataDir(dir) {
  const { regions, facilities, trails, designers, idLedger } = demoBundleForSite();

  await mkdir(join(dir, "regions"), { recursive: true });
  await mkdir(join(dir, "facilities"), { recursive: true });
  await mkdir(join(dir, "trails"), { recursive: true });

  await Promise.all([
    ...regions.map((r) => writeFile(join(dir, "regions", `${r.slug}.json`), JSON.stringify(r))),
    ...facilities.map((f) =>
      writeFile(join(dir, "facilities", `${f.slug}.json`), JSON.stringify(f)),
    ),
    ...trails.map((t) => writeFile(join(dir, "trails", `${t.slug}.json`), JSON.stringify(t))),
    writeFile(join(dir, "designers.json"), JSON.stringify(designers)),
    writeFile(join(dir, "id-ledger.json"), JSON.stringify(idLedger)),
  ]);
}
