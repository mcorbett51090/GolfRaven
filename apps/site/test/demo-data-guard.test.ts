/**
 * B3 (fail-closed demo guard): "Demo data is allowed only when
 * GOLFRAVEN_DEMO=1. An empty data/ without it fails the build, with a
 * clear message. ... GOLFRAVEN_ENV=production requires real data and
 * refuses demo mode." Tested directly against `loadSiteCatalog()`
 * (the full-build behavior — noindex-everywhere, empty sitemap, the
 * banner — is covered by `test/paths.mjs`'s `BUILDS.demo`,
 * asserted in `acceptance.test.ts`).
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadSiteCatalog } from "../src/lib/derive";
import { demoBundleForSite } from "../fixtures/demo-catalog/build-bundle.mjs";
import { writeFixtureDataDir } from "./write-fixture-data-dir.mjs";

describe("loadSiteCatalog — the 4 GOLFRAVEN_DEMO × GOLFRAVEN_ENV combinations (empty real data/)", () => {
  it("empty data/ + no GOLFRAVEN_DEMO -> throws (fail-closed, not a silent empty site)", async () => {
    await expect(loadSiteCatalog({})).rejects.toThrow(/GOLFRAVEN_DEMO/);
  });

  it("empty data/ + no GOLFRAVEN_DEMO + GOLFRAVEN_ENV=production -> STILL throws the empty-data message (never silently 'succeeds' into demo)", async () => {
    await expect(loadSiteCatalog({ GOLFRAVEN_ENV: "production" })).rejects.toThrow(
      /GOLFRAVEN_DEMO/,
    );
  });

  it("GOLFRAVEN_DEMO=1, no production -> uses the demo catalog", async () => {
    const { catalog, usedDemoData } = await loadSiteCatalog({ GOLFRAVEN_DEMO: "1" });
    expect(usedDemoData).toBe(true);
    expect(catalog.trails.length).toBeGreaterThan(0);
  });

  it("GOLFRAVEN_DEMO=1 + GOLFRAVEN_ENV=production -> throws, refusing demo data in production", async () => {
    await expect(
      loadSiteCatalog({ GOLFRAVEN_DEMO: "1", GOLFRAVEN_ENV: "production" }),
    ).rejects.toThrow(/production/i);
  });

  it("GOLFRAVEN_ENV is case-normalised: 'Production' refuses demo data exactly like 'production'", async () => {
    await expect(
      loadSiteCatalog({ GOLFRAVEN_DEMO: "1", GOLFRAVEN_ENV: "Production" }),
    ).rejects.toThrow(/production/i);
  });

  it("an unknown GOLFRAVEN_ENV value is rejected outright", async () => {
    await expect(loadSiteCatalog({ GOLFRAVEN_DEMO: "1", GOLFRAVEN_ENV: "prod" })).rejects.toThrow(
      /Unknown GOLFRAVEN_ENV/,
    );
  });

  it("GOLFRAVEN_ENV=staging (case-insensitive) does NOT refuse demo data", async () => {
    const { usedDemoData } = await loadSiteCatalog({
      GOLFRAVEN_DEMO: "1",
      GOLFRAVEN_ENV: "Staging",
    });
    expect(usedDemoData).toBe(true);
  });
});

describe("loadSiteCatalog — populated real data/ (GOLFRAVEN_DATA_DIR override)", () => {
  const dirs: string[] = [];
  afterEach(async () => {
    await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
  });

  it("uses real data when data/ is populated, no GOLFRAVEN_DEMO needed", async () => {
    const dir = await mkdtemp(join(tmpdir(), "golfraven-site-derive-"));
    dirs.push(dir);
    await writeFixtureDataDir(dir);
    const { catalog, usedDemoData } = await loadSiteCatalog({ GOLFRAVEN_DATA_DIR: dir });
    expect(usedDemoData).toBe(false);
    expect(catalog.facilities.length).toBe(demoBundleForSite().facilities.length);
  });

  it("uses real data in production too, when data/ is genuinely populated", async () => {
    const dir = await mkdtemp(join(tmpdir(), "golfraven-site-derive-"));
    dirs.push(dir);
    await writeFixtureDataDir(dir);
    const { usedDemoData } = await loadSiteCatalog({
      GOLFRAVEN_DATA_DIR: dir,
      GOLFRAVEN_ENV: "production",
    });
    expect(usedDemoData).toBe(false);
  });

  it("GOLFRAVEN_DEMO=1 still wins over populated real data (explicit request honoured)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "golfraven-site-derive-"));
    dirs.push(dir);
    await writeFixtureDataDir(dir);
    // Sabotage a required field so "real" would fail if it were loaded —
    // proves GOLFRAVEN_DEMO=1 really did skip the real data/ dir entirely.
    await writeFile(join(dir, "designers.json"), "not json");
    const { usedDemoData } = await loadSiteCatalog({
      GOLFRAVEN_DATA_DIR: dir,
      GOLFRAVEN_DEMO: "1",
    });
    expect(usedDemoData).toBe(true);
  });
});
