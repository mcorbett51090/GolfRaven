import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { emitCatalogArtifact } from "../src/emit-catalog.js";
import type { VersionEntry } from "../src/manifest.js";
import { minimalBundle } from "./emit-test-helpers.js";

function generatePrivateKeyPem(): string {
  const { privateKey } = generateKeyPairSync("ed25519");
  return privateKey.export({ type: "pkcs8", format: "pem" }).toString();
}

async function listFilesRecursive(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const out: string[] = [];
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...(await listFilesRecursive(full)));
    } else {
      out.push(full);
    }
  }
  return out.sort();
}

describe("emitCatalogArtifact", () => {
  let dir: string;
  let privateKeyPem: string;
  const FIXED_NOW = new Date("2026-01-01T00:00:00.000Z");

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "golfraven-emit-"));
    privateKeyPem = generatePrivateKeyPem();
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("writes catalog/v1/ under the given outDir and nowhere else", async () => {
    await emitCatalogArtifact(minimalBundle(), {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "0.0.0",
      kid: "k1",
      privateKeyPem,
      now: FIXED_NOW,
    });
    const files = (await listFilesRecursive(dir)).map((f) => relative(dir, f));
    expect(files).toContain("catalog/v1/manifest.json");
    expect(files).toContain("catalog/v1/manifest.sig.json");
    expect(files).toContain("catalog/v1/versions.json");
    expect(files).toContain("catalog/v1/trails.json");
    expect(files).toContain("catalog/v1/id-ledger.json");
    // Every listed file lives under catalog/v1/.
    expect(files.every((f) => f.startsWith("catalog/v1/"))).toBe(true);
  });

  it("manifest carries contractVersion, catalogVersion, minAppVersion, kid, revokedKids[] and a shard list with sha256", async () => {
    const result = await emitCatalogArtifact(minimalBundle(), {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "1.2.3",
      kid: "k1",
      revokedKids: ["old-kid"],
      privateKeyPem,
      now: FIXED_NOW,
    });
    expect(result.manifest.contractVersion).toBe(0);
    expect(result.manifest.catalogVersion).toBe("20260101-abc0001");
    expect(result.manifest.minAppVersion).toBe("1.2.3");
    expect(result.manifest.kid).toBe("k1");
    expect(result.manifest.revokedKids).toEqual(["old-kid"]);
    expect(result.manifest.shards.length).toBeGreaterThan(0);
    for (const shard of result.manifest.shards) {
      expect(shard.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(shard.bytes).toBeGreaterThan(0);
    }
  });

  it("shards facilities per ISO region (facilities/<region>.json)", async () => {
    const result = await emitCatalogArtifact(minimalBundle(), {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "0.0.0",
      kid: "k1",
      privateKeyPem,
      now: FIXED_NOW,
    });
    const paths = result.manifest.shards.map((s) => s.path).sort();
    expect(paths).toContain("facilities/US-TN.json");
    expect(paths).toContain("facilities/CA-QC.json");

    const usTn = JSON.parse(
      await readFile(join(result.v1Dir, "facilities", "US-TN.json"), "utf8"),
    ) as unknown[];
    expect(usTn).toHaveLength(1);
    const caQc = JSON.parse(
      await readFile(join(result.v1Dir, "facilities", "CA-QC.json"), "utf8"),
    ) as unknown[];
    expect(caQc).toHaveLength(1);
  });

  it("writes the ODbL-licensed osm/ shard, flagged license: ODbL-1.0, only when the bundle carries osm content", async () => {
    const withOsm = await emitCatalogArtifact(minimalBundle(), {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "0.0.0",
      kid: "k1",
      privateKeyPem,
      now: FIXED_NOW,
    });
    const osmShard = withOsm.manifest.shards.find((s) => s.path === "osm/content.json");
    expect(osmShard?.license).toBe("ODbL-1.0");
    const attribution = withOsm.manifest.shards.find((s) => s.path === "osm/ATTRIBUTION.txt");
    expect(attribution?.license).toBe("ODbL-1.0");
    const nonOsmShard = withOsm.manifest.shards.find((s) => s.path === "trails.json");
    expect(nonOsmShard?.license).toBeUndefined();

    const dir2 = await mkdtemp(join(tmpdir(), "golfraven-emit-noosm-"));
    try {
      const withoutOsm = await emitCatalogArtifact(minimalBundle({ osm: undefined }), {
        outDir: dir2,
        catalogVersion: "20260101-abc0001",
        minAppVersion: "0.0.0",
        kid: "k1",
        privateKeyPem,
        now: FIXED_NOW,
      });
      expect(withoutOsm.manifest.shards.some((s) => s.path.startsWith("osm/"))).toBe(false);
    } finally {
      await rm(dir2, { recursive: true, force: true });
    }
  });

  it("omits designers.json / offer-terms.json when the bundle doesn't carry those fields at all", async () => {
    const result = await emitCatalogArtifact(minimalBundle({ designers: undefined }), {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "0.0.0",
      kid: "k1",
      privateKeyPem,
      now: FIXED_NOW,
    });
    expect(result.manifest.shards.some((s) => s.path === "designers.json")).toBe(false);
    expect(result.manifest.shards.some((s) => s.path === "offer-terms.json")).toBe(false);
  });

  it("is deterministic: two emits of the same bundle with the same options are byte-identical", async () => {
    const dirA = await mkdtemp(join(tmpdir(), "golfraven-emit-det-a-"));
    const dirB = await mkdtemp(join(tmpdir(), "golfraven-emit-det-b-"));
    try {
      const bundle = minimalBundle();
      const opts = {
        catalogVersion: "20260101-abc0001",
        minAppVersion: "1.0.0",
        kid: "k1",
        revokedKids: ["z-kid", "a-kid"],
        privateKeyPem,
        now: FIXED_NOW,
      };
      await emitCatalogArtifact(bundle, { ...opts, outDir: dirA });
      await emitCatalogArtifact(bundle, { ...opts, outDir: dirB });

      const filesA = await listFilesRecursive(dirA);
      const filesB = await listFilesRecursive(dirB);
      const relA = filesA.map((f) => relative(dirA, f)).sort();
      const relB = filesB.map((f) => relative(dirB, f)).sort();
      expect(relA).toEqual(relB);

      for (const rel of relA) {
        const bytesA = await readFile(join(dirA, rel));
        const bytesB = await readFile(join(dirB, rel));
        expect(bytesA.equals(bytesB)).toBe(true);
      }
      // revokedKids is sorted on write regardless of input order.
      const manifestA = JSON.parse(await readFile(join(dirA, "catalog", "v1", "manifest.json"), "utf8"));
      expect(manifestA.revokedKids).toEqual(["a-kid", "z-kid"]);
    } finally {
      await rm(dirA, { recursive: true, force: true });
      await rm(dirB, { recursive: true, force: true });
    }
  });

  it("versions.json: a second emit into the same outDir appends, keeping the first entry unchanged", async () => {
    const bundle = minimalBundle();
    const first = await emitCatalogArtifact(bundle, {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "0.0.0",
      kid: "k1",
      privateKeyPem,
      now: FIXED_NOW,
    });
    const second = await emitCatalogArtifact(bundle, {
      outDir: dir,
      catalogVersion: "20260102-abc0002",
      minAppVersion: "0.0.0",
      kid: "k1",
      privateKeyPem,
      now: new Date("2026-01-02T00:00:00.000Z"),
    });

    expect(second.versions).toHaveLength(2);
    expect(second.versions[0]).toEqual(first.versions[0]);
    expect(second.versions[1]?.version).toBe("20260102-abc0002");

    const onDisk = JSON.parse(
      await readFile(join(dir, "catalog", "v1", "versions.json"), "utf8"),
    ) as VersionEntry[];
    expect(onDisk).toEqual(second.versions);
  });

  it("versions.json is append-only: refuses an emit that would change an earlier entry's content", async () => {
    const bundle = minimalBundle();
    await emitCatalogArtifact(bundle, {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "0.0.0",
      kid: "k1",
      privateKeyPem,
      now: FIXED_NOW,
    });
    // Same version string, but a different kid this time -> different
    // manifestSha -> refused as "already published with different content".
    await expect(
      emitCatalogArtifact(bundle, {
        outDir: dir,
        catalogVersion: "20260101-abc0001",
        minAppVersion: "0.0.0",
        kid: "different-kid",
        privateKeyPem,
        now: FIXED_NOW,
      }),
    ).rejects.toThrow(/already published with different content/);
  });

  it("versions.json is append-only: refuses an emit whose previousVersionsPath disagrees with this run's version", async () => {
    const dirPrev = await mkdtemp(join(tmpdir(), "golfraven-emit-prev-"));
    try {
      const previousVersionsPath = join(dirPrev, "versions.json");
      // Simulate a tampered/incomplete "previously published" file: it
      // claims version A was published with a sha256 that does not match
      // what THIS run would independently compute for version A, because
      // this run publishes a different version and never re-derives A's
      // sha itself — the point is only that appendVersion, given a
      // conflicting duplicate, refuses rather than silently overwriting.
      const tamperedPrevious: VersionEntry[] = [
        {
          version: "20260101-abc0001",
          publishedAt: "2026-01-01T00:00:00.000Z",
          kid: "k1",
          sha256: "0".repeat(64),
        },
      ];
      await writeFile(previousVersionsPath, JSON.stringify(tamperedPrevious));

      await expect(
        emitCatalogArtifact(minimalBundle(), {
          outDir: dir,
          catalogVersion: "20260101-abc0001",
          minAppVersion: "0.0.0",
          kid: "k1",
          privateKeyPem,
          now: FIXED_NOW,
          previousVersionsPath,
        }),
      ).rejects.toThrow(/already published with different content/);
    } finally {
      await rm(dirPrev, { recursive: true, force: true });
    }
  });

  it("previousVersionsPath seeds versions.json in a fresh outDir that has none of its own", async () => {
    const dirPrev = await mkdtemp(join(tmpdir(), "golfraven-emit-prev2-"));
    try {
      const previousVersionsPath = join(dirPrev, "versions.json");
      const seed: VersionEntry[] = [
        {
          version: "20251231-zzz0000",
          publishedAt: "2025-12-31T00:00:00.000Z",
          kid: "old-kid",
          sha256: "1".repeat(64),
        },
      ];
      await writeFile(previousVersionsPath, JSON.stringify(seed));

      const result = await emitCatalogArtifact(minimalBundle(), {
        outDir: dir,
        catalogVersion: "20260101-abc0001",
        minAppVersion: "0.0.0",
        kid: "k1",
        privateKeyPem,
        now: FIXED_NOW,
        previousVersionsPath,
      });
      expect(result.versions).toHaveLength(2);
      expect(result.versions[0]).toEqual(seed[0]);
    } finally {
      await rm(dirPrev, { recursive: true, force: true });
    }
  });
});
