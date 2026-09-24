import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { emitCatalogArtifact } from "../src/emit-catalog.js";
import { verifyArtifact, type TrustedKey } from "../src/sign.js";
import type { VersionEntry } from "../src/manifest.js";
import { minimalBundle } from "./emit-test-helpers.js";

function generateKeys() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
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
  let publicKeyPem: string;
  const KID = "k1";
  const FIXED = new Date("2026-01-01T00:00:00.000Z");

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "golfraven-emit-"));
    ({ privateKeyPem, publicKeyPem } = generateKeys());
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  function trustedKeys(): TrustedKey[] {
    return [{ kid: KID, publicKeyPem }];
  }

  it("writes catalog/v1/ under the given outDir and nowhere else, including versions.sig.json", async () => {
    await emitCatalogArtifact(minimalBundle(), {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "0.0.0",
      kid: KID,
      privateKeyPem,
      generatedAt: FIXED,
    });
    const files = (await listFilesRecursive(dir)).map((f) => relative(dir, f));
    expect(files).toContain("catalog/v1/manifest.json");
    expect(files).toContain("catalog/v1/manifest.sig.json");
    expect(files).toContain("catalog/v1/versions.json");
    expect(files).toContain("catalog/v1/versions.sig.json");
    expect(files).toContain("catalog/v1/trails.json");
    expect(files).toContain("catalog/v1/id-ledger.json");
    expect(files.every((f) => f.startsWith("catalog/v1/"))).toBe(true);
    // No leftover temp/backup directories after a clean run.
    expect(files.some((f) => f.includes(".v1.tmp-") || f.includes(".v1.backup-"))).toBe(false);
  });

  it("produces an artifact that verifyArtifact accepts end to end", async () => {
    await emitCatalogArtifact(minimalBundle(), {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "1.2.3",
      kid: KID,
      revokedKids: ["old-kid"],
      privateKeyPem,
      generatedAt: FIXED,
    });
    const result = await verifyArtifact(dir, { trustedKeys: trustedKeys(), revokedKids: new Set() });
    expect(result.issues).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it("manifest carries contractVersion, catalogVersion, minAppVersion, kid, sorted revokedKids[] and a shard list", async () => {
    const result = await emitCatalogArtifact(minimalBundle(), {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "1.2.3",
      kid: KID,
      revokedKids: ["zzz-kid", "aaa-kid"],
      privateKeyPem,
      generatedAt: FIXED,
    });
    expect(result.manifest.contractVersion).toBe(0);
    expect(result.manifest.catalogVersion).toBe("20260101-abc0001");
    expect(result.manifest.minAppVersion).toBe("1.2.3");
    expect(result.manifest.kid).toBe(KID);
    expect(result.manifest.revokedKids).toEqual(["aaa-kid", "zzz-kid"]);
    expect(result.manifest.shards.length).toBeGreaterThan(0);
    for (const shard of result.manifest.shards) {
      expect(shard.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(shard.bytes).toBeGreaterThan(0);
      // Every shard path is lower-case (security-gate requirement).
      expect(shard.path).toBe(shard.path.toLowerCase());
    }
  });

  it("shards facilities per ISO region, lower-cased as a path (facilities/us-tn.json)", async () => {
    const result = await emitCatalogArtifact(minimalBundle(), {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "0.0.0",
      kid: KID,
      privateKeyPem,
      generatedAt: FIXED,
    });
    const paths = result.manifest.shards.map((s) => s.path).sort();
    expect(paths).toContain("facilities/us-tn.json");
    expect(paths).toContain("facilities/ca-qc.json");

    // The FILE CONTENT still carries the real, upper-case region code.
    const usTn = JSON.parse(
      await readFile(join(result.v1Dir, "facilities", "us-tn.json"), "utf8"),
    ) as { region: string }[];
    expect(usTn).toHaveLength(1);
    expect(usTn[0]?.region).toBe("US-TN");
  });

  it("shards osm content by region under osm/directory/<region>.json, plus osm/attribution.txt, both ODbL-1.0", async () => {
    const result = await emitCatalogArtifact(minimalBundle(), {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "0.0.0",
      kid: KID,
      privateKeyPem,
      generatedAt: FIXED,
    });
    const osmShard = result.manifest.shards.find((s) => s.path === "osm/directory/us-tn.json");
    expect(osmShard?.license).toBe("ODbL-1.0");
    const attribution = result.manifest.shards.find((s) => s.path === "osm/attribution.txt");
    expect(attribution?.license).toBe("ODbL-1.0");
    const nonOsmShard = result.manifest.shards.find((s) => s.path === "trails.json");
    expect(nonOsmShard?.license).toBeUndefined();
  });

  it("omits every osm/* shard when the bundle carries no osm content at all", async () => {
    const result = await emitCatalogArtifact(minimalBundle({ osm: undefined }), {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "0.0.0",
      kid: KID,
      privateKeyPem,
      generatedAt: FIXED,
    });
    expect(result.manifest.shards.some((s) => s.path.startsWith("osm/"))).toBe(false);
  });

  it("omits designers.json / offer-terms.json when the bundle doesn't carry those fields at all", async () => {
    const result = await emitCatalogArtifact(minimalBundle({ designers: undefined }), {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "0.0.0",
      kid: KID,
      privateKeyPem,
      generatedAt: FIXED,
    });
    expect(result.manifest.shards.some((s) => s.path === "designers.json")).toBe(false);
    expect(result.manifest.shards.some((s) => s.path === "offer-terms.json")).toBe(false);
  });

  it("is deterministic: two emits of the same bundle with the same options (and a pinned generatedAt) are byte-identical", async () => {
    const dirA = await mkdtemp(join(tmpdir(), "golfraven-emit-det-a-"));
    const dirB = await mkdtemp(join(tmpdir(), "golfraven-emit-det-b-"));
    try {
      const bundle = minimalBundle();
      const opts = {
        catalogVersion: "20260101-abc0001",
        minAppVersion: "1.0.0",
        kid: KID,
        revokedKids: ["z-kid", "a-kid"],
        privateKeyPem,
        generatedAt: FIXED,
      };
      await emitCatalogArtifact(bundle, { ...opts, outDir: dirA });
      await emitCatalogArtifact(bundle, { ...opts, outDir: dirB });

      const filesA = (await listFilesRecursive(dirA)).map((f) => relative(dirA, f)).sort();
      const filesB = (await listFilesRecursive(dirB)).map((f) => relative(dirB, f)).sort();
      expect(filesA).toEqual(filesB);

      for (const rel of filesA) {
        const bytesA = await readFile(join(dirA, rel));
        const bytesB = await readFile(join(dirB, rel));
        expect(bytesA.equals(bytesB)).toBe(true);
      }
    } finally {
      await rm(dirA, { recursive: true, force: true });
      await rm(dirB, { recursive: true, force: true });
    }
  });

  it("finding #11: refuses a wall-clock re-emit of an already-published version with no --generated-at / SOURCE_DATE_EPOCH", async () => {
    const bundle = minimalBundle();
    await emitCatalogArtifact(bundle, {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "0.0.0",
      kid: KID,
      privateKeyPem,
      generatedAt: FIXED,
    });
    expect(process.env["SOURCE_DATE_EPOCH"]).toBeUndefined();
    await expect(
      emitCatalogArtifact(bundle, {
        outDir: dir,
        catalogVersion: "20260101-abc0001", // same version again
        minAppVersion: "0.0.0",
        kid: KID,
        privateKeyPem,
        // no generatedAt this time — must refuse, not silently use Date.now()
      }),
    ).rejects.toThrow(/refusing a non-deterministic re-emit/);
  });

  it("finding #11: SOURCE_DATE_EPOCH is honored as a time source", async () => {
    process.env["SOURCE_DATE_EPOCH"] = String(Math.floor(FIXED.getTime() / 1000));
    try {
      const result = await emitCatalogArtifact(minimalBundle(), {
        outDir: dir,
        catalogVersion: "20260101-abc0001",
        minAppVersion: "0.0.0",
        kid: KID,
        privateKeyPem,
      });
      expect(result.manifest.generatedAt).toBe(FIXED.toISOString());
    } finally {
      delete process.env["SOURCE_DATE_EPOCH"];
    }
  });

  it("versions.json: a second emit into the same outDir appends, keeping the first entry unchanged", async () => {
    const bundle = minimalBundle();
    const first = await emitCatalogArtifact(bundle, {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "0.0.0",
      kid: KID,
      privateKeyPem,
      generatedAt: FIXED,
    });
    const second = await emitCatalogArtifact(bundle, {
      outDir: dir,
      catalogVersion: "20260102-abc0002",
      minAppVersion: "0.0.0",
      kid: KID,
      privateKeyPem,
      generatedAt: new Date("2026-01-02T00:00:00.000Z"),
    });

    expect(second.versions).toHaveLength(2);
    expect(second.versions[0]).toEqual(first.versions[0]);
    expect(second.versions[1]?.version).toBe("20260102-abc0002");

    const onDisk = JSON.parse(
      await readFile(join(dir, "catalog", "v1", "versions.json"), "utf8"),
    ) as VersionEntry[];
    expect(onDisk).toEqual(second.versions);

    const result = await verifyArtifact(dir, { trustedKeys: trustedKeys(), revokedKids: new Set() });
    expect(result.ok).toBe(true);
  });

  it("versions.json is append-only: refuses a same-version re-emit under different content (different kid)", async () => {
    const bundle = minimalBundle();
    const { privateKeyPem: otherKeyPem } = generateKeys();
    await emitCatalogArtifact(bundle, {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "0.0.0",
      kid: KID,
      privateKeyPem,
      generatedAt: FIXED,
    });
    await expect(
      emitCatalogArtifact(bundle, {
        outDir: dir,
        catalogVersion: "20260101-abc0001",
        minAppVersion: "0.0.0",
        kid: "different-kid",
        privateKeyPem: otherKeyPem,
        generatedAt: FIXED,
      }),
    ).rejects.toThrow(/already published with different content/);
  });

  it("versions.json is append-only: refuses an emit whose catalogVersion is NOT strictly greater than the last published", async () => {
    const bundle = minimalBundle();
    await emitCatalogArtifact(bundle, {
      outDir: dir,
      catalogVersion: "20260105-abc0001",
      minAppVersion: "0.0.0",
      kid: KID,
      privateKeyPem,
      generatedAt: new Date("2026-01-05T00:00:00.000Z"),
    });
    await expect(
      emitCatalogArtifact(bundle, {
        outDir: dir,
        catalogVersion: "20260101-abc0002", // earlier date than the last published
        minAppVersion: "0.0.0",
        kid: KID,
        privateKeyPem,
        generatedAt: new Date("2026-01-06T00:00:00.000Z"),
      }),
    ).rejects.toThrow(/must be strictly greater/);
  });

  it("finding #5: a missing --previous-versions file throws, never falls back to []", async () => {
    await expect(
      emitCatalogArtifact(minimalBundle(), {
        outDir: dir,
        catalogVersion: "20260101-abc0001",
        minAppVersion: "0.0.0",
        kid: KID,
        privateKeyPem,
        generatedAt: FIXED,
        previousVersionsPath: join(dir, "does-not-exist-versions.json"),
      }),
    ).rejects.toThrow(/ENOENT|no such file/i);
  });

  it("finding #5: a malformed --previous-versions file throws, never falls back to []", async () => {
    const dirPrev = await mkdtemp(join(tmpdir(), "golfraven-emit-prev-"));
    try {
      const previousVersionsPath = join(dirPrev, "versions.json");
      await writeFile(previousVersionsPath, "{ not even json");
      await expect(
        emitCatalogArtifact(minimalBundle(), {
          outDir: dir,
          catalogVersion: "20260101-abc0001",
          minAppVersion: "0.0.0",
          kid: KID,
          privateKeyPem,
          generatedAt: FIXED,
          previousVersionsPath,
        }),
      ).rejects.toThrow(/malformed previous versions\.json/);
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
          version: "20251231-eee0000",
          publishedAt: "2025-12-31T00:00:00.000Z",
          kid: "old-kid",
          sha256: "1".repeat(64),
        },
      ];
      await writeFile(previousVersionsPath, JSON.stringify(seed, null, 2) + "\n");

      const result = await emitCatalogArtifact(minimalBundle(), {
        outDir: dir,
        catalogVersion: "20260101-abc0001",
        minAppVersion: "0.0.0",
        kid: KID,
        privateKeyPem,
        generatedAt: FIXED,
        previousVersionsPath,
      });
      expect(result.versions).toHaveLength(2);
      expect(result.versions[0]).toEqual(seed[0]);
    } finally {
      await rm(dirPrev, { recursive: true, force: true });
    }
  });

  describe("finding #2/#4: write-to-temp-then-rename — partial-failure safety", () => {
    // This session runs as root (`id` → uid=0), where chmod-based
    // permission denial is NOT a reliable way to induce a write failure —
    // root bypasses DAC checks, so an EACCES-based probe would silently
    // pass regardless of whether the temp-dir-then-rename logic is
    // correct. Instead, this test mocks `node:fs/promises.writeFile` to
    // throw partway through the shard-writing loop (which only starts
    // after every validation/signing step has already succeeded), giving
    // a deterministic, privilege-independent mid-write failure.
    it("a failure partway through writing the new tree leaves the previous tree completely intact", async () => {
      const bundle = minimalBundle();
      const first = await emitCatalogArtifact(bundle, {
        outDir: dir,
        catalogVersion: "20260101-abc0001",
        minAppVersion: "0.0.0",
        kid: KID,
        privateKeyPem,
        generatedAt: FIXED,
      });
      const beforeFiles = (await listFilesRecursive(join(dir, "catalog", "v1"))).sort();
      const beforeBytes = new Map<string, Buffer>();
      for (const f of beforeFiles) beforeBytes.set(f, await readFile(f));

      vi.resetModules();
      vi.doMock("node:fs/promises", async () => {
        const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
        let writeFileCalls = 0;
        return {
          ...actual,
          writeFile: async (...args: Parameters<typeof actual.writeFile>) => {
            writeFileCalls += 1;
            // Let the first shard write through, then fail — proving the
            // failure happens genuinely mid-write, not on the very first
            // call (which would be indistinguishable from "never started").
            if (writeFileCalls === 2) {
              throw new Error("SIMULATED_MID_WRITE_FAILURE");
            }
            return actual.writeFile(...args);
          },
        };
      });
      try {
        const { emitCatalogArtifact: emitWithMockedFs } = await import("../src/emit-catalog.js");
        await expect(
          emitWithMockedFs(bundle, {
            outDir: dir,
            catalogVersion: "20260102-abc0002",
            minAppVersion: "0.0.0",
            kid: KID,
            privateKeyPem,
            generatedAt: new Date("2026-01-02T00:00:00.000Z"),
          }),
        ).rejects.toThrow(/SIMULATED_MID_WRITE_FAILURE/);
      } finally {
        vi.doUnmock("node:fs/promises");
        vi.resetModules();
      }

      // `verifyArtifact` and `readFile` above were imported statically at
      // the top of this file, BEFORE any mocking — they're bound to the
      // real `node:fs/promises`, unaffected by the mock/reset above.
      const afterFiles = (await listFilesRecursive(join(dir, "catalog", "v1"))).sort();
      expect(afterFiles).toEqual(beforeFiles);
      for (const f of afterFiles) {
        expect((await readFile(f)).equals(beforeBytes.get(f)!)).toBe(true);
      }
      const stillVerifies = await verifyArtifact(dir, { trustedKeys: trustedKeys(), revokedKids: new Set() });
      expect(stillVerifies.ok).toBe(true);
      expect(stillVerifies.revokedKids).toEqual(first.manifest.revokedKids);
      // And no temp/backup directory was left behind under catalog/.
      const catalogEntries = await readdir(join(dir, "catalog"));
      expect(catalogEntries).toEqual(["v1"]);
    });

    it("no .v1.tmp-* / .v1.backup-* directories are left behind after a clean run", async () => {
      await emitCatalogArtifact(minimalBundle(), {
        outDir: dir,
        catalogVersion: "20260101-abc0001",
        minAppVersion: "0.0.0",
        kid: KID,
        privateKeyPem,
        generatedAt: FIXED,
      });
      await emitCatalogArtifact(minimalBundle(), {
        outDir: dir,
        catalogVersion: "20260102-abc0002",
        minAppVersion: "0.0.0",
        kid: KID,
        privateKeyPem,
        generatedAt: new Date("2026-01-02T00:00:00.000Z"),
      });
      const entries = await readdir(join(dir, "catalog"));
      expect(entries).toEqual(["v1"]);
    });
  });

  it("finding #7: the verifier reports no STRAY_FILE for a normal emit (no leftovers to trip it)", async () => {
    await emitCatalogArtifact(minimalBundle(), {
      outDir: dir,
      catalogVersion: "20260101-abc0001",
      minAppVersion: "0.0.0",
      kid: KID,
      privateKeyPem,
      generatedAt: FIXED,
    });
    const result = await verifyArtifact(dir, { trustedKeys: trustedKeys(), revokedKids: new Set() });
    expect(result.issues.some((i) => i.startsWith("STRAY_FILE:"))).toBe(false);
  });

  it("rejects a non-semver --min-app-version and a non-yyyymmdd-gitsha7 --catalog-version before any write", async () => {
    await expect(
      emitCatalogArtifact(minimalBundle(), {
        outDir: dir,
        catalogVersion: "not-a-version",
        minAppVersion: "0.0.0",
        kid: KID,
        privateKeyPem,
        generatedAt: FIXED,
      }),
    ).rejects.toThrow(/yyyymmdd-gitsha7/);
    await expect(
      emitCatalogArtifact(minimalBundle(), {
        outDir: dir,
        catalogVersion: "20260101-abc0001",
        minAppVersion: "not-semver",
        kid: KID,
        privateKeyPem,
        generatedAt: FIXED,
      }),
    ).rejects.toThrow(/semver/);
    // Nothing was written for either rejected call.
    await expect(readdir(join(dir, "catalog"))).rejects.toThrow();
  });
});
