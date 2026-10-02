// supabase/tests/unit/ledger-artifact.test.ts
import { describe, expect, it } from "vitest";
import { firstMintedVersion, latestVerifiedVersion, parseIdLedger } from "../../functions/_shared/catalog/ledger-artifact.js";
import { compareCatalogVersions } from "../../functions/_shared/catalog/manifest-artifact.js";

const FAC_ID = "fac_01ARZ3NDEKTSV4RRFFQ69G5FAV";
const FAC_ID_2 = "fac_01ARZ3NDEKTSV4RRFFQ69G5FBW";

function ledger(entries: Record<string, unknown>) {
  return { entries };
}

describe("parseIdLedger", () => {
  it("accepts a minimal valid entry", () => {
    const r = parseIdLedger(
      ledger({
        [FAC_ID]: { id: FAC_ID, transitions: [{ type: "minted", catalogVersion: "20260101-aaaaaaa" }] },
      }),
    );
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.entries).toHaveLength(1);
      expect(r.value.entries[0]!.kind).toBe("facility");
      expect(r.value.entries[0]!.status).toBeNull();
    }
  });

  it("maps every id-prefix short code to its DB full-word kind", () => {
    const CRS_ID = "crs_01ARZ3NDEKTSV4RRFFQ69G5FCX";
    const r = parseIdLedger(ledger({ [CRS_ID]: { id: CRS_ID, transitions: [{ type: "minted", catalogVersion: "20260101-aaaaaaa" }] } }));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value.entries[0]!.kind).toBe("course");
  });

  it("rejects an id that doesn't match its own map key", () => {
    const r = parseIdLedger(ledger({ [FAC_ID]: { id: FAC_ID_2, transitions: [{ type: "minted", catalogVersion: "20260101-aaaaaaa" }] } }));
    expect(r.ok).toBe(false);
  });

  it("rejects an unrecognized id prefix", () => {
    const BAD_ID = "xyz_01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const r = parseIdLedger(ledger({ [BAD_ID]: { id: BAD_ID, transitions: [{ type: "minted", catalogVersion: "20260101-aaaaaaa" }] } }));
    expect(r.ok).toBe(false);
  });

  it("rejects an empty transitions array (every id is at least minted)", () => {
    const r = parseIdLedger(ledger({ [FAC_ID]: { id: FAC_ID, transitions: [] } }));
    expect(r.ok).toBe(false);
  });

  it("rejects mergedInto set without tombstoned: true", () => {
    const r = parseIdLedger(
      ledger({
        [FAC_ID]: { id: FAC_ID, mergedInto: FAC_ID_2, transitions: [{ type: "minted", catalogVersion: "20260101-aaaaaaa" }] },
      }),
    );
    expect(r.ok).toBe(false);
  });

  it("rejects mergedInto pointing at the entry's own id", () => {
    const r = parseIdLedger(
      ledger({
        [FAC_ID]: { id: FAC_ID, tombstoned: true, mergedInto: FAC_ID, transitions: [{ type: "minted", catalogVersion: "20260101-aaaaaaa" }] },
      }),
    );
    expect(r.ok).toBe(false);
  });

  it("accepts a legitimate tombstone+merge", () => {
    const r = parseIdLedger(
      ledger({
        [FAC_ID]: { id: FAC_ID, tombstoned: true, mergedInto: FAC_ID_2, transitions: [{ type: "minted", catalogVersion: "20260101-aaaaaaa" }, { type: "merged", catalogVersion: "20260201-bbbbbbb" }] },
      }),
    );
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.entries[0]!.tombstoned).toBe(true);
      expect(r.value.entries[0]!.mergedInto).toBe(FAC_ID_2);
    }
  });

  it("rejects a bad transition type", () => {
    const r = parseIdLedger(ledger({ [FAC_ID]: { id: FAC_ID, transitions: [{ type: "exploded", catalogVersion: "20260101-aaaaaaa" }] } }));
    expect(r.ok).toBe(false);
  });
});

describe("firstMintedVersion / latestVerifiedVersion", () => {
  it("picks the earliest minted transition", () => {
    const entry = {
      id: FAC_ID,
      kind: "facility",
      status: "verified" as const,
      tombstoned: false,
      mergedInto: null,
      transitions: [
        { type: "minted" as const, catalogVersion: "20260201-bbbbbbb" },
        { type: "verified" as const, catalogVersion: "20260301-ccccccc" },
      ],
    };
    expect(firstMintedVersion(entry, compareCatalogVersions)).toBe("20260201-bbbbbbb");
    expect(latestVerifiedVersion(entry, compareCatalogVersions)).toBe("20260301-ccccccc");
  });

  it("returns null verified version for a stub with no verified transition", () => {
    const entry = { id: FAC_ID, kind: "facility", status: "stub" as const, tombstoned: false, mergedInto: null, transitions: [{ type: "minted" as const, catalogVersion: "20260101-aaaaaaa" }] };
    expect(latestVerifiedVersion(entry, compareCatalogVersions)).toBeNull();
  });

  it("picks the LATEST of several verified transitions", () => {
    const entry = {
      id: FAC_ID,
      kind: "facility",
      status: "verified" as const,
      tombstoned: false,
      mergedInto: null,
      transitions: [
        { type: "minted" as const, catalogVersion: "20260101-aaaaaaa" },
        { type: "verified" as const, catalogVersion: "20260201-bbbbbbb" },
        { type: "verified" as const, catalogVersion: "20260301-ccccccc" },
      ],
    };
    expect(latestVerifiedVersion(entry, compareCatalogVersions)).toBe("20260301-ccccccc");
  });
});
