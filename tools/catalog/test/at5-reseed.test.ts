/**
 * P1 AT(5): "An OSM re-seed never overwrites a verified field, and a
 * way→relation remap of an existing course does not mint a second ID."
 * Tested here against **fixture OSM input** (no network) — see
 * `test/fixtures/at5-*.json`, and `packages/catalog/test/ledger.test.ts`
 * for the broader `reseedFacility` unit coverage this fixture-based test
 * complements.
 */
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  IdLedgerSchema,
  reseedFacility,
  type IdLedger,
  type ReseedCandidate,
} from "@golfraven/catalog";

const FIXTURES_DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

interface At5Fixture {
  ledgerBefore: IdLedger;
  candidates: ReseedCandidate[];
  incoming: {
    osmRef: string;
    name: string;
    lat: number;
    lng: number;
    desiredSlug: string;
    catalogVersion: string;
    date: string;
  };
}

async function loadAt5Fixture(name: string): Promise<At5Fixture> {
  const raw = JSON.parse(await readFile(join(FIXTURES_DIR, `${name}.json`), "utf8")) as At5Fixture;
  // Validate the ledger half against the real schema, so a malformed
  // fixture fails loudly here rather than silently passing a bad test.
  IdLedgerSchema.parse(raw.ledgerBefore);
  return raw;
}

describe("AT(5): way→relation remap does not mint a second id", () => {
  it("matches the existing facility and appends seedRefs, minting nothing new", async () => {
    const fixture = await loadAt5Fixture("at5-way-relation-remap");
    const before = Object.keys(fixture.ledgerBefore.entries).length;

    const outcome = reseedFacility(fixture.ledgerBefore, fixture.incoming, fixture.candidates);

    expect(outcome.kind).toBe("matched");
    if (outcome.kind !== "matched") throw new Error("expected a match");
    expect(outcome.facilityId).toBe(fixture.candidates[0]?.facilityId);
    expect(Object.keys(outcome.ledger.entries)).toHaveLength(before);
    expect(outcome.ledger.entries[outcome.facilityId]?.seedRefs).toContain(
      fixture.incoming.osmRef,
    );
  });
});

describe("AT(5): a re-seed never overwrites a verified field", () => {
  it("keeps the facility's status 'verified' after a matching re-seed", async () => {
    const fixture = await loadAt5Fixture("at5-never-overwrites-verified");
    const candidateId = fixture.candidates[0]?.facilityId;
    expect(fixture.ledgerBefore.entries[candidateId as string]?.status).toBe("verified");

    const outcome = reseedFacility(fixture.ledgerBefore, fixture.incoming, fixture.candidates);

    expect(outcome.kind).toBe("matched");
    if (outcome.kind !== "matched") throw new Error("expected a match");
    expect(outcome.ledger.entries[outcome.facilityId]?.status).toBe("verified");
    // The re-seed only ever appends to seedRefs — no other field on the
    // entry is touched.
    expect(outcome.ledger.entries[outcome.facilityId]?.slug).toBe(
      fixture.ledgerBefore.entries[candidateId as string]?.slug,
    );
  });
});
