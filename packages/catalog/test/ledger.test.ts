import { describe, expect, it } from "vitest";
import {
  emptyLedger,
  mergeIntoSurvivor,
  mintSlug,
  mintStubFacility,
  promoteToVerified,
  reseedFacility,
  resolveMergedId,
  splitCourse,
  type IdLedger,
  type ReseedCandidate,
} from "../src/ledger.js";

const meta = { catalogVersion: "20260924-abc1234", date: "2026-09-24" };

describe("mintSlug (AT(7))", () => {
  it("returns the desired slug when it is free", () => {
    expect(mintSlug(emptyLedger(), "pebble-hills")).toBe("pebble-hills");
  });

  it("suffixes the newcomer on collision and leaves the existing slug conceptually unchanged", () => {
    const { ledger } = mintStubFacility(emptyLedger(), {
      osmRef: "way/1",
      desiredSlug: "pebble-hills",
      ...meta,
    });
    const existingSlug = Object.values(ledger.entries).find(
      (e) => e.kind === "fac",
    )?.slug;
    expect(existingSlug).toBe("pebble-hills");

    // A second mint with the SAME desired slug must suffix the newcomer...
    const second = mintStubFacility(ledger, {
      osmRef: "way/2",
      desiredSlug: "pebble-hills",
      ...meta,
    });
    expect(second.slug).toBe("pebble-hills-2");

    // ...and the first facility's slug must be untouched.
    const firstSlugAfter = Object.values(second.ledger.entries).find(
      (e) => e.id === Object.keys(ledger.entries)[0],
    )?.slug;
    expect(firstSlugAfter).toBe("pebble-hills");
  });
});

describe("mintStubFacility (AT(8): stub course ids)", () => {
  it("mints exactly one facility id and one course id, both ledgered as stub", () => {
    const { ledger, facilityId, courseId } = mintStubFacility(emptyLedger(), {
      osmRef: "way/1",
      desiredSlug: "pebble-hills",
      ...meta,
    });
    expect(Object.keys(ledger.entries)).toHaveLength(2);
    expect(ledger.entries[facilityId]?.status).toBe("stub");
    expect(ledger.entries[courseId]?.status).toBe("stub");
    expect(ledger.entries[facilityId]?.seedRefs).toEqual(["way/1"]);
    expect(ledger.entries[courseId]?.seedRefs).toEqual(["way/1"]);
    expect(ledger.entries[facilityId]?.transitions[0]?.type).toBe("minted");
    expect(ledger.entries[courseId]?.transitions[0]?.type).toBe("minted");
  });
});

describe("reseedFacility (AT(5), G-P1-12, FM-14)", () => {
  function seedOne(ledger: IdLedger) {
    const minted = mintStubFacility(ledger, {
      osmRef: "way/100",
      desiredSlug: "pebble-hills",
      ...meta,
    });
    const candidate: ReseedCandidate = {
      facilityId: minted.facilityId,
      courseId: minted.courseId,
      name: "Pebble Hills Golf Club",
      lat: 36.16,
      lng: -86.78,
    };
    return { ledger: minted.ledger, candidate };
  }

  it("a re-seed of the same osmRef is idempotent (already-known)", () => {
    const { ledger, candidate } = seedOne(emptyLedger());
    const outcome = reseedFacility(
      ledger,
      {
        osmRef: "way/100",
        name: "Pebble Hills Golf Club",
        lat: 36.16,
        lng: -86.78,
        desiredSlug: "pebble-hills",
        ...meta,
      },
      [candidate],
    );
    expect(outcome.kind).toBe("already-known");
    if (outcome.kind === "already-known") {
      expect(outcome.facilityId).toBe(candidate.facilityId);
    }
  });

  it("a spatially + name matching re-seed appends seedRefs and never mints a second id", () => {
    const { ledger, candidate } = seedOne(emptyLedger());
    const before = Object.keys(ledger.entries).length;
    const outcome = reseedFacility(
      ledger,
      {
        osmRef: "way/101", // a different OSM object id, same real-world place
        name: "Pebble Hills Golf Club",
        lat: 36.1601, // ~11 m away, well within 150 m
        lng: -86.78,
        desiredSlug: "pebble-hills",
        ...meta,
      },
      [candidate],
    );
    expect(outcome.kind).toBe("matched");
    if (outcome.kind === "matched") {
      expect(outcome.facilityId).toBe(candidate.facilityId);
      expect(Object.keys(outcome.ledger.entries)).toHaveLength(before); // no new ids
      expect(outcome.ledger.entries[candidate.facilityId]?.seedRefs).toEqual([
        "way/100",
        "way/101",
      ]);
    }
  });

  it('a way→relation remap does not mint a second id (AT(5) "way→relation remap")', () => {
    const { ledger, candidate } = seedOne(emptyLedger());
    const before = Object.keys(ledger.entries).length;
    // OSM upgraded the same object from a way to a relation: new osmRef,
    // identical coordinates and name.
    const outcome = reseedFacility(
      ledger,
      {
        osmRef: "relation/9001",
        name: "Pebble Hills Golf Club",
        lat: 36.16,
        lng: -86.78,
        desiredSlug: "pebble-hills",
        ...meta,
      },
      [candidate],
    );
    expect(outcome.kind).toBe("matched");
    expect(Object.keys((outcome as { ledger: IdLedger }).ledger.entries)).toHaveLength(
      before,
    );
  });

  it("an unrelated OSM object with no spatial match mints a new stub facility", () => {
    const { ledger, candidate } = seedOne(emptyLedger());
    const outcome = reseedFacility(
      ledger,
      {
        osmRef: "way/999",
        name: "Riverside Municipal",
        lat: 40.0, // far away
        lng: -75.0,
        desiredSlug: "riverside-municipal",
        ...meta,
      },
      [candidate],
    );
    expect(outcome.kind).toBe("minted");
    if (outcome.kind === "minted") {
      expect(outcome.facilityId).not.toBe(candidate.facilityId);
    }
  });

  it("a re-seed never overwrites a verified field (AT(5))", () => {
    const { ledger, candidate } = seedOne(emptyLedger());
    const promoted = promoteToVerified(
      ledger,
      [candidate.facilityId, candidate.courseId],
      meta,
    );
    const beforeStatus = promoted.entries[candidate.facilityId]?.status;
    const outcome = reseedFacility(
      promoted,
      {
        osmRef: "way/102",
        name: "Pebble Hills Golf Club",
        lat: 36.1602,
        lng: -86.78,
        desiredSlug: "pebble-hills",
        ...meta,
      },
      [candidate],
    );
    expect(outcome.kind).toBe("matched");
    if (outcome.kind === "matched") {
      // status stays 'verified' — a re-seed only ever appends to seedRefs.
      expect(outcome.ledger.entries[candidate.facilityId]?.status).toBe(
        beforeStatus,
      );
    }
  });

  it("an ambiguous match (two candidates both within range) is never auto-minted", () => {
    const { ledger, candidate } = seedOne(emptyLedger());
    const secondMint = mintStubFacility(ledger, {
      osmRef: "way/200",
      desiredSlug: "pebble-hills-east",
      ...meta,
    });
    const secondCandidate: ReseedCandidate = {
      facilityId: secondMint.facilityId,
      courseId: secondMint.courseId,
      name: "Pebble Hills Golf Club East", // similar enough name
      lat: 36.1601, // also within 150 m of the incoming ref
      lng: -86.78,
    };
    const outcome = reseedFacility(
      secondMint.ledger,
      {
        osmRef: "way/300",
        name: "Pebble Hills Golf Club",
        lat: 36.1601,
        lng: -86.78,
        desiredSlug: "pebble-hills",
        ...meta,
      },
      [candidate, secondCandidate],
    );
    expect(outcome.kind).toBe("ambiguous");
  });
});

describe("splitCourse (AT(8) split)", () => {
  it("keeps the stub id on one course and records the siblings", () => {
    const minted = mintStubFacility(emptyLedger(), {
      osmRef: "way/1",
      desiredSlug: "big-site",
      ...meta,
    });
    const { ledger, siblingIds } = splitCourse(
      minted.ledger,
      minted.courseId,
      2,
      meta,
    );
    expect(siblingIds).toHaveLength(2);
    const keptEntry = ledger.entries[minted.courseId];
    const splitTransition = keptEntry?.transitions.find(
      (t) => t.type === "split",
    );
    expect(splitTransition?.siblingIds).toEqual(siblingIds);
    for (const siblingId of siblingIds) {
      expect(ledger.entries[siblingId]?.status).toBe("verified");
    }
    // The kept id is never re-keyed.
    expect(ledger.entries[minted.courseId]).toBeDefined();
  });
});

describe("mergeIntoSurvivor + resolveMergedId (A2-04 closure)", () => {
  it("tombstones the merged id and resolves it to the survivor", () => {
    const a = mintStubFacility(emptyLedger(), {
      osmRef: "way/1",
      desiredSlug: "site-a",
      ...meta,
    });
    const b = mintStubFacility(a.ledger, {
      osmRef: "way/2",
      desiredSlug: "site-b",
      ...meta,
    });
    const merged = mergeIntoSurvivor(b.ledger, [b.facilityId], a.facilityId, meta);
    expect(merged.entries[b.facilityId]?.tombstoned).toBe(true);
    expect(merged.entries[b.facilityId]?.mergedInto).toBe(a.facilityId);
    expect(resolveMergedId(merged, b.facilityId)).toBe(a.facilityId);
    // A live id resolves to itself.
    expect(resolveMergedId(merged, a.facilityId)).toBe(a.facilityId);
  });
});

describe("promoteToVerified (AT(8) promotion)", () => {
  it("keeps both ids and appends a verified transition", () => {
    const minted = mintStubFacility(emptyLedger(), {
      osmRef: "way/1",
      desiredSlug: "pebble-hills",
      ...meta,
    });
    const promoted = promoteToVerified(
      minted.ledger,
      [minted.facilityId, minted.courseId],
      meta,
    );
    expect(promoted.entries[minted.facilityId]?.status).toBe("verified");
    expect(promoted.entries[minted.courseId]?.status).toBe("verified");
    expect(
      promoted.entries[minted.facilityId]?.transitions.map((t) => t.type),
    ).toEqual(["minted", "verified"]);
    // Same ids — promotion never re-keys (G3-01).
    expect(promoted.entries[minted.facilityId]?.id).toBe(minted.facilityId);
  });
});
