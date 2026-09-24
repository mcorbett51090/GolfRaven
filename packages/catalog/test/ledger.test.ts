import { describe, expect, it } from "vitest";
import {
  detectMergeCycle,
  emptyLedger,
  findLedgerIdBySeedRef,
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
    expect(
      Object.keys((outcome as { ledger: IdLedger }).ledger.entries),
    ).toHaveLength(before);
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
    const merged = mergeIntoSurvivor(
      b.ledger,
      [b.facilityId],
      a.facilityId,
      meta,
    );
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

  it("S8: rejects a second verified transition", () => {
    const minted = mintStubFacility(emptyLedger(), {
      osmRef: "way/1",
      desiredSlug: "pebble-hills",
      ...meta,
    });
    const promoted = promoteToVerified(
      minted.ledger,
      [minted.facilityId],
      meta,
    );
    expect(() =>
      promoteToVerified(promoted, [minted.facilityId], meta),
    ).toThrow();
  });

  it("S8: rejects promoting a tombstoned id", () => {
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
    const merged = mergeIntoSurvivor(
      b.ledger,
      [b.facilityId],
      a.facilityId,
      meta,
    );
    expect(() => promoteToVerified(merged, [b.facilityId], meta)).toThrow();
  });
});

describe("mergeIntoSurvivor guards (S8, gate review post-e9b3ab0)", () => {
  it("rejects a self-merge", () => {
    const a = mintStubFacility(emptyLedger(), {
      osmRef: "way/1",
      desiredSlug: "site-a",
      ...meta,
    });
    expect(() =>
      mergeIntoSurvivor(a.ledger, [a.facilityId], a.facilityId, meta),
    ).toThrow();
  });

  it("rejects a merge across kinds (course into facility)", () => {
    const a = mintStubFacility(emptyLedger(), {
      osmRef: "way/1",
      desiredSlug: "site-a",
      ...meta,
    });
    expect(() =>
      mergeIntoSurvivor(a.ledger, [a.courseId], a.facilityId, meta),
    ).toThrow();
  });

  it("rejects a merge cycle", () => {
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
    const merged = mergeIntoSurvivor(
      b.ledger,
      [b.facilityId],
      a.facilityId,
      meta,
    );
    // b already resolves to a; merging a into b would close a 2-cycle.
    expect(() =>
      mergeIntoSurvivor(merged, [a.facilityId], b.facilityId, meta),
    ).toThrow();
  });
});

describe("mintSlug rejects un-slugified input (nit)", () => {
  it("throws on a raw, non-slugified name", () => {
    expect(() => mintSlug(emptyLedger(), "Pine Hills!")).toThrow();
    expect(() => mintSlug(emptyLedger(), "Pine Hills")).toThrow(); // space
    expect(() => mintSlug(emptyLedger(), "pine--hills")).toThrow(); // doubled hyphen
    expect(() => mintSlug(emptyLedger(), "-pine-hills")).toThrow(); // leading hyphen
  });
  it("accepts an already-slugified name", () => {
    expect(mintSlug(emptyLedger(), "pine-hills")).toBe("pine-hills");
  });
});

describe("blocking #4 (gate review post-e9b3ab0): re-seed must not mint a second id", () => {
  it("a known ref with an EMPTY candidate list mints nothing (whole-ledger lookup)", () => {
    const minted = mintStubFacility(emptyLedger(), {
      osmRef: "relation/9",
      desiredSlug: "pine-hills",
      ...meta,
    });
    const before = Object.keys(minted.ledger.entries).length;
    const outcome = reseedFacility(
      minted.ledger,
      {
        osmRef: "relation/9",
        name: "Pine Hills Golf Club",
        lat: 36.003,
        lng: -86.0,
        desiredSlug: "pine-hills",
        ...meta,
      },
      [], // no candidates supplied at all
    );
    expect(outcome.kind).toBe("already-known");
    if (outcome.kind === "already-known") {
      expect(outcome.facilityId).toBe(minted.facilityId);
      expect(outcome.courseId).toBe(minted.courseId);
    }
    expect(Object.keys(minted.ledger.entries)).toHaveLength(before);
  });

  it("the ref of a MERGED-AWAY facility resolves to its survivor and mints nothing", () => {
    const m = mintStubFacility(emptyLedger(), {
      osmRef: "way/1",
      desiredSlug: "pine-hills",
      ...meta,
    });
    const m2 = mintStubFacility(m.ledger, {
      osmRef: "way/50",
      desiredSlug: "oak",
      ...meta,
    });
    const merged = mergeIntoSurvivor(
      m2.ledger,
      [m2.facilityId],
      m.facilityId,
      meta,
    );
    const before = Object.keys(merged.entries).length;

    // Re-seeing way/50 (the tombstoned facility's own ref) on every re-seed
    // must resolve to the SURVIVOR (m), never mint a second id.
    for (let i = 0; i < 3; i += 1) {
      const outcome = reseedFacility(
        merged,
        {
          osmRef: "way/50",
          name: "Oak",
          lat: 40,
          lng: -80,
          desiredSlug: "oak",
          ...meta,
        },
        [
          {
            facilityId: m2.facilityId,
            courseId: m2.courseId,
            name: "Oak",
            lat: 40,
            lng: -80,
          },
        ],
      );
      expect(outcome.kind).toBe("already-known");
      if (outcome.kind === "already-known") {
        expect(outcome.facilityId).toBe(m.facilityId);
      }
    }
    expect(Object.keys(merged.entries)).toHaveLength(before);
  });
});

describe("S9 (gate review post-e9b3ab0): proximity without a name match is ambiguous", () => {
  it('"Pine Hills GC" near "Pine Hills Golf Club" goes to ambiguous, not auto-mint', () => {
    const minted = mintStubFacility(emptyLedger(), {
      osmRef: "way/1",
      desiredSlug: "pine-hills",
      ...meta,
    });
    const candidate: ReseedCandidate = {
      facilityId: minted.facilityId,
      courseId: minted.courseId,
      name: "Pine Hills Golf Club",
      lat: 36.0,
      lng: -86.0,
    };
    // "Pine Hills GC" vs "Pine Hills Golf Club" — within 150 m, but below
    // the 0.8 name-similarity bar.
    const outcome = reseedFacility(
      minted.ledger,
      {
        osmRef: "way/2",
        name: "Pine Hills GC",
        lat: 36.0,
        lng: -86.0,
        desiredSlug: "pine-hills-gc",
        ...meta,
      },
      [candidate],
    );
    expect(outcome.kind).toBe("ambiguous");
  });
});

describe("item 3 (gate review round 2): merge re-parenting (§4.2 row 2)", () => {
  it("mergeIntoSurvivor re-parents the merged facility's course(s) under the survivor", () => {
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
    expect(b.ledger.entries[b.courseId]?.facilityId).toBe(b.facilityId);

    const merged = mergeIntoSurvivor(
      b.ledger,
      [b.facilityId],
      a.facilityId,
      meta,
    );

    // The course's own id is unchanged; only its facilityId link moves.
    expect(merged.entries[b.courseId]).toBeDefined();
    expect(merged.entries[b.courseId]?.facilityId).toBe(a.facilityId);
    expect(merged.entries[b.facilityId]?.tombstoned).toBe(true);
  });

  it("findLedgerIdBySeedRef resolves a merged facility's ref to {survivor facility, ORIGINAL course}", () => {
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
    const merged = mergeIntoSurvivor(
      b.ledger,
      [b.facilityId],
      a.facilityId,
      meta,
    );

    const found = findLedgerIdBySeedRef(merged, "way/2");
    expect(found?.facilityId).toBe(a.facilityId); // the survivor
    expect(found?.courseId).toBe(b.courseId); // b's OWN course, re-parented — not a.courseId
  });

  it("does not confuse the survivor's own course with the re-parented one when both exist", () => {
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
    const merged = mergeIntoSurvivor(
      b.ledger,
      [b.facilityId],
      a.facilityId,
      meta,
    );

    // The survivor "a" now has TWO courses under it: its own (a.courseId)
    // and the re-parented one (b.courseId). Looking up each ref must
    // return the course that ref actually belongs to, not just "any"
    // course under the survivor facility.
    expect(findLedgerIdBySeedRef(merged, "way/1")?.courseId).toBe(a.courseId);
    expect(findLedgerIdBySeedRef(merged, "way/2")?.courseId).toBe(b.courseId);
  });

  it("splitCourse's siblings inherit the kept course's facilityId (unaffected by re-parenting)", () => {
    const a = mintStubFacility(emptyLedger(), {
      osmRef: "way/1",
      desiredSlug: "site-a",
      ...meta,
    });
    const { ledger, siblingIds } = splitCourse(a.ledger, a.courseId, 2, meta);
    for (const siblingId of siblingIds) {
      expect(ledger.entries[siblingId]?.facilityId).toBe(a.facilityId);
    }
  });
});

describe("nit (gate review round 2): a mergedInto cycle is reported, not thrown", () => {
  it("resolveMergedId stops and returns a value instead of throwing on a self-cycle", () => {
    const a = mintStubFacility(emptyLedger(), {
      osmRef: "way/1",
      desiredSlug: "site-a",
      ...meta,
    });
    const corrupted: IdLedger = {
      entries: {
        ...a.ledger.entries,
        [a.facilityId]: {
          ...a.ledger.entries[a.facilityId]!,
          mergedInto: a.facilityId,
          tombstoned: true,
        },
      },
    };
    expect(() => resolveMergedId(corrupted, a.facilityId)).not.toThrow();
    expect(resolveMergedId(corrupted, a.facilityId)).toBe(a.facilityId);
  });

  it("detectMergeCycle reports true for a self-cycle and false for a normal chain", () => {
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
    const merged = mergeIntoSurvivor(
      b.ledger,
      [b.facilityId],
      a.facilityId,
      meta,
    );
    expect(detectMergeCycle(merged, b.facilityId)).toBe(false);

    const corrupted: IdLedger = {
      entries: {
        ...merged.entries,
        [a.facilityId]: {
          ...merged.entries[a.facilityId]!,
          mergedInto: b.facilityId,
        },
      },
    };
    // Now a -> b -> a: a genuine cycle.
    expect(detectMergeCycle(corrupted, a.facilityId)).toBe(true);
  });
});
