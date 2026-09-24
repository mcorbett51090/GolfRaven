/**
 * S3 (gate review): "Every field aggregate resolves ids through the
 * `mergedInto` closure (A2-04, §4.1 line 590). A play on a tombstoned id
 * counts for its survivor, and never twice."
 */
import { describe, expect, it } from "vitest";
import { type CourseId, type DesignerId, type FacilityId, type TrailId } from "@golfraven/catalog";
import { countDistinct, countWhere, maxCountBy, type AggregateContext } from "../src/aggregates.js";
import type { Play } from "../src/completion.js";
import { nextId } from "./test-ids.js";

describe("S3: field aggregates resolve mergedInto before deduping", () => {
  it("a play recorded against a tombstoned course id counts for its survivor, and only once", () => {
    const facilityId = nextId("fac") as FacilityId;
    const x = nextId("crs") as CourseId; // tombstoned
    const y = nextId("crs") as CourseId; // survivor
    const designerId = nextId("dsg") as DesignerId;
    const ctx: AggregateContext = {
      courses: {
        [y]: { id: y, facilityId, region: "CA-NB", country: "CA", designers: [designerId], verified: true },
      },
      ledger: {
        entries: {
          [x]: { id: x, kind: "crs", transitions: [], tombstoned: true, mergedInto: y },
          [y]: { id: y, kind: "crs", transitions: [] },
        },
      },
      trails: {},
    };
    // A play recorded against the OLD (tombstoned) id.
    const plays: Play[] = [{ courseId: x, localDate: "2026-01-01", scoreBadge: 1 }];

    expect(countDistinct("region", ctx, plays, {})).toBe(1);
    expect(countWhere("designer", designerId, ctx, plays, {})).toBe(1);

    // A SECOND play against the SURVIVOR's own id, same real course —
    // must not double-count.
    const plays2: Play[] = [
      { courseId: x, localDate: "2026-01-01", scoreBadge: 1 },
      { courseId: y, localDate: "2026-02-01", scoreBadge: 1 },
    ];
    expect(maxCountBy("designer", ctx, plays2, {})).toBe(1);
    expect(countDistinct("region", ctx, plays2, {})).toBe(1);
  });

  it("field: 'trail' resolves a roster member's own tombstoned course reference to its survivor too", () => {
    const facilityId = nextId("fac") as FacilityId;
    const trailId = nextId("trl") as TrailId;
    const x = nextId("crs") as CourseId;
    const y = nextId("crs") as CourseId;
    const ctx: AggregateContext = {
      courses: { [y]: { id: y, facilityId, verified: true } },
      ledger: {
        entries: {
          [x]: { id: x, kind: "crs", transitions: [], tombstoned: true, mergedInto: y },
          [y]: { id: y, kind: "crs", transitions: [] },
        },
      },
      trails: {
        [trailId]: [
          {
            version: 1,
            effectiveFrom: "2026-01-01",
            source: { url: "https://example.com/r", retrieved: "2026-01-01" },
            verifiedAt: "2026-01-01",
            completionUnit: "course",
            markerUnit: "facility",
            completionRule: { kind: "all" },
            markerRule: { kind: "all" },
            // The roster STILL lists the pre-merge id, x.
            members: [{ unit: "course", courseId: x }],
          },
        ],
      },
    };
    const plays: Play[] = [{ courseId: y, localDate: "2026-01-01", scoreBadge: 1 }];
    expect(countDistinct("trail", ctx, plays, {})).toBe(1);
  });
});
