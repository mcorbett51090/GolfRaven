// supabase/tests/unit/partner-programme-shape.test.ts
//
// The strict body shapes of `programme-config` (S6): the facility programme and the trail programme. Pure: no ports. Design 133 found by driving the lane against the real database that the facility shape could not
// express `false` for its three nullable booleans: `parseOptionalBool` answered an invalid value with the literal `false`, and `false` is also what an operator means by "this facility does not stock markers", so every such
// body was a 400. The handler suite (partner-programme-handler.test.ts) feeds the handler a parsed `true` or a mock; nothing there sent a `false`.

import { describe, expect, it } from "vitest";
import {
  parseFacilityProgrammeUpsertBody,
  parseTrailProgrammeUpsertBody,
} from "../../functions/_shared/partner/programme-shape.ts";

const facility = (over: Record<string, unknown> = {}) => ({
  trailId: "trl_t",
  facilityId: "fac_x",
  participation: "accepted",
  qrMode: "rotating",
  ...over,
});
const BOOLS = ["stocksMarkers", "holdsSpecialMarker", "staffNetwork"] as const;

describe("parseFacilityProgrammeUpsertBody: the three nullable booleans", () => {
  it("accepts false as a value (the facility does NOT stock markers / hold the special marker / have a staff network), and true", () => {
    for (const field of BOOLS) {
      for (const value of [false, true]) {
        const r = parseFacilityProgrammeUpsertBody(
          facility({ [field]: value }),
        );
        expect(r.ok, `${field}: ${value}`).toBe(true);
        if (r.ok) expect(r.value[field]).toBe(value);
      }
    }
    const all = parseFacilityProgrammeUpsertBody(
      facility({
        stocksMarkers: false,
        holdsSpecialMarker: false,
        staffNetwork: false,
      }),
    );
    expect(
      all.ok && [
        all.value.stocksMarkers,
        all.value.holdsSpecialMarker,
        all.value.staffNetwork,
      ],
    ).toEqual([false, false, false]);
  });

  it("reads null and an omitted field as null (unknown), which is not false", () => {
    for (const field of BOOLS) {
      for (const over of [{ [field]: null }, {}]) {
        const r = parseFacilityProgrammeUpsertBody(facility(over));
        expect(r.ok && r.value[field]).toBeNull();
      }
    }
  });

  it("refuses anything that is not a boolean or null, and names the field", () => {
    for (const field of BOOLS) {
      for (const bad of ["false", "true", 0, 1, [], {}]) {
        const r = parseFacilityProgrammeUpsertBody(facility({ [field]: bad }));
        expect(r.ok, `${field}: ${JSON.stringify(bad)}`).toBe(false);
        if (!r.ok) expect(r.issues.map((i) => i.path)).toContain(field);
      }
    }
  });
});

describe("parseFacilityProgrammeUpsertBody: the rest of the body is unchanged", () => {
  it("still requires a participation and a qrMode, bounds the note and refuses an unknown key", () => {
    expect(
      parseFacilityProgrammeUpsertBody(facility({ participation: "maybe" })).ok,
    ).toBe(false);
    expect(
      parseFacilityProgrammeUpsertBody(facility({ qrMode: "none" })).ok,
    ).toBe(false);
    expect(
      parseFacilityProgrammeUpsertBody(facility({ wifiNote: "x".repeat(501) }))
        .ok,
    ).toBe(false);
    expect(
      parseFacilityProgrammeUpsertBody(facility({ wifiNote: "x".repeat(500) }))
        .ok,
    ).toBe(true);
    expect(parseFacilityProgrammeUpsertBody(facility({ extra: 1 })).ok).toBe(
      false,
    );
  });
});

describe("parseTrailProgrammeUpsertBody: its booleans were never affected", () => {
  it("accepts false for markerRequiresCompletion and webPlayerFlow", () => {
    const r = parseTrailProgrammeUpsertBody({
      trailId: "trl_t",
      status: "live",
      markerSource: "any_purchase",
      markerRequiresCompletion: false,
      specialMarkerLowThreshold: 3,
      webPlayerFlow: false,
    });
    expect(
      r.ok && [r.value.markerRequiresCompletion, r.value.webPlayerFlow],
    ).toEqual([false, false]);
  });
});
