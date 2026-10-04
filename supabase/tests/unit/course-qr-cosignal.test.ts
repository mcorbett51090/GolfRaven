// supabase/tests/unit/course-qr-cosignal.test.ts
//
// Does a scan's fix qualify as a co-signal (_shared/course-qr/cosignal.ts)? A DRIFT GUARD against the scorer's own predicate: `coSignalGrade` is the twin of packages/rules
// `isQualityCoSignalFix` (the predicate `presence_signal` itself uses), kept in lock-step by running BOTH over every combination of the fields either one reads. If the scorer's
// definition of a co-signal changes and this twin does not, this test fails.

import { describe, expect, it } from "vitest";
import { COSIGNAL_ACCURACY_METERS_MAX, coSignalGrade } from "../../functions/_shared/course-qr/cosignal.ts";
import type { DerivedFix } from "../../functions/_shared/evidence/derive-fix.ts";
import { ACCURACY_METERS_MAX, isQualityCoSignalFix, resolveFixGrade, type AppFix } from "../../../packages/rules/src/internal/classify.ts";

const FAC = "fac_x";

function fix(over: Partial<DerivedFix>): DerivedFix {
  return {
    fixId: "fix1",
    facilityId: FAC,
    fromApp: true,
    simulated: false,
    foreground: true,
    challenge: "prefetched",
    token: { present: true, grade: "attested" },
    verificationTier: "play-verified",
    geometryKind: "polygon",
    insideBuffer: true,
    accuracyMeters: 12,
    capturedAt: 1_790_000_000_000,
    localDate: "2026-09-26",
    ...over,
  };
}

describe("the co-signal predicate", () => {
  it("uses the scorer's accuracy ceiling", () => {
    expect(COSIGNAL_ACCURACY_METERS_MAX).toBe(ACCURACY_METERS_MAX);
  });

  it("a polygon, play-verified, inside-the-buffer, foreground, non-simulated, from-the-app fix against a challenge qualifies, with the token's grade", () => {
    expect(coSignalGrade(fix({}), FAC)).toBe("attested");
    expect(coSignalGrade(fix({ token: { present: true, grade: "unattestable" } }), FAC)).toBe("unattestable");
    expect(coSignalGrade(fix({ challenge: "live" }), FAC)).toBe("attested");
  });

  it("each condition on its own removes it: a failed grade, no token, no challenge, a simulated or background fix, a radius circle, an unverified course, outside the buffer, poor accuracy, another facility", () => {
    const refused: Array<[string, Partial<DerivedFix>]> = [
      ["failed grade", { token: { present: true, grade: "failed" } }],
      ["no token", { token: { present: false, hardwareSupportsAttestation: false }, challenge: "none" }],
      ["no challenge", { challenge: "none" }],
      ["simulated", { simulated: true }],
      ["background", { foreground: false }],
      ["not from the app", { fromApp: false }],
      ["radius circle", { geometryKind: "radius" }],
      ["listed-verified only", { verificationTier: "listed-verified" }],
      ["unverified", { verificationTier: "unverified" }],
      ["outside the buffer", { insideBuffer: false }],
      ["poor accuracy", { accuracyMeters: 50.01 }],
      ["negative accuracy", { accuracyMeters: -1 }],
      ["NaN accuracy", { accuracyMeters: Number.NaN }],
      ["another facility", { facilityId: "fac_y" }],
    ];
    for (const [why, over] of refused) expect(coSignalGrade(fix(over), FAC), why).toBeNull();
    expect(coSignalGrade(fix({ accuracyMeters: 50 }), FAC)).toBe("attested"); // the ceiling itself is inside
    expect(coSignalGrade(fix({ accuracyMeters: 0 }), FAC)).toBe("attested");
  });

  it("agrees with the scorer's isQualityCoSignalFix over EVERY combination of the fields either reads (the states deriveFix can produce)", () => {
    let n = 0;
    const bools = [true, false];
    const tokens: DerivedFix["token"][] = [
      { present: true, grade: "attested" },
      { present: true, grade: "unattestable" },
      { present: true, grade: "failed" },
    ];
    for (const fromApp of bools)
      for (const simulated of bools)
        for (const foreground of bools)
          for (const challenge of ["live", "prefetched"] as const)
            for (const token of tokens)
              for (const accuracyMeters of [0, 12, 50, 50.5, -1])
                for (const geometryKind of ["polygon", "radius"] as const)
                  for (const verificationTier of ["unverified", "listed-verified", "play-verified"] as const)
                    for (const insideBuffer of bools)
                      for (const facilityId of [FAC, "fac_other"]) {
                        const f = fix({ fromApp, simulated, foreground, challenge, token, accuracyMeters, geometryKind, verificationTier, insideBuffer, facilityId });
                        const mine = coSignalGrade(f, FAC) !== null;
                        const theirs = isQualityCoSignalFix(f as unknown as AppFix, FAC);
                        expect(mine, JSON.stringify(f)).toBe(theirs);
                        if (mine) expect(coSignalGrade(f, FAC)).toBe(resolveFixGrade(f.token as never));
                        n += 1;
                      }
    expect(n).toBe(2 * 2 * 2 * 2 * 3 * 5 * 2 * 3 * 2 * 2);
  });

  it("a fix with no challenge is never a co-signal in either, whatever else it carries (deriveFix produces `challenge: none` exactly when there is no consumed token)", () => {
    const f = fix({ challenge: "none", token: { present: false, hardwareSupportsAttestation: false } });
    expect(coSignalGrade(f, FAC)).toBeNull();
    expect(isQualityCoSignalFix(f as unknown as AppFix, FAC)).toBe(false);
  });
});
