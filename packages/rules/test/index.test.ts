import { describe, expect, it } from "vitest";
import * as packageIndex from "../src/index.js";

describe("@golfraven/rules (M5, fifth gate)", () => {
  it("no longer exports the P0 POLICY_VERSION placeholder", () => {
    // M5: removed — it had one consumer (this test, previously pinning it
    // at 0) and sat as a footgun beside `SCORE_PLAY_POLICY_VERSION`, the
    // real, independently versioned, content-hash-pinned policy version
    // (see `score-play-policy-hash.test.ts`).
    expect("POLICY_VERSION" in packageIndex).toBe(false);
  });

  it("still exports SCORE_PLAY_POLICY_VERSION, the one real policy version", () => {
    expect(packageIndex.SCORE_PLAY_POLICY_VERSION).toBe(1);
  });
});
