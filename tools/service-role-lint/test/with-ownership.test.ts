import { describe, expect, it, vi } from "vitest";
import { withOwnership } from "../../../supabase/functions/_shared/privileged.ts";

// build plan §4.7.1a (docs/golf-trails/02-build-plan.md:1189-1196). B6
// (gate round 2): "withOwnership must fail closed. Until it is properly
// implemented, it throws, and it never returns the raw supabase-js
// client."

describe("withOwnership (stub) fails closed", () => {
  it("throws synchronously rather than returning a client or a value", () => {
    const op = vi.fn();
    expect(() => withOwnership({ uid: "u1", role: "authenticated" }, op)).toThrow();
  });

  it("never invokes the callback — no privileged client is ever handed to caller code", () => {
    const op = vi.fn();
    try {
      withOwnership({ uid: "u1", role: "authenticated" }, op);
    } catch {
      // expected
    }
    expect(op).not.toHaveBeenCalled();
  });
});
