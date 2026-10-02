// supabase/tests/unit/edge-selfcheck-gate.test.ts
//
// Edge role PR3: the SCHEDULE of the edge connection's self-check (supabase/functions/_shared/edge-selfcheck-gate.ts), proved without a
// database against a fake check and a fake clock. What the check itself asserts (login is not super / BYPASSRLS / a forbidden member) is
// proved against a real cluster in supabase/tests/integration/edge-role.deno.test.ts, which also proves that privileged.ts is wired through
// this gate (so a refusal appears at the NEXT transaction after the interval).
import { describe, expect, it } from "vitest";
import { makeSelfCheckGate } from "../../functions/_shared/edge-selfcheck-gate.js";

function harness(over: { intervalMs?: number; everyNCalls?: number } = {}) {
  let t = 1_000_000;
  const log: string[] = [];
  let failWith: Error | null = null;
  let hold: Promise<void> | null = null;
  const gate = makeSelfCheckGate({
    intervalMs: over.intervalMs ?? 60_000,
    everyNCalls: over.everyNCalls,
    now: () => t,
    check: async () => {
      log.push("check");
      if (hold) await hold;
      if (failWith) throw failWith;
    },
  });
  return {
    gate,
    log,
    advance: (ms: number) => (t += ms),
    failWith: (e: Error | null) => (failWith = e),
    holdChecks: () => {
      let release!: () => void;
      hold = new Promise<void>((r) => (release = r));
      return () => {
        hold = null;
        release();
      };
    },
  };
}

describe("edge self-check schedule", () => {
  it("the first call checks; calls inside the interval cost nothing", async () => {
    const h = harness();
    await h.gate.ensure();
    await h.gate.ensure();
    h.advance(59_999);
    await h.gate.ensure();
    expect(h.log).toEqual(["check"]);
    expect(h.gate.checksStarted).toBe(1);
  });

  it("the interval is a re-check: once it has elapsed the NEXT call checks again, and a change made in between is refused from then on", async () => {
    const h = harness();
    await h.gate.ensure();
    h.failWith(new Error("edge_gateway gained BYPASSRLS")); // the operator's change, after the first success
    await h.gate.ensure(); // still inside the interval: remembered (the documented window)
    h.advance(60_000);
    await expect(h.gate.ensure()).rejects.toThrow("gained BYPASSRLS");
    expect(h.log).toEqual(["check", "check"]);
  });

  it("a FAILURE is never remembered: every following call checks again, and recovery is seen at once", async () => {
    const h = harness();
    h.failWith(new Error("member of service_role"));
    await expect(h.gate.ensure()).rejects.toThrow("member of service_role");
    await expect(h.gate.ensure()).rejects.toThrow("member of service_role");
    h.failWith(null);
    await h.gate.ensure();
    await h.gate.ensure(); // and now it is trusted again
    expect(h.log).toEqual(["check", "check", "check"]);
  });

  it("a failed re-check withdraws the earlier success: nothing runs on the old trust", async () => {
    const h = harness();
    await h.gate.ensure();
    h.advance(60_000);
    h.failWith(new Error("nope"));
    await expect(h.gate.ensure()).rejects.toThrow("nope");
    h.advance(1); // well inside what WOULD have been a fresh window
    await expect(h.gate.ensure()).rejects.toThrow("nope");
    expect(h.log).toEqual(["check", "check", "check"]);
  });

  it("the call budget re-checks every N passes even inside the interval", async () => {
    const h = harness({ everyNCalls: 3 });
    await h.gate.ensure(); // check #1
    await h.gate.ensure();
    await h.gate.ensure();
    await h.gate.ensure(); // three passes since the check: this is the 3rd cheap one
    expect(h.log).toEqual(["check"]);
    h.failWith(new Error("drifted"));
    await expect(h.gate.ensure()).rejects.toThrow("drifted"); // the budget ran out: re-check
    expect(h.log).toEqual(["check", "check"]);
  });

  it("callers that arrive while a re-check is in flight wait for THAT check (one check, not one per caller, and nobody skips ahead on the old success)", async () => {
    const h = harness();
    await h.gate.ensure();
    h.advance(60_000);
    const release = h.holdChecks();
    h.failWith(new Error("drifted"));
    const calls = [h.gate.ensure(), h.gate.ensure(), h.gate.ensure()];
    expect(h.gate.checksStarted).toBe(2); // the first success, plus ONE re-check for all three callers
    release();
    const settled = await Promise.allSettled(calls);
    expect(settled.every((s) => s.status === "rejected")).toBe(true);
    expect(h.log).toEqual(["check", "check"]);
  });

  it("an interval of 0 re-checks on every call", async () => {
    const h = harness({ intervalMs: 0 });
    await h.gate.ensure();
    await h.gate.ensure();
    await h.gate.ensure();
    expect(h.log).toEqual(["check", "check", "check"]);
  });

  it("a check that throws synchronously is a rejection, not an escaped exception, and is not remembered", async () => {
    let n = 0;
    const gate = makeSelfCheckGate({
      intervalMs: 60_000,
      check: () => {
        n += 1;
        if (n === 1) throw new Error("GOLFRAVEN_EDGE_DB_URL is not set");
        return Promise.resolve();
      },
    });
    await expect(gate.ensure()).rejects.toThrow("not set");
    await gate.ensure();
    expect(n).toBe(2);
  });

  it("reset() forgets the trust (a new pool is checked from scratch) and a check still in flight cannot re-trust the new state", async () => {
    const h = harness();
    await h.gate.ensure();
    h.gate.reset();
    await h.gate.ensure();
    expect(h.log).toEqual(["check", "check"]);

    const release = h.holdChecks();
    h.advance(60_000);
    const inflight = h.gate.ensure(); // a re-check begins...
    h.gate.reset(); // ...and the pool is replaced while it is still running
    release();
    await inflight;
    await h.gate.ensure(); // the stale success did not mark the new pool as checked
    expect(h.log.length).toBe(4);
  });
});
