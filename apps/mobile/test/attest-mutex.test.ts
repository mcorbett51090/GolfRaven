/** The per-key assertion lock (PR #40 gate LOW-1): strictly sequential per key, released on success, on error AND on timeout, independent across keys. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { KeyedMutex, LockAbortedError, LockTimeoutError, assertionLockKey, withAssertionLock } from "../src/attest";

const deferred = <T = void>() => {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((a, b) => {
    resolve = a;
    reject = b;
  });
  return { promise, resolve, reject };
};
const tick = async (n = 50): Promise<void> => {
  for (let i = 0; i < n; i += 1) await Promise.resolve();
};

afterEach(() => vi.useRealTimers());

describe("KeyedMutex", () => {
  it("runs holders of ONE key strictly one after another, in call order, even when the first is slow", async () => {
    const m = new KeyedMutex({ holdTimeoutMs: 60_000 });
    const log: string[] = [];
    const gate1 = deferred();
    const gate2 = deferred();
    const p1 = m.run("k", async () => {
      log.push("1:start");
      await gate1.promise;
      log.push("1:end");
      return 1;
    });
    const p2 = m.run("k", async () => {
      log.push("2:start");
      await gate2.promise;
      log.push("2:end");
      return 2;
    });
    const p3 = m.run("k", async () => {
      log.push("3:start");
      return 3;
    });
    await tick();
    expect(log).toEqual(["1:start"]); // 2 and 3 have not started
    gate1.resolve();
    await tick();
    expect(log).toEqual(["1:start", "1:end", "2:start"]);
    gate2.resolve();
    expect(await Promise.all([p1, p2, p3])).toEqual([1, 2, 3]);
    expect(log).toEqual(["1:start", "1:end", "2:start", "2:end", "3:start"]);
    expect(m.pendingKeys()).toEqual([]);
  });

  it("different keys do not wait for each other", async () => {
    const m = new KeyedMutex({ holdTimeoutMs: 60_000 });
    const log: string[] = [];
    const gate = deferred();
    const a = m.run("a", async () => {
      log.push("a:start");
      await gate.promise;
    });
    const b = m.run("b", async () => {
      log.push("b:start");
    });
    await b;
    expect(log).toEqual(["a:start", "b:start"]);
    gate.resolve();
    await a;
  });

  it("the lock is released when the holder THROWS: the next one runs, and the error reaches the first caller", async () => {
    const m = new KeyedMutex({ holdTimeoutMs: 60_000 });
    const p1 = m.run("k", () => Promise.reject(new Error("boom")));
    const p2 = m.run("k", async () => "second");
    await expect(p1).rejects.toThrow("boom");
    await expect(p2).resolves.toBe("second");
    expect(m.pendingKeys()).toEqual([]);
  });

  it("the lock is released when fn throws SYNCHRONOUSLY", async () => {
    const m = new KeyedMutex({ holdTimeoutMs: 60_000 });
    const p1 = m.run("k", (() => {
      throw new Error("sync boom");
    }) as () => Promise<never>);
    await expect(p1).rejects.toThrow("sync boom");
    await expect(m.run("k", async () => "ok")).resolves.toBe("ok");
  });

  it("the lock is released on TIMEOUT: a hung holder is abandoned with LockTimeoutError and the next waiter runs", async () => {
    vi.useFakeTimers();
    const m = new KeyedMutex({ holdTimeoutMs: 1_000 });
    const hung = deferred<string>(); // never settles
    const p1 = m.run("k", () => hung.promise);
    const p1Settled = p1.then(
      () => "resolved",
      (e: unknown) => e,
    );
    let ran = false;
    const p2 = m.run("k", async () => {
      ran = true;
      return "second";
    });
    await vi.advanceTimersByTimeAsync(999);
    expect(ran).toBe(false); // still held
    await vi.advanceTimersByTimeAsync(2);
    const e1 = await p1Settled;
    expect(e1).toBeInstanceOf(LockTimeoutError);
    expect((e1 as LockTimeoutError).holdTimeoutMs).toBe(1_000);
    await expect(p2).resolves.toBe("second");
    expect(ran).toBe(true);
    // the abandoned holder settling later changes nothing and raises no unhandled rejection
    hung.reject(new Error("late"));
    await vi.advanceTimersByTimeAsync(10);
    expect(m.pendingKeys()).toEqual([]);
  });

  it("the hold timer starts when the holder STARTS, not when it queued: a long wait behind a healthy holder is not a timeout", async () => {
    vi.useFakeTimers();
    const m = new KeyedMutex({ holdTimeoutMs: 1_000 });
    const g1 = deferred();
    const p1 = m.run("k", () => g1.promise);
    let ranSecond = false;
    const p2 = m.run("k", async () => {
      ranSecond = true;
      return "second";
    });
    await vi.advanceTimersByTimeAsync(900);
    g1.resolve();
    await p1;
    await vi.advanceTimersByTimeAsync(1);
    await expect(p2).resolves.toBe("second");
    expect(ranSecond).toBe(true);
  });

  it("the timer is cleared when the holder finishes in time (no stray timer, no late rejection)", async () => {
    vi.useFakeTimers();
    const m = new KeyedMutex({ holdTimeoutMs: 1_000 });
    await m.run("k", async () => "fast");
    expect(vi.getTimerCount()).toBe(0);
  });

  // ---- PR #42 gate HIGH-1: abort, not abandonment ---------------------------------------------------------------------------------------------

  it("after the hold time the guard is ABORTED: check() and effect() throw, so a holder that resumes performs no further side effect; the caller gets LockTimeoutError and the next waiter runs", async () => {
    vi.useFakeTimers();
    const m = new KeyedMutex({ holdTimeoutMs: 1_000 });
    const stuck = deferred();
    const log: string[] = [];
    const p1 = m.run("k", async (g) => {
      await stuck.promise; // stuck in a native call
      log.push("resumed");
      expect(g.aborted).toBe(true);
      g.check(); // throws: the holder stops here
      log.push("NEVER: a side effect after the abort");
    });
    const p1Result = p1.then(() => "resolved", (e: unknown) => e);
    const p2 = m.run("k", async (g) => {
      g.check();
      log.push("second ran");
      return "second";
    });
    await vi.advanceTimersByTimeAsync(1_001);
    expect(await p1Result).toBeInstanceOf(LockTimeoutError);
    await expect(p2).resolves.toBe("second");
    stuck.resolve();
    await vi.advanceTimersByTimeAsync(10);
    expect(log).toEqual(["second ran", "resumed"]);
  });

  it("guard.effect after the abort throws LockAbortedError (the request is never sent)", async () => {
    vi.useFakeTimers();
    const m = new KeyedMutex({ holdTimeoutMs: 1_000 });
    const stuck = deferred();
    let sent = false;
    let thrown: unknown = null;
    const p1 = m.run("k", async (g) => {
      await stuck.promise;
      try {
        await g.effect(async () => {
          sent = true;
        });
      } catch (e) {
        thrown = e;
      }
    });
    p1.catch(() => undefined);
    await vi.advanceTimersByTimeAsync(1_001);
    stuck.resolve();
    await vi.advanceTimersByTimeAsync(10);
    expect(thrown).toBeInstanceOf(LockAbortedError);
    expect(sent).toBe(false);
  });

  it("an effect IN FLIGHT keeps the lock past the hold time: the next waiter does not start until it settles, and the holder's value is returned, not discarded", async () => {
    vi.useFakeTimers();
    const m = new KeyedMutex({ holdTimeoutMs: 1_000 });
    const response = deferred<string>();
    const log: string[] = [];
    const p1 = m.run("k", async (g) => {
      const r = await g.effect(() => response.promise);
      log.push(`got ${r}`);
      return r;
    });
    const p2 = m.run("k", async () => {
      log.push("second ran");
      return "second";
    });
    await vi.advanceTimersByTimeAsync(30_000);
    expect(log).toEqual([]); // far past the hold time: still held, the second has not run
    expect(m.pendingKeys()).toEqual(["k"]);
    response.resolve("answer");
    await expect(p1).resolves.toBe("answer");
    await expect(p2).resolves.toBe("second");
    expect(log).toEqual(["got answer", "second ran"]);
  });

  it("an effect that FAILS after the abort releases the lock too (and an aborted holder's next check() ends it as a LockTimeoutError)", async () => {
    vi.useFakeTimers();
    const m = new KeyedMutex({ holdTimeoutMs: 1_000 });
    const response = deferred<string>();
    const p1 = m.run("k", async (g) => {
      await g.effect(() => response.promise);
      g.check();
    });
    const p1Result = p1.then(() => "resolved", (e: unknown) => e);
    const p2 = m.run("k", async () => "second");
    await vi.advanceTimersByTimeAsync(5_000);
    response.reject(new Error("network"));
    expect(await p1Result).toMatchObject({ message: "network" });
    await expect(p2).resolves.toBe("second");
  });

  it("withAssertionLock / assertionLockKey: one key per (user, device lowercased); the seam shares the lock with a plain run on that key", async () => {
    expect(assertionLockKey("u", "ABC-1")).toBe(assertionLockKey("u", "abc-1"));
    expect(assertionLockKey("u", "abc-1")).not.toBe(assertionLockKey("v", "abc-1"));
    expect(assertionLockKey("u", "abc-1")).not.toBe(assertionLockKey("u", "abc-2"));
    const m = new KeyedMutex({ holdTimeoutMs: 60_000 });
    const gate = deferred();
    const log: string[] = [];
    const a = withAssertionLock(m, "u", "ABC-1", async () => {
      log.push("a");
      await gate.promise;
    });
    const b = m.run(assertionLockKey("u", "abc-1"), async () => {
      log.push("b");
    });
    await tick();
    expect(log).toEqual(["a"]);
    gate.resolve();
    await Promise.all([a, b]);
    expect(log).toEqual(["a", "b"]);
  });
});
