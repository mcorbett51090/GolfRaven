/**
 * A keyed async mutex for the App Attest assertion lock, with COOPERATIVE ABORT.
 *
 * Why (PR #40 gate LOW-1): an App Attest key's assertion counter is strictly monotonic at the server and SHARED by `checkin-token` and `rewards-activate`.
 * If two assertions are generated back to back and their requests arrive out of order, the one that arrives second carries the lower counter and an honest
 * client is graded `failed` plus a fraud signal. So every assertion is held in this mutex from `generateAssertion` until the HTTP response of the request that
 * carries it has returned or failed; the next one is generated only after that.
 *
 * Why abort (PR #42 gate HIGH-1): a lock that merely STOPS WAITING for a holder, while the holder goes on running, lets the abandoned holder write state, register
 * a key or send a request OUTSIDE the lock, concurrently with the next holder: the client then keeps key A while the server holds key B, and every later check-in
 * is graded `failed`. So a holder is not abandoned, it is told to stop:
 *   - `run(key, fn)` gives `fn` a `LockGuard`. After `holdTimeoutMs` the guard is ABORTED: `guard.check()` (called by the holder before EVERY side effect) then throws
 *     `LockAbortedError`, so an aborted holder performs no further effect.
 *   - A SERVER-SIDE effect already SENT (`guard.effect(...)`: a registration, the request that carries an assertion) is never abandoned: the lock is kept until it
 *     settles (the HTTP timeout, 20 s, bounds that), because releasing it would let the next holder's request overlap it. The hold timeout never releases a lock whose
 *     holder has an effect in flight.
 *   - With no effect in flight the lock IS released at the timeout (the holder may be stuck in a native call): the caller gets `LockTimeoutError`, and the holder, if it
 *     ever resumes, is stopped by its next `check()`. Its eventual native result is discarded.
 *   - A holder that finishes with a value after the abort (its last effect was in flight) still returns that value: the response of a request that was sent is not thrown away.
 * The lock is always released when `fn` settles, on error as well as on success.
 *
 * NOT RE-ENTRANT. A holder must never call `redeem` / `activate` / `withAssertionLock` for the SAME key from inside its own `fn` (each takes this lock, so the inner call would wait for the
 * outer holder, which is waiting for it). A nested `run` that starts in the synchronous part of the holder (`await redeem(...)` as its first step: the common slip) is refused at once with
 * `LockReentryError`; one that starts after an await cannot be told from another flow queueing for the lock (there is no async context to ask on Hermes), so it is not detected and ends at the
 * hold timeout (`LockTimeoutError`). The holder gets its own steps through the `guard`, never through another entry point.
 */
export class LockTimeoutError extends Error {
  constructor(readonly key: string, readonly holdTimeoutMs: number) {
    super(`lock "${key}" was held longer than ${holdTimeoutMs} ms`);
    this.name = "LockTimeoutError";
  }
}

/** Thrown by `LockGuard.check()` once the hold time has elapsed; `run` turns it into `LockTimeoutError`. */
export class LockAbortedError extends Error {
  constructor() {
    super("the lock's hold time elapsed: this holder must not perform any further side effect");
    this.name = "LockAbortedError";
  }
}

/** `run` was called for a key whose holder is still in the synchronous start of its own `fn`: a nested acquisition, which would deadlock. Rejected, never waited on. */
export class LockReentryError extends Error {
  constructor(readonly key: string) {
    super(`lock "${key}" was requested from inside its own holder: the assertion lock is not re-entrant (never call redeem / activate inside withAssertionLock)`);
    this.name = "LockReentryError";
  }
}

export interface LockGuard {
  /** True once the hold time has elapsed. */
  readonly aborted: boolean;
  /** Throws `LockAbortedError` when aborted. Call it immediately before EVERY side effect (a state write, a native call that matters, an HTTP request). */
  check(): void;
  /** Runs a server-side effect: `check()`, then `f()`, and the lock cannot be released (nor the holder abandoned) while `f()` is pending. */
  effect<T>(f: () => Promise<T>): Promise<T>;
  /** Runs a state write that MUST follow a request already sent (the server has applied it, so the record has to say so): no abort check, but the lock cannot be released (nor the holder
   * abandoned, its real answer thrown away) while `f()` is pending. `f()` is the write only: it makes no request and starts nothing new. */
  settle<T>(f: () => Promise<T>): Promise<T>;
}

export interface KeyedMutexOptions {
  /** Longest a holder may keep running its own steps before it is told to stop. */
  holdTimeoutMs: number;
}

export class KeyedMutex {
  private readonly tails = new Map<string, Promise<void>>();
  /** Keys whose holder is inside the synchronous start of `fn` right now (`LockReentryError`). */
  private readonly starting = new Set<string>();

  constructor(private readonly opts: KeyedMutexOptions) {}

  run<T>(key: string, fn: (guard: LockGuard) => Promise<T>): Promise<T> {
    if (this.starting.has(key)) return Promise.reject(new LockReentryError(key));
    const prev = this.tails.get(key) ?? Promise.resolve();
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = prev.then(() => held);
    this.tails.set(key, tail);
    let released = false;
    const cleanup = (): void => {
      if (released) return;
      released = true;
      release();
      if (this.tails.get(key) === tail) this.tails.delete(key);
    };
    return (async () => {
      await prev; // never rejects: a tail is only ever `held`, which resolves
      return new Promise<T>((resolve, reject) => {
        let aborted = false;
        let inFlight = 0;
        let settled = false;
        const finish = (f: () => void): void => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          f();
        };
        const guard: LockGuard = {
          get aborted() {
            return aborted;
          },
          check() {
            if (aborted) throw new LockAbortedError();
          },
          async effect<R>(f: () => Promise<R>): Promise<R> {
            if (aborted) throw new LockAbortedError();
            inFlight += 1;
            try {
              return await f();
            } finally {
              inFlight -= 1;
            }
          },
          async settle<R>(f: () => Promise<R>): Promise<R> {
            inFlight += 1;
            try {
              return await f();
            } finally {
              inFlight -= 1;
            }
          },
        };
        const timer = setTimeout(() => {
          aborted = true;
          // With a server-side effect in flight the lock stays held until the holder settles. Otherwise the holder is abandoned (it stops at its next `check()`).
          if (inFlight === 0) {
            finish(() => {
              cleanup();
              reject(new LockTimeoutError(key, this.opts.holdTimeoutMs));
            });
          }
        }, this.opts.holdTimeoutMs);
        Promise.resolve()
          .then(() => {
            this.starting.add(key);
            try {
              return fn(guard);
            } finally {
              this.starting.delete(key); // the synchronous start is over: from here another flow may legitimately queue
            }
          })
          .then(
            (v) => finish(() => {
              cleanup();
              resolve(v);
            }),
            (e: unknown) => finish(() => {
              cleanup();
              reject(e instanceof LockAbortedError ? new LockTimeoutError(key, this.opts.holdTimeoutMs) : e);
            }),
          );
      });
    })();
  }

  /** Test helper: keys with a holder or a waiter right now. */
  pendingKeys(): string[] {
    return [...this.tails.keys()];
  }
}

/** The key of the assertion lock of one App Attest key. A key belongs to one (account, device id) pair on the server, so that pair names the lock; the device id is
 * compared in lowercase (the server's, the secure store's and Swift's `uuidString` spellings differ in case only). EVERY assertion of that key must be held under
 * this key: check-in redemption (`redeemer.ts`) and, in P4.2c, reward activation (`rewards-activate` shares the counter). */
export function assertionLockKey(userId: string, deviceId: string): string {
  return `ios:${userId}:${deviceId.toLowerCase()}`;
}

/** Runs `fn` while holding the assertion lock of (userId, deviceId): the one entry point reward activation (P4.2c) must use for its `generateAssertion`, so it shares
 * the EXACT lock check-in uses. `fn` must `guard.check()` before each side effect and run its sent request through `guard.effect`.
 * NOT RE-ENTRANT: never call `redeem` or `activate` (or this function) from inside `fn`; they take this same lock and the call would wait for its own caller. See `KeyedMutex`. */
export function withAssertionLock<T>(locks: KeyedMutex, userId: string, deviceId: string, fn: (guard: LockGuard) => Promise<T>): Promise<T> {
  return locks.run(assertionLockKey(userId, deviceId), fn);
}
