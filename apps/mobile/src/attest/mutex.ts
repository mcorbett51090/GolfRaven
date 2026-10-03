/**
 * A keyed async mutex with a HOLD TIMEOUT: `run(key, fn)` runs `fn` only when no other `run` on the same key is in progress, strictly in call order.
 *
 * Why (PR #40 gate LOW-1): an App Attest key's assertion counter is strictly monotonic at the server and SHARED by `checkin-token` and `rewards-activate`.
 * If two assertions are generated back to back and their requests arrive out of order, the one that arrives second carries the lower counter and an honest
 * client is graded `failed` plus a fraud signal. So every assertion is held in this mutex from `generateAssertion` until the HTTP response of the request that
 * carries it has returned or failed; the next one is generated only after that.
 *
 * The lock is always released: when `fn` settles (value or error) AND when `holdTimeoutMs` elapses first (`fn` is then abandoned: its eventual result is
 * ignored and the caller gets `LockTimeoutError`). A lock that could be held forever by a hung native call would block every later check-in; the timeout is a
 * liveness bound, set above the HTTP timeout (`HTTP_POLICY.timeoutMs`, 20 s), so on the normal path it never fires.
 */
export class LockTimeoutError extends Error {
  constructor(readonly key: string, readonly holdTimeoutMs: number) {
    super(`lock "${key}" was held longer than ${holdTimeoutMs} ms and was released`);
    this.name = "LockTimeoutError";
  }
}

export interface KeyedMutexOptions {
  /** Longest a holder may keep the lock. */
  holdTimeoutMs: number;
}

export class KeyedMutex {
  private readonly tails = new Map<string, Promise<void>>();

  constructor(private readonly opts: KeyedMutexOptions) {}

  run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.tails.get(key) ?? Promise.resolve();
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = prev.then(() => held);
    this.tails.set(key, tail);
    const cleanup = (): void => {
      release();
      if (this.tails.get(key) === tail) this.tails.delete(key);
    };
    return (async () => {
      await prev; // never rejects: a tail is only ever `held`, which resolves
      let timer: ReturnType<typeof setTimeout> | undefined;
      const timedOut = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new LockTimeoutError(key, this.opts.holdTimeoutMs)), this.opts.holdTimeoutMs);
      });
      try {
        return await Promise.race([Promise.resolve().then(fn), timedOut]);
      } finally {
        if (timer !== undefined) clearTimeout(timer);
        cleanup();
      }
    })();
  }

  /** Test helper: keys with a holder or a waiter right now. */
  pendingKeys(): string[] {
    return [...this.tails.keys()];
  }
}
