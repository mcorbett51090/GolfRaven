// supabase/functions/_shared/edge-selfcheck-gate.ts
//
// Edge role PR3: WHEN the edge connection's self-check (`privileged.ts#assertEdgeConnectionSafe`) runs, separated from WHAT it checks so
// the schedule is unit-testable without a database (supabase/tests/unit/edge-selfcheck-gate.test.ts) and proved against a real one in
// supabase/tests/integration/edge-role.deno.test.ts.
//
// PR2 ran the self-check once per pool and remembered the success for the pool's life. A worker lives for hours, and the properties the
// check asserts (the login is not a superuser, not BYPASSRLS, and is a member of none of the privileged roles) are database state an
// operator can change underneath a running worker: `ALTER ROLE edge_gateway BYPASSRLS` or `GRANT service_role TO edge_gateway` made
// after the first request would go unseen until the worker was recycled. The per-transaction assertion in `openScopedTx` catches the
// ROLE it switches into (edge_actor / edge_system gaining a privileged attribute) but not the login's own membership closure. So the
// check is repeated: after `intervalMs` since the last success, or after `everyNCalls` successful gate passes, whichever comes first.
//
// Semantics (each one is a test):
//   - a success is remembered until the interval or the call budget runs out; within it the gate costs nothing (no round trip);
//   - when it runs out, the NEXT caller re-checks, and every caller that arrives while that re-check is in flight waits for the same
//     one (never a thundering herd of checks, never a caller that skips ahead on the old success);
//   - a FAILURE is never remembered: the next caller checks again (a misconfiguration is not "remembered as fine", and a transient
//     error is retried), and the failing caller gets the check's own error;
//   - a re-check that fails after earlier successes refuses exactly like the first one did (the caller sees a plain Error: a 500).
//
// This file imports nothing and reads no environment: privileged.ts owns the connection and builds the gate over its own check.

export interface SelfCheckGateOptions {
  /** The check itself; rejects when the connection is not acceptable. */
  check: () => Promise<void>;
  /** A success is trusted for this long (ms). 0 re-checks on every call. */
  intervalMs: number;
  /** A success is also trusted for at most this many gate passes; 0 or undefined = no call budget. */
  everyNCalls?: number;
  /** Clock, injectable for tests. */
  now?: () => number;
}

export interface SelfCheckGate {
  /** Resolves when the connection is acceptable now (per the schedule); rejects with the check's error otherwise. */
  ensure(): Promise<void>;
  /** Forgets everything (a pool was replaced). */
  reset(): void;
  /** How many times the underlying check has been started (tests). */
  readonly checksStarted: number;
}

export function makeSelfCheckGate(opts: SelfCheckGateOptions): SelfCheckGate {
  const now = opts.now ?? (() => Date.now());
  const everyN = opts.everyNCalls !== undefined && opts.everyNCalls > 0 ? opts.everyNCalls : 0;
  let inflight: Promise<void> | null = null;
  let trusted = false; // true only after a success, until the interval or the call budget runs out
  let checkedAt = 0;
  let callsSince = 0;
  let started = 0;
  let generation = 0; // reset() bumps it so a check that was in flight across a reset cannot re-trust the new state

  function fresh(): boolean {
    if (!trusted) return false;
    if (now() - checkedAt >= opts.intervalMs) return false;
    if (everyN > 0 && callsSince >= everyN) return false;
    return true;
  }

  return {
    ensure(): Promise<void> {
      if (inflight) return inflight;
      if (fresh()) {
        callsSince += 1;
        return Promise.resolve();
      }
      const gen = generation;
      started += 1;
      // `check()` may throw synchronously (a missing URL); normalise to a rejection so the failure path below always runs.
      const p: Promise<void> = Promise.resolve()
        .then(() => opts.check())
        .then(
          () => {
            if (gen === generation) {
              trusted = true;
              checkedAt = now();
              callsSince = 0;
            }
            if (inflight === p) inflight = null;
          },
          (err) => {
            if (gen === generation) trusted = false; // never remember a failure, and never keep an older success past it
            if (inflight === p) inflight = null;
            throw err;
          },
        );
      inflight = p;
      return p;
    },
    reset(): void {
      generation += 1;
      inflight = null;
      trusted = false;
      checkedAt = 0;
      callsSince = 0;
    },
    get checksStarted(): number {
      return started;
    },
  };
}
