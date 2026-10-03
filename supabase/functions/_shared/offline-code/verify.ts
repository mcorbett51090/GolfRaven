// supabase/functions/_shared/offline-code/verify.ts
//
// The VERIFICATION CORE of the offline staff code (build plan §7.6 "Offline staff path (G-P1-07)"): given a seed, the 6 digits a staff member typed
// and the clock, decide whether the code is a valid one. PURE: no I/O, no database, no environment. The staff verification endpoint (P5 portal, not
// in this stage) composes it:
//
//   1. resolve the player (handle) and derive the seed in the database (a P5 definer over `private.offline_seed_derive`, migration 0045);
//   2. `verifyOfflineCode({ seed, code, now })`  -> { ok: true, step } | { ok: false, reason };
//   3. `repo.offlineCode.recordStep({ deviceId, seedVersion, step, facilityId })` -> the ATOMIC replay check ("recorded" | "replayed" | ...);
//   4. only on "recorded": write the evidence, bound to the staff member's facility scope.
//
// WHAT THIS DOES NOT DO, deliberately: it holds no failure counter. "5 failures per staff per hour" (§7.6, SP13) is P5's to enforce around this
// call (params.ts, OFFLINE_CODE_STAFF_FAILURE_BUCKET); a pure function cannot rate-limit.
//
// REPLAY. `usedSteps` lets a caller that already knows the used steps for this (device, seed version) get the specific verdict `replayed` without
// a write. It is an ADVISORY pre-check only: two requests carrying the same code race past it. The AUTHORITY is `recordStep`'s atomic insert
// (a unique key on (device, seed version, step); a second insert of the same step reports "replayed"), which a caller must always make.
//
// CONSTANT TIME. The comparison of the typed code with each candidate is `constantTimeEqual` (no early exit on the first differing digit), every
// candidate step is computed and compared whether or not an earlier one matched, and the verdict is chosen after the loop. A code is not a secret
// that outlives its step, so this is defence in depth against a timing probe of a still-valid code, not the only control (the 5-failure limit is).

import { OFFLINE_CODE_DIGITS, OFFLINE_CODE_WINDOW_STEPS } from "./params.ts";
import { hotp, stepOf } from "./totp.ts";

export type OfflineCodeRefusal = "malformed_code" | "mismatch" | "replayed";

export type OfflineCodeVerdict = { ok: true; step: number } | { ok: false; reason: OfflineCodeRefusal };

export interface VerifyOfflineCodeInput {
  /** The 32-byte seed of the (account, device, seed version) the code is being checked against. */
  seed: Uint8Array;
  /** What the staff member typed. Anything but exactly 6 ASCII digits is `malformed_code` (and still a failed verification for P5's counter). */
  code: string;
  /** The server's clock. */
  now: Date;
  /** Steps already used for this (device, seed version); advisory (see the header). */
  usedSteps?: Iterable<number>;
}

/** Equality of two strings that does the same work whatever the inputs hold: no early return on the first difference, and a length difference is
 * folded into the result rather than short-circuiting. */
export function constantTimeEqual(a: string, b: string): boolean {
  const n = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < n; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

/** The steps a code is checked against, in preference order: the current step first, then the two neighbours (a device clock a little behind, then a
 * little ahead). `OFFLINE_CODE_WINDOW_STEPS` = 1 gives [t, t-1, t+1]. */
export function candidateSteps(now: Date): number[] {
  const t = stepOf(now.getTime() / 1000);
  const out = [t];
  for (let d = 1; d <= OFFLINE_CODE_WINDOW_STEPS; d++) out.push(t - d, t + d);
  return out.filter((s) => s >= 0);
}

export async function verifyOfflineCode(input: VerifyOfflineCodeInput): Promise<OfflineCodeVerdict> {
  const { seed, code, now } = input;
  if (typeof code !== "string" || !new RegExp(`^[0-9]{${OFFLINE_CODE_DIGITS}}$`).test(code)) return { ok: false, reason: "malformed_code" };
  const used = new Set(input.usedSteps ?? []);
  let accepted: number | null = null;
  let matchedButUsed = false;
  for (const step of candidateSteps(now)) {
    const expected = await hotp(seed, step);
    const matches = constantTimeEqual(expected, code); // never short-circuit: every candidate is compared
    if (matches && used.has(step)) matchedButUsed = true;
    else if (matches && accepted === null) accepted = step;
  }
  if (accepted !== null) return { ok: true, step: accepted };
  return { ok: false, reason: matchedButUsed ? "replayed" : "mismatch" };
}
