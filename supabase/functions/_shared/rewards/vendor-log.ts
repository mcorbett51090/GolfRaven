// supabase/functions/_shared/rewards/vendor-log.ts
//
// A rate-limited log line for vendor outcomes a CALLER can trigger. The one user today: Google's 403 on `decodeIntegrityToken`, which is ambiguous between
// "our service account lacks access" and "the token was minted for another app or project" (types.ts#VendorForbiddenError). An unauthenticated-in-effect
// caller (any signed-in account) can send such a token, so the line must neither flood the log nor read as an outage of OUR credentials.
//
// At most one line per (source, kind) per interval; the next line after the window reports how many were suppressed. State is per isolate and bounded by the
// constant (source, kind) pairs the code uses, never by anything a caller sends. Pure and DI'd (sink + clock) so the window is testable; no environment, no secret.
// Verification-only (the earning side imports it, rewards-isolation.test.ts).

export const VENDOR_FAULT_LOG_INTERVAL_MS = 60_000;

export interface VendorFaultSink {
  warn(message: string): void;
}

export function createVendorFaultLogger(sink: VendorFaultSink, nowMs: () => number, intervalMs: number = VENDOR_FAULT_LOG_INTERVAL_MS) {
  const seen = new Map<string, { lastAt: number; suppressed: number }>();
  /** Returns whether a line was written. */
  return function logVendorFault(source: string, kind: string, message: string): boolean {
    const key = `${source}\u0000${kind}`;
    const now = nowMs();
    const prev = seen.get(key);
    if (prev !== undefined && now - prev.lastAt < intervalMs) {
      prev.suppressed++;
      return false;
    }
    seen.set(key, { lastAt: now, suppressed: 0 });
    const tail = prev !== undefined && prev.suppressed > 0 ? ` (${prev.suppressed} similar suppressed since the last line)` : "";
    sink.warn(`${source}: ${message}${tail}`);
    return true;
  };
}

/** The production instance: `console.warn`, wall clock. */
export const logVendorFault = createVendorFaultLogger({ warn: (m) => console.warn(m) }, () => Date.now());
