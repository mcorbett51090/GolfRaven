// supabase/functions/_shared/signin/secret-expiry.ts
//
// Build plan §4.8: "A calendar reminder plus a MONTHLY CHECK that FAILS if the Apple client secret expires within 30 days."
//
// Which secret: the server (apple-client-secret.ts) mints its own 10-minute secrets on demand, so IT never has a six-month
// expiry to forget. The secret that DOES expire is the one an operator pastes into Supabase Auth's Apple provider settings (the
// dashboard step): a JWT, signed with the same `.p8`, valid for at most six months `[unverified — training knowledge of Apple's
// <= 6 months limit; A77]`. Nothing in this repo can read the dashboard, so the check takes that JWT as input and reads its `exp`.
//
// This file is the pure core (decode a JWT's `exp`, decide). The runnable, scheduled form is tools/apple/check-siwa-secret-expiry.mjs
// (Node, no dependencies), which duplicates the ~20 lines of decoding on purpose so it runs with nothing installed; a unit test
// runs both against the same fixtures.

export const DEFAULT_WARN_DAYS = 30;

export interface ExpiryVerdict {
  ok: boolean;
  /** Machine reason: 'ok' | 'malformed' | 'no_exp' | 'expired' | 'expires_soon'. */
  reason: "ok" | "malformed" | "no_exp" | "expired" | "expires_soon";
  expiresAtIso: string | null;
  daysLeft: number | null;
}

function decodePayload(jwt: string): Record<string, unknown> | null {
  const parts = jwt.trim().split(".");
  if (parts.length !== 3) return null;
  try {
    const b64 = parts[1]!.replace(/-/g, "+").replace(/_/g, "/");
    const json = new TextDecoder().decode(Uint8Array.from(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)), (c) => c.charCodeAt(0)));
    const v: unknown = JSON.parse(json);
    return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Fails (ok: false) when the secret is malformed, has no `exp`, is expired, or expires within `warnDays` days. */
export function checkClientSecretExpiry(jwt: string, nowMs: number, warnDays: number = DEFAULT_WARN_DAYS): ExpiryVerdict {
  const payload = decodePayload(jwt);
  if (payload === null) return { ok: false, reason: "malformed", expiresAtIso: null, daysLeft: null };
  const exp = payload.exp;
  if (typeof exp !== "number" || !Number.isFinite(exp)) return { ok: false, reason: "no_exp", expiresAtIso: null, daysLeft: null };
  const daysLeft = (exp * 1000 - nowMs) / 86_400_000;
  const expiresAtIso = new Date(exp * 1000).toISOString();
  if (daysLeft <= 0) return { ok: false, reason: "expired", expiresAtIso, daysLeft };
  if (daysLeft < warnDays) return { ok: false, reason: "expires_soon", expiresAtIso, daysLeft };
  return { ok: true, reason: "ok", expiresAtIso, daysLeft };
}
