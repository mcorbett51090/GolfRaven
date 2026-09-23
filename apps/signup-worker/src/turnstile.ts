/**
 * Server-side Cloudflare Turnstile verification (siteverify).
 *
 * Adapted from the owner's production Worker:
 * raven-site-kit/secure-upload/worker/src/turnstile.ts — same siteverify
 * contract (fail closed on network/HTTP/malformed-response error), copied
 * near-verbatim because that shape is already production-proven.
 *
 * Defense-in-depth only (gate-review S6): Turnstile raises the cost of
 * scripted abuse but is NOT the sole abuse control — see ratelimit.ts for
 * the per-IP-key and per-email caps that actually bound signup volume.
 */

const SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

export interface TurnstileResult {
  success: boolean;
  errorCodes?: string[];
}

export async function verifyTurnstileToken(
  token: string,
  secretKey: string,
  remoteIp: string | null,
): Promise<TurnstileResult> {
  if (!token || token.length > 4096) {
    return { success: false, errorCodes: ["missing-or-oversized-token"] };
  }

  const body = new URLSearchParams();
  body.set("secret", secretKey);
  body.set("response", token);
  if (remoteIp) body.set("remoteip", remoteIp);

  let res: Response;
  try {
    res = await fetch(SITEVERIFY_URL, { method: "POST", body });
  } catch {
    // Network failure talking to Cloudflare's own API — fail closed.
    return { success: false, errorCodes: ["siteverify-network-error"] };
  }

  if (!res.ok) {
    return { success: false, errorCodes: [`siteverify-http-${res.status}`] };
  }

  const data = (await res.json().catch(() => null)) as
    | { success?: boolean; "error-codes"?: string[] }
    | null;
  if (!data || data.success !== true) {
    return { success: false, errorCodes: data?.["error-codes"] ?? ["siteverify-malformed-response"] };
  }
  return { success: true };
}
