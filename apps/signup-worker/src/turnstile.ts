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

/**
 * Gate finding F12 (NIT, defense in depth only — the site key is already
 * hostname-restricted in the Cloudflare dashboard): when `expectedHostname`
 * or `expectedAction` is passed AND the siteverify response actually
 * carries that field, it must match. A field the response omits is not
 * treated as a mismatch (keeps this lenient enough for test doubles and
 * any future siteverify response shape change), but a field that IS
 * present and wrong fails closed.
 */
export async function verifyTurnstileToken(
  token: string,
  secretKey: string,
  remoteIp: string | null,
  expected?: { hostname?: string | undefined; action?: string | undefined },
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
    | { success?: boolean; "error-codes"?: string[]; hostname?: string; action?: string }
    | null;
  if (!data || data.success !== true) {
    return { success: false, errorCodes: data?.["error-codes"] ?? ["siteverify-malformed-response"] };
  }
  if (expected?.hostname && data.hostname && data.hostname !== expected.hostname) {
    return { success: false, errorCodes: ["hostname-mismatch"] };
  }
  if (expected?.action && data.action && data.action !== expected.action) {
    return { success: false, errorCodes: ["action-mismatch"] };
  }
  return { success: true };
}
