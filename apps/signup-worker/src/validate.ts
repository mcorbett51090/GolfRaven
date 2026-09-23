/**
 * Strict input validation for `POST /api/signup` (gate-review S6:
 * "validation" as one of the required abuse controls).
 */

import {
  ALLOWED_CONSENT_VERSIONS,
  MAX_EMAIL_LENGTH,
  MAX_SOURCE_LENGTH,
  MAX_TURNSTILE_TOKEN_LENGTH,
} from "./config";

// Deliberately the same pragmatic (not RFC-5322-complete) pattern used by
// the owner's production Worker (raven-site-kit/secure-upload/worker/src/config.ts) —
// good enough to reject obvious garbage; Resend's own delivery is the real
// backstop for anything more exotic.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export interface ValidSignupInput {
  emailLc: string;
  consentVersion: string;
  ageConfirmed: true;
  turnstileToken: string;
  source?: string;
}

export type ValidationResult =
  | { ok: true; value: ValidSignupInput }
  | { ok: false; error: string };

function fail(error: string): ValidationResult {
  return { ok: false, error };
}

export function validateSignupPayload(body: unknown): ValidationResult {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return fail("request body must be a JSON object");
  }
  const obj = body as Record<string, unknown>;

  const rawEmail = obj.email;
  if (typeof rawEmail !== "string") {
    return fail("email is required and must be a string");
  }
  const trimmedEmail = rawEmail.trim();
  if (trimmedEmail.length === 0 || trimmedEmail.length > MAX_EMAIL_LENGTH) {
    return fail(`email must be 1-${MAX_EMAIL_LENGTH} characters`);
  }
  if (!EMAIL_RE.test(trimmedEmail)) {
    return fail("email is not a valid address");
  }

  // ageConfirmed must be the literal boolean true — a truthy string/number
  // is deliberately rejected so a client bug can never silently attest to
  // something the visitor didn't actually check (README "What we store").
  if (obj.ageConfirmed !== true) {
    return fail("ageConfirmed must be true");
  }

  if (typeof obj.consentVersion !== "string" || !ALLOWED_CONSENT_VERSIONS.includes(obj.consentVersion)) {
    return fail(`consentVersion must be one of: ${ALLOWED_CONSENT_VERSIONS.join(", ")}`);
  }

  if (typeof obj.turnstileToken !== "string" || obj.turnstileToken.length === 0) {
    return fail("turnstileToken is required");
  }
  if (obj.turnstileToken.length > MAX_TURNSTILE_TOKEN_LENGTH) {
    return fail("turnstileToken is too large");
  }

  let source: string | undefined;
  if (obj.source !== undefined) {
    if (typeof obj.source !== "string") {
      return fail("source must be a string when present");
    }
    const trimmedSource = obj.source.trim();
    if (trimmedSource.length > MAX_SOURCE_LENGTH) {
      return fail(`source must be at most ${MAX_SOURCE_LENGTH} characters`);
    }
    // Strip control characters defensively — this value round-trips into
    // D1 and is never rendered as HTML, but a clean value is cheap insurance.
    // eslint-disable-next-line no-control-regex
    source = trimmedSource.replace(/[\x00-\x1f\x7f]/g, "") || undefined;
  }

  return {
    ok: true,
    value: {
      emailLc: trimmedEmail.toLowerCase(),
      consentVersion: obj.consentVersion,
      ageConfirmed: true,
      turnstileToken: obj.turnstileToken,
      ...(source !== undefined ? { source } : {}),
    },
  };
}
