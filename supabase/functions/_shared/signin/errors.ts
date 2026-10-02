// supabase/functions/_shared/signin/errors.ts
//
// The failure vocabulary of the sign-in modules. Every class carries a SHORT MACHINE CODE (`code`, [a-z0-9_:.-]) and
// nothing else a vendor said: provider response bodies can echo tokens and are never copied into an error, a log line
// or the revocation queue (private.signin_revocation_queue.last_error is CHECK-constrained to the same alphabet).

/** The provider (or the network to it) is not answering usefully: timeout, 5xx, redirect, oversized or malformed
 * response, a host outside the allow-list. Always retryable; says nothing about the request itself. */
export class VendorUnavailableError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(`provider unavailable: ${code}`);
    this.code = code;
  }
}

/** A required piece of configuration is absent or unusable (the Apple key, a Vault KEK). Fails closed: never a default. */
export class NotConfiguredError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(`not configured: ${code}`);
    this.code = code;
  }
}

/** Apple's token endpoint understood the request and refused it (`invalid_grant`: the authorization code is wrong,
 * used, expired or belongs to another client). The REQUEST is bad; retrying it unchanged cannot help. */
export class AppleGrantError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(`apple refused the authorization code: ${code}`);
    this.code = code;
  }
}

export type AppleTokenFailure =
  | "malformed"
  | "alg"
  | "unknown_kid"
  | "signature"
  | "issuer"
  | "audience"
  | "expired"
  | "not_yet_valid"
  | "subject"
  | "nonce";

/** An Apple identity token that does not verify. `reason` is a closed set so a handler can answer without echoing
 * anything attacker-controlled. */
export class AppleTokenError extends Error {
  readonly reason: AppleTokenFailure;
  constructor(reason: AppleTokenFailure) {
    super(`apple identity token rejected: ${reason}`);
    this.reason = reason;
  }
}

/** Envelope decryption failed: wrong KEK, tampered ciphertext or wrapped DEK, or a format this code does not know. */
export class EnvelopeError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(`envelope: ${code}`);
    this.code = code;
  }
}
