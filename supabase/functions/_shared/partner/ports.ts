// supabase/functions/_shared/partner/ports.ts
//
// The seams of the partner sign-in handler (docs/security/partner-auth-design.md 4.2 / 4.4 / 4.5, slice S1.2): what the pure handler asks of the database (`PartnerDb`, implemented in
// `privileged.ts`, the sole database site) and of the WebAuthn wrapper (`AssertionVerifier`, implemented in `webauthn-port.ts`). Types and three error classes only: no behaviour, no imports,
// so the handler and its unit tests (vitest, no Deno) see the contract without pulling in a driver or a library.

/** The relying party, from `app.partner_rp_config` (the exact origin and the RP ID). */
export interface RpConfig {
  readonly rpId: string;
  readonly origin: string;
}

/** A stateless challenge (5.1): 32 random bytes, an expiry in epoch seconds and the HMAC the database computed. */
export interface ChallengeIssue {
  readonly nonce: Uint8Array;
  readonly exp: number;
  readonly mac: Uint8Array;
}

/** What the database knows of a live credential (4.4 `partner_credential_lookup`). */
export interface StoredCredentialRow {
  /** The credential row's uuid (never sent to the client). */
  readonly id: string;
  /** The person (auth.users id): its 16 bytes are the WebAuthn user handle. */
  readonly userId: string;
  readonly alg: number;
  readonly publicKey: Uint8Array;
  readonly signCount: number;
}

/** `ok` carries the credential; `unknown` (an unknown credential and a revoked one are one answer) and `cooldown` (five failed verifications in the last hour) carry nothing. */
export type CredentialLookup = { readonly status: "ok"; readonly credential: StoredCredentialRow } | { readonly status: "unknown" | "cooldown" };

export interface MintInput {
  /** sha256 hex of the opaque session token: the raw token never reaches the database. */
  readonly tokenHash: string;
  readonly credentialId: Uint8Array;
  readonly nonce: Uint8Array;
  readonly exp: number;
  readonly mac: Uint8Array;
  readonly authenticatorData: Uint8Array;
  readonly clientDataJson: Uint8Array;
  readonly signature: Uint8Array;
}

export interface MintResult {
  /** `ok` or one of the refusal statuses of `private.partner_session_mint` (never shown to a client). */
  readonly status: string;
  readonly aal: number | null;
  readonly expiresAt: string | null;
}

/** One transaction as `edge_partner_minter`: no actor is bound. It COMMITS when the callback returns, whatever status it holds (the alarm rows, the burned nonce and the failure counter are written by refusals). */
export interface PartnerMintTx {
  rpConfig(): Promise<RpConfig>;
  issueChallenge(): Promise<ChallengeIssue>;
  lookupCredential(credentialId: Uint8Array): Promise<CredentialLookup>;
  /** Counts one failed verification of a credential (design 8): `counted`, `cooldown` or `unknown`. */
  recordFailure(credentialId: Uint8Array): Promise<"counted" | "cooldown" | "unknown">;
  mint(input: MintInput): Promise<MintResult>;
}

export interface ReauthCredential extends StoredCredentialRow {
  readonly rp: RpConfig;
}

export interface ReauthInput {
  readonly credentialId: Uint8Array;
  readonly nonce: Uint8Array;
  readonly exp: number;
  readonly mac: Uint8Array;
  readonly authenticatorData: Uint8Array;
  readonly clientDataJson: Uint8Array;
  readonly signature: Uint8Array;
}

/** What `GET pin` returns: the PBKDF2 inputs the browser derives with (`ok`), or why it cannot (`unset`, `must_change`, `locked`: none of them carries a salt). */
export type PinParams =
  | { readonly state: "ok"; readonly salt: Uint8Array; readonly iterations: number; readonly retryAfterSeconds: number }
  | { readonly state: "unset" | "must_change" | "locked" };

/** The outcome of evaluating a derived key (partner_pin_verify_for_partner): every one a RETURNED status, so the failure counter commits with the refusal (the 0020 lesson). */
export type PinCheckStatus = "ok" | "wrong" | "locked" | "retry_after" | "unset" | "must_change";
export interface PinVerifyResult {
  readonly status: PinCheckStatus;
  /** Whole seconds until the next attempt is allowed (`retry_after`), or the backoff the failure just started (`wrong`); 0 otherwise. */
  readonly retryAfterSeconds: number;
  /** ISO time the single-use PIN grant expires (`ok` only). */
  readonly grantUntil: string | null;
}

export interface PinSetInput {
  /** The browser-derived key (32 bytes): never the PIN. */
  readonly derived: Uint8Array;
  /** The salt the browser chose (16 bytes). */
  readonly salt: Uint8Array;
  readonly iterations: number;
}
export interface PinChangeInput extends PinSetInput {
  /** The derived key of the CURRENT PIN (32 bytes). */
  readonly current: Uint8Array;
}
export type PinWriteStatus = "ok" | "already_set" | "no_pin" | "must_change" | "wrong" | "locked" | "retry_after" | "unset";
export interface PinWriteResult {
  readonly status: PinWriteStatus;
  readonly retryAfterSeconds: number;
}

/** One transaction as `edge_partner`, bound to the presented session. Every method is a `_for_partner` definer that begins with `partner_authorize`. */
export interface PartnerSessionTx {
  whoami(): Promise<unknown>;
  signOut(): Promise<void>;
  lock(): Promise<void>;
  reauthOptions(): Promise<ChallengeIssue & { readonly rp: RpConfig }>;
  /** The key a reauth assertion is verified against: a live credential of THE SESSION'S OWN person, or null (PA-27). */
  reauthCredential(credentialId: Uint8Array): Promise<ReauthCredential | null>;
  reauth(input: ReauthInput): Promise<{ readonly status: string; readonly reauthUntil: string | null }>;
  /** GET pin (class A0, staff or manager): the PBKDF2 inputs for this person. */
  pinParams(): Promise<PinParams>;
  /** POST step-up/pin: evaluates the derived key; on `ok` the session holds a single-use PIN grant. A returned status for every refusal: the transaction COMMITS (the counter and the audit row with it). */
  pinVerify(derived: Uint8Array): Promise<PinVerifyResult>;
  /** POST pin/set: the first PIN, or the replacement after a reset. 42501 (`PartnerAuthorityRefused`) without an enrolment window or an email proof. */
  pinSet(input: PinSetInput): Promise<PinWriteResult>;
  /** POST pin/change: replace a live PIN (needs the current one, counted like a verify). */
  pinChange(input: PinChangeInput): Promise<PinWriteResult>;
  /** The member's OWN mailbox for the email OTP of the proof, or null when the account has none. Never returned to a client. */
  otpTarget(): Promise<string | null>;
  /** Records the email proof bound to a fresh GoTrue session of this person: `refused` when the session is not fresh for this person or was already used for a proof. */
  otpProof(gotrueSessionId: string): Promise<{ readonly status: "ok" | "refused"; readonly otpProofUntil: string | null }>;
}

/**
 * The email OTP of the proof (6.1, 6.3), through GoTrue with the ANON key, as the player flow already does (E19): `send` mails a one-time code to the member's own address; `verify` proves the mailbox and returns the
 * GoTrue session the verification created, which the database then checks (it must exist, for THIS person, fresh) and which the caller closes AFTER the proof is recorded, on every path. A wrong or expired code is
 * `{ ok: false }`; a transport failure THROWS (it says nothing about the code).
 */
export interface EmailOtpPort {
  send(email: string): Promise<void>;
  verify(email: string, code: string): Promise<{ readonly ok: false } | { readonly ok: true; readonly userId: string; readonly sessionId: string | null; closeSession(): Promise<void> }>;
}

export interface PartnerDb {
  /** Runs `op` in one transaction as `edge_partner_minter`; COMMITS whenever `op` returns (a refusal is a returned value, never a throw). A throw rolls back. */
  withMint<T>(op: (m: PartnerMintTx) => Promise<T>): Promise<T>;
  /** Runs `op` in one transaction as `edge_partner` bound to the session whose token hash this is. Throws `PartnerSessionRefused` when the binder refuses, `PartnerAuthorityRefused` on a 42501 refusal. */
  withSession<T>(tokenHash: string, op: (s: PartnerSessionTx) => Promise<T>): Promise<T>;
  /** One hit of a per-member bucket, in its OWN short transaction, committed before any request transaction opens (the pool-deadlock rule of `hitRateLimitForActor`). */
  hitRateLimit(tokenHash: string, bucket: string, windowSeconds: number, max: number): Promise<{ readonly ok: boolean; readonly retryAfterSeconds: number }>;
}

/** The assertion as the browser's `PublicKeyCredential.toJSON()` hands it over (the shape `@simplewebauthn/server` takes). */
export interface AssertionJson {
  id: string;
  rawId: string;
  type: "public-key";
  response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle?: string };
  clientExtensionResults: Record<string, never>;
}

export interface VerifyAssertionRequest {
  readonly rp: RpConfig;
  readonly response: AssertionJson;
  readonly expectedChallenge: Uint8Array;
  readonly credential: { readonly id: string; readonly publicKey: Uint8Array; readonly signCount: number };
  readonly expectedUserHandle: Uint8Array;
}

/**
 * The outcome of the Edge's own verification. `counterOnly` is true when the assertion fails ONLY because the counter did not advance (re-verified with the stored counter forgotten): a clone
 * indicator, which is passed to the mint anyway so the database writes the audit_log and alarm rows (PA-12). Anything else that fails is a plain refusal.
 */
export type VerifyOutcome = { readonly ok: true } | { readonly ok: false; readonly counterOnly: boolean };

export interface AssertionVerifier {
  /** The sign-in options (UV required, empty allowCredentials) for a challenge the database issued. */
  options(rp: RpConfig, challenge: Uint8Array): Promise<unknown>;
  verify(input: VerifyAssertionRequest): Promise<VerifyOutcome>;
}

/** The binder refused the presented token (28000, one message for unknown, idle, expired, revoked ...): the handler answers the ONE 401. */
export class PartnerSessionRefused extends Error {
  constructor() {
    super("partner_session_refused");
    this.name = "PartnerSessionRefused";
  }
}

/** A definer refused with 42501 (no scope, the assurance level is below the member's required one): the handler answers 403. */
export class PartnerAuthorityRefused extends Error {
  constructor() {
    super("partner_authority_refused");
    this.name = "PartnerAuthorityRefused";
  }
}

/** A deploy fault (the relying-party row or the Vault key is missing, or the configured origin disagrees with the database's): a bare 503, never a client refusal. */
export class PartnerNotConfigured extends Error {
  constructor() {
    super("partner_not_configured");
    this.name = "PartnerNotConfigured";
  }
}

/** A unique index refused the write (23505): in this lane, only a GoTrue session that already proved another proof. The handler answers a 409 (an OTP proof answers its one 403). */
export class PartnerConflict extends Error {
  constructor() {
    super("partner_conflict");
    this.name = "PartnerConflict";
  }
}
