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

/** One transaction as `edge_partner`, bound to the presented session. Every method is a `_for_partner` definer that begins with `partner_authorize`. */
export interface PartnerSessionTx {
  whoami(): Promise<unknown>;
  signOut(): Promise<void>;
  lock(): Promise<void>;
  reauthOptions(): Promise<ChallengeIssue & { readonly rp: RpConfig }>;
  /** The key a reauth assertion is verified against: a live credential of THE SESSION'S OWN person, or null (PA-27). */
  reauthCredential(credentialId: Uint8Array): Promise<ReauthCredential | null>;
  reauth(input: ReauthInput): Promise<{ readonly status: string; readonly reauthUntil: string | null }>;
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
