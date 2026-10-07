/** The wire shapes of `partner-session` (docs/security/partner-auth-design.md 18.1, 18.2). Responses are `{ data }`; errors are `{ error: { code, message } }`. */

/** The browser's `PublicKeyCredential` of a `navigator.credentials.get`, as the server's strict parser takes it. Every binary field is canonical unpadded base64url. */
export interface AssertionJson {
  id: string;
  rawId: string;
  type: "public-key";
  response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle?: string };
}

/** `POST options` and `POST reauth/options`: the WebAuthn request options (the server's, verbatim), the stateless challenge token to send back, and its expiry. */
export interface ChallengeResponse {
  readonly options: unknown;
  readonly challengeToken: string;
  readonly expiresAt: string;
}

/** `POST verify` (201): what the client may know about the session it just opened. The token itself is never returned to the caller: the client keeps it. */
export interface SessionGrant {
  readonly expiresAt: string;
  readonly aal: number;
}

export interface Membership {
  readonly orgId: string;
  readonly role: string;
  readonly facilityIds: readonly string[];
  readonly trailIds: readonly string[];
}

export interface StepUpState {
  readonly pinGrantActive: boolean;
  readonly reauthUntil: string | null;
  readonly mfaUntil: string | null;
  readonly otpProofUntil: string | null;
  readonly enrolmentUntil: string | null;
}

/** `GET session` (class PEEK: it never extends the idle timer). Everything is re-read by the server on every call. */
export interface WhoAmI {
  readonly userId: string;
  readonly sessionId: string;
  readonly aal: number;
  readonly requiredAal: number;
  readonly createdAt: string;
  readonly lastSeenAt: string;
  readonly idleExpiresAt: string;
  readonly expiresAt: string;
  readonly isAdmin: boolean;
  readonly stepUp: StepUpState;
  readonly memberships: readonly Membership[];
}

/** `POST reauth` (200). */
export interface ReauthResult {
  readonly reauthUntil: string;
}
