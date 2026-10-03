/**
 * The app's view of the backend, `api.*` (build plan §3.3, §4.7). Two implementations behind one interface:
 *  - `http-client.ts`: the real client over the Edge Functions that exist today (P4.2a);
 *  - `mock.ts`: the in-memory mock, for tests and the `__DEV__` demo ONLY (never constructed in a release build, `runtime/backend.ts`).
 *
 * Every method that talks to the server THROWS an `ApiError` (`errors.ts`) on failure; the one exception is `submitEvidence`, which by the
 * outbox contract never throws for an HTTP outcome (it returns a `ServerAnswer`).
 */
import type { EvidenceCredentials, EvidenceSubmitter } from "../outbox";
import type { SignInProviderId } from "../signin/providers";
import type { ProgrammeStatus } from "../wallet";

export type PlayConfidence = "hard" | "badge" | "pending_verification";

export interface PlaySummary {
  id: string;
  courseId: string;
  /** ISO timestamp. */
  playedAt: string;
  confidence: PlayConfidence;
}

export type AchievementState = "earned" | "in_progress" | "locked";
export interface AchievementSummary {
  id: string;
  name: string;
  state: AchievementState;
  progress?: { k: number; n: number };
}

/** The signed-in player, as the screens see it. */
export interface Session {
  userId: string;
  /** The method the session was created with, or "email" when the stored session does not say. */
  provider: SignInProviderId;
  /** The mock/demo only: there is no real account behind it. */
  stub: boolean;
}

/** One row of `GET me-signin-methods` (`MethodView`). `provider` is a string on the wire; the UI treats unknown values as plain text. */
export interface SignInMethod {
  provider: string;
  linkedAt: string;
  isPrivateRelay: boolean;
  /** false for the only remaining method (unlinking it is a 422 `last_sign_in_method`). */
  canUnlink: boolean;
}

/** `POST me-signin-methods { action: "link" }` (Apple only: Google is a 501 `provider_not_supported` server-side). The wire shape is
 * `LinkRequest` in `_shared/signin/request-shape.ts`; `nonce` is the RAW nonce (the server hashes it and compares it with the token's claim). */
export interface LinkSignInRequest {
  provider: "apple" | "google";
  identityToken: string;
  authorizationCode: string;
  nonce: string;
  /** Only ever set by an explicit player action: the 6-10 digit code sent to the address that already belongs to another account. */
  emailProof?: { code: string };
}

export interface LinkSignInResult {
  linked: { provider: "apple"; created: boolean; isPrivateRelay: boolean };
  /** "proven_account": the identity went to ANOTHER account whose mailbox the caller proved; `methods` is then `null`. */
  linkedTo: "self" | "proven_account";
  methods: SignInMethod[] | null;
}

export interface UnlinkSignInResult {
  methods: SignInMethod[];
  revocation: { queueId: string; provider: string; status: "revoked" | "queued_for_retry"; error?: string | undefined }[];
}

export interface DeleteAccountResult {
  userId: string;
  deletedAt: string;
  authUserDeleted: boolean;
  authUserAlreadyGone: boolean;
  /** What happened to each Apple / Google grant: revoked now, or queued for the server's 72 h retry. */
  signinProvidersRevoked: { queueId: string; provider: string; status: "revoked" | "queued_for_retry"; error?: string | undefined }[];
}

export interface ExportResult {
  generatedAt: string;
  userId: string;
  /** The caller's personal data, table by table. Opaque to the app: it is handed to the player, never interpreted. */
  data: Record<string, unknown>;
}

export interface PushTokenRequest {
  /** The per-install device id (a UUID). */
  deviceId: string;
  expoToken: string;
  platform?: "ios" | "android";
}

export interface PushTokenResult {
  deviceId: string;
  updatedAt: string;
}

/** One challenge `POST checkin-challenge` issued (`IssuedChallenge`, `_shared/checkin/challenge-handler.ts`). `nonce` is the RAW nonce, shown once. */
export interface IssuedChallenge {
  id: string;
  nonce: string;
  /** ISO timestamp (live: 120 s after issue; prefetched: 24 h). */
  expiresAt: string;
  kind: "live" | "prefetched";
}

/** `POST checkin-token` answer (`IssuedToken`, `token-handler.ts`): the jti a fix then names as `checkinTokenJti`, valid 15 minutes. */
export interface CheckinTokenResult {
  jti: string;
  expiresAt: string;
  attestationGrade: "attested" | "unattestable" | "failed";
}

export interface CheckinChallengeRequest {
  /** The per-install device id (a UUID). */
  deviceId: string;
  facilityId?: string;
  /** Absent / 0: one LIVE challenge. 1..10: that many PREFETCHED ones (the server issues fewer when the device already holds some). */
  prefetchCount?: number;
}

export interface CheckinTokenRequest {
  challengeId: string;
  nonce: string;
  hardwareSupportsAttestation: boolean;
}

/** The check-in challenge endpoints. Both take the OWNER's credentials explicitly (the bearer is `credentials.accessToken`, never whatever is
 * signed in by the time the request is made), neither is retried automatically (a challenge is single-use; the requests are rate limited at
 * 30 and 60 per user per hour), and both throw `ApiError`. */
export interface CheckinApi {
  requestCheckinChallenges(req: CheckinChallengeRequest, credentials: EvidenceCredentials): Promise<IssuedChallenge[]>;
  redeemCheckinChallenge(req: CheckinTokenRequest, credentials: EvidenceCredentials): Promise<CheckinTokenResult>;
}

export interface ApiClient extends EvidenceSubmitter, CheckinApi {
  /** Server policy constants the app must not hard-code (`MIN_AGE`, §7.8). `[no server endpoint exists yet: the real client answers the
   * compiled default (16) — see `http-client.ts`]` */
  getPolicy(): Promise<{ minAge: number }>;
  listPlays(): Promise<PlaySummary[]>;
  listAchievements(): Promise<AchievementSummary[]>;
  /** `trail_programme.status` per trail id (O17). */
  listTrailProgrammes(): Promise<Record<string, ProgrammeStatus>>;

  /** `GET me-signin-methods`. */
  listSignInMethods(): Promise<SignInMethod[]>;
  /** `POST me-signin-methods` link. NOT retried automatically (the authorization code is single-use; an OTP proof attempt is counted). */
  linkSignInMethod(req: LinkSignInRequest): Promise<LinkSignInResult>;
  /** `POST me-signin-methods` unlink. NOT retried automatically (a second unlink is a 404). */
  unlinkSignInMethod(provider: "email" | "apple" | "google"): Promise<UnlinkSignInResult>;
  /** `DELETE me-delete` (`DELETE /v1/me`). Idempotent server-side, so a transport failure is retried and the player may retry by hand. */
  deleteAccount(): Promise<DeleteAccountResult>;
  /** `GET me-export`. */
  exportData(): Promise<ExportResult>;
  /** `POST me-push-token`. */
  registerPushToken(req: PushTokenRequest): Promise<PushTokenResult>;
}
