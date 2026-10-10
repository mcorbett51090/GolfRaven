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
  /** Stale App Attest key hint: present, and only ever `true`, when an iOS assertion was refused because the key id is not the registered one (`failed`) or no key is registered (`unattestable`).
   * The token is still valid with that grade; `attest/redeemer.ts` marks the local key stale and registers a FRESH one on the next need. Absent on every other answer. */
  rekey?: true;
}

export interface CheckinChallengeRequest {
  /** The per-install device id (a UUID). */
  deviceId: string;
  facilityId?: string;
  /** Absent / 0: one LIVE challenge. 1..10: that many PREFETCHED ones (the server issues fewer when the device already holds some). */
  prefetchCount?: number;
}

/** The device attestation a redemption may carry (`token-request-shape.ts`): an App Attest assertion (iOS) or a Play Integrity token (Android). */
export type CheckinAttestationBlock = { platform: "ios"; keyId: string; assertion: string } | { platform: "android"; integrityToken: string };

/** The WIRE body of `POST checkin-token`. Strict at the server: an unknown key is a 400. `hardwareSupportsAttestation` is true only when `attestation` is present
 * (`attest/redeemer.ts` `wireRequest` is the only constructor). */
export interface CheckinTokenRequest {
  challengeId: string;
  nonce: string;
  hardwareSupportsAttestation: boolean;
  attestation?: CheckinAttestationBlock;
}

/** What a caller gives to redeem a challenge: the attestation (and so the wire body) is built by the client's redeemer, bound to these. `deviceId` is the device the
 * challenge was issued to. */
export interface CheckinRedeemInput {
  challengeId: string;
  nonce: string;
  deviceId: string;
}

/** The check-in challenge endpoints. Both take the OWNER's credentials explicitly (the bearer is `credentials.accessToken`, never whatever is
 * signed in by the time the request is made), neither is retried automatically (a challenge is single-use; the requests are rate limited at
 * 30 and 60 per user per hour), and both throw `ApiError`. */
export interface CheckinApi {
  requestCheckinChallenges(req: CheckinChallengeRequest, credentials: EvidenceCredentials): Promise<IssuedChallenge[]>;
  redeemCheckinChallenge(req: CheckinRedeemInput, credentials: EvidenceCredentials): Promise<CheckinTokenResult>;
}

/** `POST me-offline-seed` request (`parseOfflineSeedRequest`, `_shared/me/offline-seed-handler.ts`): STRICT, the two keys below and no others. */
export interface OfflineSeedRequest {
  /** The per-install device id (a UUID). The device must already be registered to this account (a 404 otherwise: this endpoint never creates one). */
  deviceId: string;
  /** `true`: a NEW seed and version; the old one stops working at once. Absent: the same seed as before (deterministic). */
  rotate?: boolean;
}

/** `POST me-offline-seed` answer (`OfflineSeedResponse`). `seed` is a SECRET: RFC 4648 base32, upper case, no padding, of 32 bytes. Never logged, never stored anywhere but the secure store. */
export interface OfflineSeedResult {
  seed: string;
  stepSeconds: 600;
  digits: 6;
  algorithm: "SHA256";
  seedVersion: number;
  /** The server's clock when the seed was issued (ISO-8601): the client's clock-offset estimate. */
  issuedAt: string;
}

/** The two offline-code calls (P4.2b-3b). The bearer is `credentials.accessToken` (the owner's, never whoever is signed in by the time the request is made); not retried here. */
export interface OfflineCodeApi {
  provisionOfflineSeed(req: OfflineSeedRequest, credentials: EvidenceCredentials): Promise<OfflineSeedResult>;
}

/** The presence fix of a marker scan, the evidence endpoint's own fix fields (`_shared/course-qr/request-shape.ts` `MarkerScanFix`: STRICT, these eight keys and no others). */
export interface MarkerScanFix {
  fixId: string;
  lat: number;
  lng: number;
  accuracyMeters: number;
  /** Epoch milliseconds. */
  capturedAt: number;
  simulated: boolean;
  foreground: boolean;
  fromApp: boolean;
}

/** What the player scanned: the shop's rotating token (Q1), or the printed facility QR (its `kid` and `sig` from the link's fragment) plus today's four-digit PIN (Q2). */
export type MarkerScanQr = { variant: "rotating"; token: string } | { variant: "static_pin"; kid: string; sig: string; pin: string };

/** `POST marker-scan` request (`parseMarkerScanBody`, `_shared/course-qr/request-shape.ts`): STRICT. A scan carries `qr` (and, to be credited, a challenge-bound `fix` with its `deviceId` and
 * the redeemed check-in token's `jti`); a CO-SIGNAL intake carries only the `fix` (completing the player's own pending purchase at that facility). */
export interface MarkerScanRequest {
  facilityId: string;
  qr?: MarkerScanQr;
  deviceId?: string;
  fix?: MarkerScanFix;
  jti?: string;
}

/** `POST marker-scan` answer. `outcome` is the WORST state across the purchases: `credited` only when every credit is, `held_review` when a reviewer must look, else `pending` (no qualifying co-signal yet).
 * 201 for a scan, 200 for a co-signal intake. No secret and no trust fact (no grade, no nonce) is ever returned. */
export interface MarkerScanResult {
  outcome: "credited" | "pending" | "held_review";
  facilityId: string;
  /** The facility-local date of the purchase; `null` for a co-signal intake that completed an earlier scan. */
  localDate: string | null;
  cosignal: "counted" | "none";
  purchases: { purchaseId: string; trailId: string; status: "valid" | "pending" | "held_review"; credit: { id: string | null; status: "credited" | "pending" | "held_review" | "void" } }[];
}

/** The player's half of a marker purchase (P5.1a S2a). The bearer is `credentials.accessToken` (the owner's); NOT retried here (a scan is single-use: a repeat answers 409). Behind `MARKER_COSIGNAL_UI_ENABLED`, which stays false:
 * nothing in the app calls it yet. Refusals the UI must tell apart: 409 `qr_used` / `fix_already_used` / `duplicate_scan`, 422 `qr_expired` / `invalid_qr` / `invalid_pin` / `no_pending_purchase` (retryable for the 7 days after the fix: the staff row may land after the player's sync, and the refusal is rolled back, so the same request succeeds once it does), 429 (a rate limit or `locked` PINs, with Retry-After). */
export interface MarkerScanApi {
  scanMarker(req: MarkerScanRequest, credentials: EvidenceCredentials): Promise<MarkerScanResult>;
}

/** React Native's FormData file part (`uri` + `name` + `type`). Not a DOM Blob; the HTTP client appends it as-is for `expo/fetch`. */
export interface ReceiptUploadUriFile {
  uri: string;
  name: string;
  type: string;
}

/** `POST receipts` multipart fields (`parseReceiptMultipart`, `_shared/receipts/request-shape.ts`): `facilityId` + `file` required; `localDate` / `receiptNumberOcr` optional. */
export interface ReceiptUploadRequest {
  facilityId: string;
  /** JPEG/PNG/HEIC as Blob/File (Node/web), or a React Native `{ uri, name, type }` part. */
  file: Blob | File | ReceiptUploadUriFile;
  /** Filename when `file` is a nameless Blob (a `File`'s own name wins; RN uri parts carry `name`). */
  fileName?: string;
  localDate?: string;
  receiptNumberOcr?: string;
}

/** `POST receipts` answer (`handleReceiptUpload` / `mapStatus`): 201 for `ok` / `duplicate` / `review`. No secret and no Storage path is returned. */
export interface ReceiptUploadResult {
  status: "ok" | "duplicate" | "review";
  localDate: string | null;
  dedupe: "clean" | "same_user" | "cross_user" | null;
  purchases: {
    purchaseId: string;
    trailId: string;
    purchaseStatus: string;
    creditId: string;
    creditStatus: string;
  }[];
}

/** Player-lane receipt image upload (P5 §40 / §43). The bearer is `credentials.accessToken` (the owner's); NOT retried here (a repeat may create another fingerprint / review path). Behind `RECEIPTS_UPLOAD_UI_ENABLED`, which stays false: nothing in the app calls it yet. Refusals the UI must tell apart: 404 `not_found`, 415 unsupported media, 413 payload too large, 422 `no_programme` / `bad_args`, 403 review account, 429 with Retry-After. */
export interface ReceiptsApi {
  uploadReceipt(req: ReceiptUploadRequest, credentials: EvidenceCredentials): Promise<ReceiptUploadResult>;
}

/** The server's `RewardKind` (`_shared/rewards/types.ts`): an offer code, or an `entitlement` (the special marker; the table's own `kind` column calls it `special_marker`, the activation answer says `entitlement`). */
export type RewardKind = "offer_code" | "entitlement";

/** One reward earned on the server and not yet activated on a device (build plan §7.5). NO server endpoint lists them yet: `listEarnedRewards` answers `[]` without a request. */
export interface EarnedReward {
  id: string;
  kind: RewardKind;
}

/** What `rewards-activate` answered with 200 (`ActivationResult`, `_shared/rewards/activate-handler.ts`). The matched table row and its reasons are server-side diagnostics and are never returned,
 * and neither is the attestation GRADE: the client reads the outcome from `state` / `held` / `replay` only. */
export interface ActivationAnswer {
  id: string;
  kind: RewardKind;
  /** `issued` / `redeemable` (activated) or `held_review`. */
  state: string;
  held: boolean;
  /** true when nothing was (re)written: the reward was already held, or already active on this very device. */
  replay: boolean;
}

/** The activation attestation material, one of the server's three shapes (`request-shape.ts`). */
export type ActivationAttestation =
  | { kind: "ios"; keyId: string; assertion: string; deviceCheckToken: string }
  | { kind: "android"; integrityToken: string }
  | { kind: "none"; hardwareSupportsAttestation: false; deviceCheckToken?: string };

/** The WIRE body of `POST rewards-activate/{id}`. STRICT at the server (an unknown key is a 400). The reward id is in the URL only. `attestation.kind: "none"` always claims
 * `hardwareSupportsAttestation: false` (`attest/activator.ts` `activationWireRequest` is the only constructor: a claim of "I can attest" with no token is graded `failed` plus a fraud signal). */
export interface ActivationWireRequest {
  deviceId: string;
  platform: "ios" | "android";
  challengeId?: string;
  nonce?: string;
  installLinkId?: string;
  attestation: ActivationAttestation;
}

/** What a caller gives to activate one reward: the attestation (and so the wire body) is built by the client's activator, bound to these. */
export interface ActivateRewardInput {
  rewardId: string;
  deviceId: string;
}

export interface RewardsApi {
  /** `POST rewards-activate/{id}` as the credentials' owner. Not retried here (a retry is safe at the server, which answers `replay: true`, but it costs a live challenge and an assertion). */
  activateReward(req: ActivateRewardInput, credentials: EvidenceCredentials): Promise<ActivationAnswer>;
  /** Earned, not yet activated rewards. `[no server endpoint serves this yet: the real client answers `[]` without a request]` */
  listEarnedRewards(): Promise<EarnedReward[]>;
}

export interface ApiClient extends EvidenceSubmitter, CheckinApi, OfflineCodeApi, MarkerScanApi, ReceiptsApi, RewardsApi {
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
