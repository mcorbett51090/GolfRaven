/**
 * Runtime validation of every response the real client accepts (zod 4.6.5, already used server-side). The shapes are copied from the
 * server handlers and their tests, not invented:
 *
 *  - envelope: `{ "data": T }` on success (`okResponse`), `{ "error": { code, message, details? } }` on failure (`errorResponse`),
 *    `supabase/functions/_shared/http.ts`;
 *  - `GET /me-signin-methods`          -> `{ methods: MethodView[] }`                      `_shared/signin/methods-handler.ts#handleListMethods`
 *  - `POST /me-signin-methods` link    -> `{ linked, linkedTo, methods | null }`           `#handleLinkProvider` (`LinkResult`)
 *  - `POST /me-signin-methods` unlink  -> `{ methods, revocation }`                        `#handleUnlinkProvider` (`UnlinkResult`)
 *  - `DELETE /me-delete`               -> `{ userId, deletedAt, authUserDeleted, authUserAlreadyGone, signinProvidersRevoked, connectorsRevoked }`
 *                                         `me-delete/index.ts`
 *  - `GET /me-export`                  -> `{ generatedAt, userId, data }`                  `_shared/me/export-handler.ts` (`MeExportEnvelope`)
 *  - `POST /me-push-token`             -> `{ deviceId, updatedAt }`                        `_shared/me/push-token-handler.ts` (`PushTokenResult`)
 *
 *  - `POST /checkin-challenge`         -> `{ challenges: IssuedChallenge[] }` (201)       `_shared/checkin/challenge-handler.ts`
 *  - `POST /checkin-token`             -> `{ jti, expiresAt, attestationGrade }` (201)   `_shared/checkin/token-handler.ts`
 *  - `POST /evidence`, `/evidence-batch` -> mapped to an outbox `ServerAnswer`, not validated here: `evidence-answer.ts`
 *  - `POST /me-offline-seed`           -> `{ seed, stepSeconds, digits, algorithm, seedVersion, issuedAt }`  `_shared/me/offline-seed-handler.ts` (P4.2b-3b)
 *  - `POST /rewards-activate/{id}`     -> `{ id, kind, state, held, replay }`              `_shared/rewards/activate-handler.ts` (P4.2b-3b)
 *
 * A response that does not match is `bad_response`, never a partial success. Unknown EXTRA keys are ignored (zod's default "strip"): the
 * server may add fields without breaking an installed app; a missing or wrongly typed one is refused.
 */
import { z } from "zod";
import { OFFLINE_CODE_ALGORITHM, OFFLINE_CODE_DIGITS, OFFLINE_CODE_STEP_SECONDS } from "../offline-code/params";

export const providerSchema = z.enum(["apple", "google", "email"]);

/** `MethodView` (methods-handler.ts). */
export const methodViewSchema = z.object({
  provider: z.string().min(1),
  linkedAt: z.string().min(1),
  isPrivateRelay: z.boolean(),
  /** false for the only remaining method (unlinking it is a 422). */
  canUnlink: z.boolean(),
});

export const listMethodsSchema = z.object({ methods: z.array(methodViewSchema) });

export const linkResultSchema = z.object({
  linked: z.object({ provider: z.literal("apple"), created: z.boolean(), isPrivateRelay: z.boolean() }),
  linkedTo: z.enum(["self", "proven_account"]),
  methods: z.array(methodViewSchema).nullable(),
});

/** `RevocationOutcome` (signin/revocation.ts). */
export const revocationOutcomeSchema = z.object({
  queueId: z.string(),
  provider: z.string(),
  status: z.enum(["revoked", "queued_for_retry"]),
  error: z.string().optional(),
});

export const unlinkResultSchema = z.object({ methods: z.array(methodViewSchema), revocation: z.array(revocationOutcomeSchema) });

/** `ProviderRevocationOutcome` (me/provider-revocation.ts). */
const connectorRevocationSchema = z.object({ provider: z.string(), revoked: z.boolean(), deferred: z.boolean(), reason: z.string() });

export const deleteResultSchema = z.object({
  userId: z.string().min(1),
  deletedAt: z.string().min(1),
  authUserDeleted: z.boolean(),
  authUserAlreadyGone: z.boolean(),
  signinProvidersRevoked: z.array(revocationOutcomeSchema),
  connectorsRevoked: z.array(connectorRevocationSchema),
});

export const exportResultSchema = z.object({
  generatedAt: z.string().min(1),
  userId: z.string().min(1),
  data: z.record(z.string(), z.unknown()),
});

export const pushTokenResultSchema = z.object({ deviceId: z.string().min(1), updatedAt: z.string().min(1) });

/** The failure envelope. Anything else (an HTML gateway page, an empty body) is mapped by status alone. */
export const errorEnvelopeSchema = z.object({
  error: z.object({ code: z.string(), message: z.string().optional(), details: z.unknown().optional() }),
});

export const retryDetailsSchema = z.object({ retryAfterSeconds: z.number().positive().finite() });
export const attemptsDetailsSchema = z.object({ attemptsRemaining: z.number().int().nonnegative() });

/** The success envelope `{ data: ... }`; the payload is then checked against the call's own schema (a missing `data` is `undefined`, which no
 * payload schema accepts). */
export const successEnvelopeSchema = z.object({ data: z.unknown() });

/** `IssuedChallenge`. The id is opaque; the nonce is unpadded base64url (the server mints 32 random bytes). */
export const issuedChallengeSchema = z.object({
  id: z.string().min(1).max(128),
  nonce: z.string().regex(/^[A-Za-z0-9_-]{1,512}$/),
  expiresAt: z.string().min(1).refine((s) => Number.isFinite(Date.parse(s))),
  kind: z.enum(["live", "prefetched"]),
});
export const challengesResultSchema = z.object({ challenges: z.array(issuedChallengeSchema) });

/** `IssuedToken`. The jti must be what the evidence endpoint accepts as `checkinTokenJti` (unpadded base64url, 1-128).
 * `rekey` is the server's stale-App-Attest-key hint (`token-handler.ts`): present, and always `true`, ONLY when an iOS assertion was refused for a key-identity reason (`key_id_mismatch`
 * graded `failed`, `key_not_registered` graded `unattestable`); omitted otherwise, never `false`. The token is valid whatever it says; `attest/redeemer.ts` is the one consumer.
 * The schema stays non-strict (another unknown member is ignored), but this one is explicit: a `rekey: false` would break the contract and fails as `bad_response`, loudly. */
export const checkinTokenResultSchema = z.object({
  jti: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
  expiresAt: z.string().min(1),
  attestationGrade: z.enum(["attested", "unattestable", "failed"]),
  rekey: z.literal(true).optional(),
});

/** `POST devices-attest-key` answer (`attest-key-handler.ts`): 201 `registered`, 200 when it replaced an earlier key. */
export const attestKeyResultSchema = z.object({ deviceId: z.string().min(1), keyId: z.string().min(1), replaced: z.boolean() });

/** `POST /me-offline-seed` -> `OfflineSeedResponse` (`_shared/me/offline-seed-handler.ts`). The three pinned parameters are literals: an answer that echoes another step, digit count or algorithm is
 * `bad_response` ("a client built against another value fails loudly instead of computing wrong codes", `offline-code/params.ts`). `seed` is 52 base32 characters (32 bytes). */
export const offlineSeedResultSchema = z.object({
  seed: z.string().regex(/^[A-Z2-7]{52}$/),
  stepSeconds: z.literal(OFFLINE_CODE_STEP_SECONDS),
  digits: z.literal(OFFLINE_CODE_DIGITS),
  algorithm: z.literal(OFFLINE_CODE_ALGORITHM),
  seedVersion: z.number().int().min(1),
  issuedAt: z.string().min(1).refine((s) => Number.isFinite(Date.parse(s))),
});

/** `POST /rewards-activate/{id}` -> `ActivationResult` (`_shared/rewards/activate-handler.ts`). `state` is open (the server may add one); the client reads `held` and the two active states. */
export const activationResultSchema = z.object({
  id: z.string().min(1).max(128),
  kind: z.enum(["offer_code", "entitlement"]),
  state: z.string().min(1).max(64),
  held: z.boolean(),
  replay: z.boolean(),
});
