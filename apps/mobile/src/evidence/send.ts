/**
 * One evidence item -> the server (build plan §7.6). `sendEvidenceItem` is what `ApiClient.submitEvidence` runs; `sendEvidenceBatch` is
 * `ApiClient.submitEvidenceBatch`. Both are pure over injected transport functions, so the http client and the tests share one implementation.
 *
 * ORDER FOR A FIX WITH A CHALLENGE (`FixChallenge`, `payload.ts`):
 *   held (consumed locally at check-in, not yet redeemed)
 *     -> expired?        `none / expired` and the fix goes with NO challenge (the x0.6 penalty): an expired challenge is never used;
 *     -> `checkin-token` redeem it with the attestor's capability (`hardwareSupportsAttestation`), authenticated as the ITEM'S OWNER
 *        (`credentials.accessToken`, never a token fetched here);
 *          ok                          -> `redeemed { jti }`, persisted BEFORE the evidence request (`persistPayload`), so a crash between the
 *                                         two cannot lose the jti the server has already bound;
 *          transport / 5xx / 429 / 401 -> stop and answer that (retry; the challenge is untouched and may still be redeemed next time);
 *          any other refusal           -> `none / unusable` (already used, expired, not ours...): the fix goes with no challenge;
 *   redeemed -> its jti rides on the fix, in EVERY later send, byte for byte: the server hashes the whole submission, so a replay of a
 *               play that was in fact recorded must be identical or it is a 409 `evidence_conflict`.
 * The payload changes (jti recorded, challenge dropped) travel back to the outbox on the answer (`ServerAnswer.payload`).
 *
 * NEVER RETRIES: one request per call. Retrying belongs to the outbox (backoff + jitter + `Retry-After`), and `source_ref` makes its replays safe.
 */
import { isApiError } from "../api/errors";
import { answersFromBatchHttp } from "../api/evidence-answer";
import type { CheckinTokenResult } from "../api/types";
import type { Attestor } from "../attest";
import type { EvidenceCredentials, JsonValue, OutboxItem, ServerAnswer } from "../outbox";
import { buildEvidenceBody, fixesOf, parseEvidencePayload, toJsonValue, type EvidencePayload, type WireBody } from "./payload";

export interface SendDeps {
  attestor: Attestor;
  now: () => number;
  /** `POST checkin-token`; throws `ApiError`. Authenticated with exactly `accessToken`. */
  redeem(req: { challengeId: string; nonce: string; hardwareSupportsAttestation: boolean }, accessToken: string): Promise<CheckinTokenResult>;
  /** `POST evidence`: never throws for an HTTP outcome. */
  post(body: WireBody, accessToken: string): Promise<ServerAnswer>;
  /** Writes `payload` into the item's stored row now (crash safety for the redeemed jti). Optional. */
  persistPayload?(item: OutboxItem, payload: JsonValue): Promise<void>;
}

function withPayload(answer: ServerAnswer, payload: EvidencePayload | null): ServerAnswer {
  if (payload === null || answer.kind === "unsendable") return answer;
  return { ...answer, payload: toJsonValue(payload) };
}

function answerForRedeemError(e: unknown): ServerAnswer | null {
  if (!isApiError(e)) return { kind: "network_error", message: e instanceof Error ? e.message : "redeem failed" };
  switch (e.kind) {
    case "network":
      return { kind: "network_error", message: e.message };
    case "unauthenticated":
    case "forbidden":
    case "rate_limited":
    case "server":
    case "unavailable":
    case "not_supported":
      return { kind: "response", status: e.status ?? (e.kind === "unauthenticated" ? 401 : 500), code: e.code ?? undefined, ...(e.retryAfterSeconds !== null ? { retryAfterSeconds: e.retryAfterSeconds } : {}) };
    default:
      return null; // the challenge itself was refused: drop it, send without
  }
}

export async function sendEvidenceItem(deps: SendDeps, item: OutboxItem, credentials: EvidenceCredentials): Promise<ServerAnswer> {
  const parsed = parseEvidencePayload(item.payload);
  if (!parsed.ok) return { kind: "unsendable", code: "invalid_payload", message: parsed.message };
  let payload: EvidencePayload = parsed.payload;
  let changed = false;

  for (const fix of fixesOf(payload.submission)) {
    const c = payload.challenges[fix.fixId];
    if (!c || c.state !== "held") continue;
    if (deps.now() >= c.expiresAt) {
      payload = { ...payload, challenges: { ...payload.challenges, [fix.fixId]: { state: "none", reason: "expired" } } };
      changed = true;
      continue;
    }
    let next: EvidencePayload;
    try {
      const token = await deps.redeem(
        { challengeId: c.challengeId, nonce: c.nonce, hardwareSupportsAttestation: deps.attestor.capability.hardwareSupportsAttestation },
        credentials.accessToken,
      );
      next = { ...payload, challenges: { ...payload.challenges, [fix.fixId]: { state: "redeemed", challengeId: c.challengeId, kind: c.kind, jti: token.jti, grade: token.attestationGrade } } };
    } catch (e) {
      const answer = answerForRedeemError(e);
      if (answer !== null) return withPayload(answer, changed ? payload : null);
      next = { ...payload, challenges: { ...payload.challenges, [fix.fixId]: { state: "none", reason: "unusable" } } };
    }
    payload = next;
    changed = true;
    // The redemption is spent at the server: record its outcome before anything else can fail.
    if (deps.persistPayload) await deps.persistPayload(item, toJsonValue(payload)).catch(() => undefined);
  }

  const built = buildEvidenceBody(item, payload);
  if (!built.ok) return { kind: "unsendable", code: built.code, message: built.message };
  return withPayload(await deps.post(built.body, credentials.accessToken), changed ? payload : null);
}

/** One request for one planned chunk (`batch.ts`): the answers are aligned with `items`. An item whose body cannot be built is `unsendable` and
 * is left out of the request. */
export async function sendEvidenceBatch(
  deps: { postBatch(bodies: WireBody[], accessToken: string): Promise<ReturnType<typeof answersFromBatchHttp>> },
  items: readonly OutboxItem[],
  credentials: EvidenceCredentials,
): Promise<ServerAnswer[]> {
  const answers: ServerAnswer[] = new Array<ServerAnswer>(items.length);
  const bodies: WireBody[] = [];
  const slots: number[] = [];
  items.forEach((item, i) => {
    const parsed = parseEvidencePayload(item.payload);
    if (!parsed.ok) {
      answers[i] = { kind: "unsendable", code: "invalid_payload", message: parsed.message };
      return;
    }
    const built = buildEvidenceBody(item, parsed.payload);
    if (!built.ok) {
      answers[i] = { kind: "unsendable", code: built.code, message: built.message };
      return;
    }
    bodies.push(built.body);
    slots.push(i);
  });
  if (bodies.length === 0) return answers;
  const got = await deps.postBatch(bodies, credentials.accessToken);
  slots.forEach((slot, k) => {
    answers[slot] = got[k] ?? { kind: "network_error", message: "evidence-batch: missing answer" };
  });
  return answers;
}
