/**
 * P5 §52: drain one local "Buying a marker" co-signal through `POST marker-scan` (fix-only intake).
 *
 * ORDER (same redeem-then-post discipline as `evidence/send.ts`):
 *   held challenge, not expired
 *     -> redeem at `checkin-token` (attestation-bound) → persist `redeemed { jti }` BEFORE the scan
 *     -> `scanMarker({ facilityId, deviceId, fix, jti })` — no `qr` (cosignal intake)
 *   already redeemed → POST with that jti
 *   held but expired / none → drop (a co-signal without a usable challenge is worthless)
 *
 * `422 no_pending_purchase` is retryable until 7 days after `fix.capturedAt` (design L6: refusal is
 * rolled back, so the same request succeeds once the staff row lands). Other conflicts / rejections drop.
 * Transport / 5xx / 429 / 401 / attestation deferral: keep for the next drain.
 *
 * NEVER RETRIES inside one call. The drain (sync) owns backoff.
 */
import { isApiError } from "../api/errors";
import type { CheckinTokenResult, MarkerScanApi, MarkerScanResult } from "../api/types";
import { ATTEST_MAX_DEFERRALS, AttestationDeferred } from "../attest";
import type { EvidenceCredentials } from "../outbox";
import type { FixChallenge } from "../evidence/payload";
import type { MarkerCosignal, MarkerCosignalStore } from "./store";

/** Intake bound from design / S2a: drop after the fix is this old. */
export const MARKER_COSIGNAL_RETRY_MS = 7 * 24 * 3600_000;

export type MarkerSendOutcome =
  | { kind: "sent"; result: MarkerScanResult }
  | { kind: "dropped"; reason: "expired_challenge" | "no_challenge" | "past_retry" | "unusable"; code?: string }
  | { kind: "retry"; reason: "no_pending_purchase" | "transport" | "attestation_deferred"; code?: string; message?: string };

export interface MarkerSendDeps {
  now: () => number;
  /** `POST checkin-token` with device attestation; throws `ApiError` or `AttestationDeferred`. */
  redeem(req: { challengeId: string; nonce: string; deviceId: string }, credentials: EvidenceCredentials): Promise<CheckinTokenResult>;
  scan: Pick<MarkerScanApi, "scanMarker">;
  store: Pick<MarkerCosignalStore, "update" | "deleteById">;
}

function withChallenge(record: MarkerCosignal, challenge: FixChallenge): MarkerCosignal {
  return { ...record, challenge };
}

async function persist(deps: MarkerSendDeps, record: MarkerCosignal): Promise<void> {
  await deps.store.update(record).catch(() => undefined);
}

function isRetryableTransport(e: unknown): boolean {
  if (!isApiError(e)) return true;
  switch (e.kind) {
    case "network":
    case "unauthenticated":
    case "forbidden":
    case "rate_limited":
    case "server":
    case "unavailable":
    case "not_supported":
    case "not_configured":
      return true;
    default:
      return false;
  }
}

/** Send one queued co-signal. Never throws. */
export async function sendMarkerCoSignal(deps: MarkerSendDeps, record: MarkerCosignal, credentials: EvidenceCredentials): Promise<MarkerSendOutcome> {
  const now = deps.now();
  if (now - record.fix.capturedAt > MARKER_COSIGNAL_RETRY_MS) {
    await deps.store.deleteById(record.ownerUserId, record.id).catch(() => undefined);
    return { kind: "dropped", reason: "past_retry" };
  }

  let working = record;
  let jti: string | null = null;

  if (working.challenge.state === "redeemed") {
    jti = working.challenge.jti;
  } else if (working.challenge.state === "held") {
    if (now >= working.challenge.expiresAt) {
      await deps.store.deleteById(working.ownerUserId, working.id).catch(() => undefined);
      return { kind: "dropped", reason: "expired_challenge" };
    }
    const held = working.challenge;
    try {
      const token = await deps.redeem({ challengeId: held.challengeId, nonce: held.nonce, deviceId: working.deviceId }, credentials);
      working = withChallenge(working, {
        state: "redeemed",
        challengeId: held.challengeId,
        kind: held.kind,
        jti: token.jti,
        grade: token.attestationGrade,
      });
      await persist(deps, working);
      jti = token.jti;
    } catch (e) {
      if (e instanceof AttestationDeferred) {
        const deferrals = (held.attestDeferrals ?? 0) + 1;
        if (deferrals > ATTEST_MAX_DEFERRALS) {
          await deps.store.deleteById(working.ownerUserId, working.id).catch(() => undefined);
          return { kind: "dropped", reason: "unusable", code: "attestation_unavailable" };
        }
        working = withChallenge(working, { ...held, attestDeferrals: deferrals });
        await persist(deps, working);
        return { kind: "retry", reason: "attestation_deferred", message: e.reason };
      }
      if (isRetryableTransport(e)) {
        return {
          kind: "retry",
          reason: "transport",
          code: isApiError(e) ? (e.code ?? undefined) : undefined,
          message: e instanceof Error ? e.message : String(e),
        };
      }
      await deps.store.deleteById(working.ownerUserId, working.id).catch(() => undefined);
      return { kind: "dropped", reason: "unusable", code: isApiError(e) ? (e.code ?? undefined) : undefined };
    }
  } else {
    await deps.store.deleteById(working.ownerUserId, working.id).catch(() => undefined);
    return { kind: "dropped", reason: "no_challenge" };
  }

  if (jti === null) {
    await deps.store.deleteById(working.ownerUserId, working.id).catch(() => undefined);
    return { kind: "dropped", reason: "no_challenge" };
  }

  try {
    const result = await deps.scan.scanMarker(
      {
        facilityId: working.facilityId,
        deviceId: working.deviceId,
        fix: working.fix,
        jti,
      },
      credentials,
    );
    await deps.store.deleteById(working.ownerUserId, working.id).catch(() => undefined);
    return { kind: "sent", result };
  } catch (e) {
    if (isApiError(e) && e.kind === "rejected" && e.code === "no_pending_purchase") {
      if (deps.now() - working.fix.capturedAt > MARKER_COSIGNAL_RETRY_MS) {
        await deps.store.deleteById(working.ownerUserId, working.id).catch(() => undefined);
        return { kind: "dropped", reason: "past_retry", code: "no_pending_purchase" };
      }
      return { kind: "retry", reason: "no_pending_purchase", code: "no_pending_purchase" };
    }
    if (isRetryableTransport(e)) {
      return {
        kind: "retry",
        reason: "transport",
        code: isApiError(e) ? (e.code ?? undefined) : undefined,
        message: e instanceof Error ? e.message : String(e),
      };
    }
    await deps.store.deleteById(working.ownerUserId, working.id).catch(() => undefined);
    return { kind: "dropped", reason: "unusable", code: isApiError(e) ? (e.code ?? undefined) : undefined };
  }
}

export interface MarkerDrainDeps extends MarkerSendDeps {
  store: MarkerCosignalStore;
  currentUserId: () => string | null;
  accessTokenFor: (userId: string) => Promise<string | null>;
}

/** Drain every queued co-signal for the signed-in user. Capture stays flag-gated; drain always runs when rows exist. */
export async function drainMarkerCoSignals(deps: MarkerDrainDeps): Promise<MarkerSendOutcome[]> {
  const owner = deps.currentUserId();
  if (owner === null || owner === "") return [];
  const token = await deps.accessTokenFor(owner);
  if (token === null || token === "") return [];
  const credentials = { userId: owner, accessToken: token };
  const rows = await deps.store.listByOwner(owner);
  const out: MarkerSendOutcome[] = [];
  for (const row of rows) {
    out.push(await sendMarkerCoSignal(deps, row, credentials));
  }
  return out;
}
