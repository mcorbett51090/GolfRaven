/**
 * The real `ApiClient` (P4.2a), over the Edge Functions that exist today. Base URL = the project's Functions root
 * (`EXPO_PUBLIC_API_BASE_URL`, https only); each call goes to `<base>/<function-name>`:
 *
 * | method                  | request                                              | function            |
 * |-------------------------|------------------------------------------------------|---------------------|
 * | `listSignInMethods`     | `GET`                                                | `me-signin-methods` |
 * | `linkSignInMethod`      | `POST { action: "link", provider, identityToken, authorizationCode, nonce, emailProof? }` | `me-signin-methods` |
 * | `unlinkSignInMethod`    | `POST { action: "unlink", provider }`                | `me-signin-methods` |
 * | `deleteAccount`         | `DELETE`                                             | `me-delete`         |
 * | `exportData`            | `GET`                                                | `me-export`         |
 * | `registerPushToken`     | `POST { deviceId, expoToken, platform? }`            | `me-push-token`     |
 * | `submitEvidence`        | `POST <evidence body>` (`evidence/payload.ts`)       | `evidence`          |
 * | `submitEvidenceBatch`   | `POST { items: [<evidence body>] }`                  | `evidence-batch`    |
 * | `requestCheckinChallenges` | `POST { deviceId, facilityId?, prefetchCount? }`  | `checkin-challenge` |
 * | `redeemCheckinChallenge`| `POST { challengeId, nonce, hardwareSupportsAttestation, attestation? }` (`attest/redeemer.ts` builds it) | `checkin-token` |
 *
 * Auth: `Authorization: Bearer <Supabase access token>` from `getAccessToken()` (the auth service refreshes an expired token itself); a `401`
 * forces ONE refresh and one repeat of the request, then surfaces as `unauthenticated`. No cookies, no redirects.
 *
 * Retry policy (kept consistent with the outbox, `outbox/machine.ts`: `429` / `5xx` / network are the retryable class, jittered exponential
 * backoff, a server `Retry-After` is a floor), scaled down because a person is waiting: at most 3 attempts, 0.5 s base, 4 s cap, a `Retry-After`
 * above 10 s is surfaced instead of slept through. Only IDEMPOTENT calls are retried (`GET`s, `DELETE me`, the push-token upsert). `link` and
 * `unlink` are not: an Apple authorization code is single-use, every OTP proof attempt is counted against 5 per address per hour, and a second
 * unlink is a 404, so a blind repeat could turn one success into a visible failure or burn an attempt. The EVIDENCE and CHECK-IN calls are not retried
 * either, and are made with the OWNER's credentials handed in by the caller (`credentials.accessToken`; the client never fetches or refreshes a token
 * for them): the outbox owns evidence retries (backoff, jitter, `Retry-After`; `source_ref` makes a replay safe) and a challenge is single-use. Each attempt has a 20 s timeout (the
 * server's own request cap is 15 s).
 *
 * `[Request/response shapes are the handlers' own (see `schemas.ts`); the deployed URL layout (`/functions/v1/<name>`) is the Supabase
 * convention and is unverified against a real project: nothing here has ever called a server.]`
 */
import { DEFAULT_MIN_AGE } from "../age/gate";
import { PlainRedeemer, type CheckinRedeemer, type RedeemIo } from "../attest";
import { planBatches, selectBatchEntries } from "../evidence/batch";
import { sendEvidenceBatch, sendEvidenceItem } from "../evidence/send";
import type { WireBody } from "../evidence/payload";
import type { EvidenceCredentials, JsonValue, OutboxItem, ServerAnswer } from "../outbox";
import type { ProgrammeStatus } from "../wallet";
import { ApiError, kindForStatus } from "./errors";
import { answerFromHttp, answersFromBatchHttp } from "./evidence-answer";
import { retryAfterSecondsFrom } from "./retry-after";
import {
  attestKeyResultSchema,
  challengesResultSchema,
  checkinTokenResultSchema,
  deleteResultSchema,
  errorEnvelopeSchema,
  exportResultSchema,
  linkResultSchema,
  listMethodsSchema,
  pushTokenResultSchema,
  successEnvelopeSchema,
  unlinkResultSchema,
} from "./schemas";
import type { z } from "zod";
import type { AchievementSummary, ApiClient, CheckinChallengeRequest, CheckinRedeemInput, PlaySummary } from "./types";

export { retryAfterSecondsFrom };

/** The part of `fetch` this client uses. `expo/fetch` and the global `fetch` both satisfy it. */
export type HttpFetch = (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string; redirect: "error"; credentials: "omit"; signal: AbortSignal },
) => Promise<Response>;

export const HTTP_POLICY = {
  timeoutMs: 20_000,
  maxAttempts: 3,
  backoffBaseMs: 500,
  backoffCapMs: 4_000,
  /** A `Retry-After` longer than this is returned to the caller, not slept through. */
  retryAfterCapMs: 10_000,
  /** Upper bound on a response body, defence in depth (the export is documented as at most 8 MiB server-side). */
  maxResponseChars: 16 * 1024 * 1024,
} as const;

export interface HttpApiOptions {
  /** The Functions root, no trailing slash (`parseApiBaseUrl`). */
  baseUrl: string;
  fetch: HttpFetch;
  /** The current access token (refreshing it if it is about to expire); `forceRefresh` after a `401`. `null` = signed out. */
  getAccessToken: (opts?: { forceRefresh?: boolean }) => Promise<string | null>;
  rng?: () => number;
  sleep?: (ms: number) => Promise<void>;
  policy?: Partial<{ [K in keyof typeof HTTP_POLICY]: number }>;
  /** How a check-in redemption is built and attested (`attest/redeemer.ts`). Default: `PlainRedeemer` (no attestation: `hardwareSupportsAttestation: false`). */
  redeemer?: CheckinRedeemer;
  now?: () => number;
  /** Writes an item's payload into its stored row (the redeemed check-in jti, `evidence/send.ts`). */
  persistEvidencePayload?: (item: OutboxItem, payload: JsonValue) => Promise<void>;
}

interface CallSpec<T extends z.ZodType> {
  fn: string;
  method: "GET" | "POST" | "DELETE";
  body?: unknown;
  schema: T;
  /** Safe to repeat after a transport failure / 5xx. */
  idempotent: boolean;
  /** The success status (default 200; the two check-in endpoints answer 201; `devices-attest-key` answers 201 or 200). */
  okStatus?: number | readonly number[];
  /** A bearer chosen by the caller: used as is, never replaced or refreshed (a `401` is surfaced, not retried with another user's token). */
  accessToken?: string;
}

const realSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Backoff for attempt `n` (1 = the first retry): uniform in [d/2, d], `d = min(cap, base * 2^(n-1))`; a `Retry-After` is a floor. */
export function backoffMs(attempt: number, rng: () => number, p: { backoffBaseMs: number; backoffCapMs: number }, retryAfterSeconds: number | null): number {
  const exp = Math.min(p.backoffCapMs, p.backoffBaseMs * 2 ** Math.max(0, attempt - 1));
  const jittered = Math.floor(exp / 2 + rng() * (exp / 2));
  return Math.max(jittered, retryAfterSeconds !== null ? Math.ceil(retryAfterSeconds * 1000) : 0);
}

export function createHttpApiClient(opts: HttpApiOptions): ApiClient {
  const policy: { [K in keyof typeof HTTP_POLICY]: number } = { ...HTTP_POLICY, ...opts.policy };
  const rng = opts.rng ?? Math.random;
  const sleep = opts.sleep ?? realSleep;
  const base = opts.baseUrl.replace(/\/+$/, "");
  const redeemer = opts.redeemer ?? new PlainRedeemer();
  const now = opts.now ?? Date.now;

  interface Raw {
    status: number;
    headers: Headers;
    text: string;
  }

  async function once(url: string, spec: CallSpec<z.ZodType>, token: string, sent: { maybeApplied: boolean }): Promise<Raw> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), policy.timeoutMs);
    try {
      const headers: Record<string, string> = { Authorization: `Bearer ${token}`, Accept: "application/json" };
      let body: string | undefined;
      if (spec.body !== undefined) {
        headers["Content-Type"] = "application/json";
        body = JSON.stringify(spec.body);
      }
      const res = await opts.fetch(url, { method: spec.method, headers, ...(body !== undefined ? { body } : {}), redirect: "error", credentials: "omit", signal: controller.signal });
      // Read the body inside the timeout: a stalled body must not outlive it.
      const text = await res.text();
      if (res.status >= 500) sent.maybeApplied = true; // a 5xx can follow a half-executed request
      if (text.length > policy.maxResponseChars) throw new ApiError({ kind: "bad_response", status: res.status, message: "response too large" });
      return { status: res.status, headers: res.headers, text };
    } catch (e) {
      if (e instanceof ApiError) throw e;
      sent.maybeApplied = true; // the request was sent; whether the server ran it is unknown
      throw new ApiError({ kind: "network", message: controller.signal.aborted ? `timed out after ${policy.timeoutMs} ms` : e instanceof Error ? e.message : "network error" });
    } finally {
      clearTimeout(timer);
    }
  }

  function failure(res: Raw): ApiError {
    let code: string | null = null;
    let details: unknown;
    let message: string | undefined;
    try {
      const parsed = errorEnvelopeSchema.safeParse(JSON.parse(res.text));
      if (parsed.success) {
        code = parsed.data.error.code;
        details = parsed.data.error.details;
        message = parsed.data.error.message;
      }
    } catch {
      // not JSON (a gateway page, an empty body): the status alone decides
    }
    return new ApiError({
      kind: kindForStatus(res.status),
      status: res.status,
      code,
      details,
      retryAfterSeconds: retryAfterSecondsFrom(res, details),
      ...(message !== undefined ? { message } : {}),
    });
  }

  /** The token provider may throw (a refresh that could not reach the server): that is a transport failure, not "signed out". */
  async function tokenOrThrow(forceRefresh = false): Promise<string | null> {
    try {
      return await opts.getAccessToken(forceRefresh ? { forceRefresh: true } : undefined);
    } catch (e) {
      throw new ApiError({ kind: "network", message: e instanceof Error ? e.message : "could not refresh the session" });
    }
  }

  /** Runs the call; any error it throws is flagged `mayHaveBeenApplied` if an earlier request of the call may have been executed unseen. */
  async function call<T extends z.ZodType>(spec: CallSpec<T>): Promise<z.infer<T>> {
    const sent = { maybeApplied: false };
    try {
      return await attemptCall(spec, sent);
    } catch (e) {
      if (e instanceof ApiError && sent.maybeApplied && !e.mayHaveBeenApplied) throw e.withMayHaveBeenApplied();
      throw e;
    }
  }

  async function attemptCall<T extends z.ZodType>(spec: CallSpec<T>, sent: { maybeApplied: boolean }): Promise<z.infer<T>> {
    const url = `${base}/${spec.fn}`;
    const attempts = spec.idempotent ? policy.maxAttempts : 1;
    let refreshed = false;
    let last: ApiError | null = null;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      let token = spec.accessToken ?? (await tokenOrThrow());
      if (token === null) throw new ApiError({ kind: "unauthenticated", message: "not signed in" });
      let res: Raw;
      try {
        res = await once(url, spec, token, sent);
        if (res.status === 401 && !refreshed && spec.accessToken === undefined) {
          refreshed = true;
          const fresh = await tokenOrThrow(true);
          if (fresh === null) throw new ApiError({ kind: "unauthenticated", status: 401, message: "session expired" });
          token = fresh;
          res = await once(url, spec, token, sent);
        }
      } catch (e) {
        if (!(e instanceof ApiError)) throw e;
        last = e;
        if (e.kind === "network" && attempt < attempts) {
          await sleep(backoffMs(attempt, rng, policy, null));
          continue;
        }
        throw e;
      }
      const okStatuses = spec.okStatus === undefined ? [200] : typeof spec.okStatus === "number" ? [spec.okStatus] : spec.okStatus;
      const okStatus = okStatuses[0] ?? 200;
      if (okStatuses.includes(res.status)) {
        let json: unknown;
        try {
          json = JSON.parse(res.text);
        } catch {
          throw new ApiError({ kind: "bad_response", status: okStatus, message: "response is not JSON" });
        }
        const outer = successEnvelopeSchema.safeParse(json);
        const inner = outer.success ? spec.schema.safeParse(outer.data.data) : null;
        if (!inner || !inner.success) {
          const where = (inner && !inner.success ? inner.error.issues[0]?.path.join(".") : "") ?? "";
          throw new ApiError({ kind: "bad_response", status: okStatus, message: `unexpected response shape${where ? ` at ${where}` : ""}` });
        }
        return inner.data;
      }
      if (res.status >= 200 && res.status < 400) throw new ApiError({ kind: "bad_response", status: res.status, message: `unexpected success status ${res.status} (the contract answers ${okStatuses.join(" or ")})` });
      const err = failure(res);
      last = err;
      const retryable = err.kind === "server" || err.kind === "unavailable" || err.kind === "rate_limited";
      if (retryable && attempt < attempts) {
        const wait = backoffMs(attempt, rng, policy, err.retryAfterSeconds);
        // A long Retry-After (the daily export cap, an hour-long OTP lockout) is the caller's to show, not ours to sleep through.
        if (wait <= policy.retryAfterCapMs) {
          await sleep(wait);
          continue;
        }
      }
      throw err;
    }
    throw last ?? new ApiError({ kind: "network", message: "no attempt was made" });
  }

  /** One POST, no retry, no token handling: the caller's bearer, the raw response, or `{ answer }` when the transport failed. */
  async function rawPost(fn: string, body: unknown, accessToken: string): Promise<Raw | { answer: ServerAnswer }> {
    try {
      return await once(`${base}/${fn}`, { fn, method: "POST", body, schema: successEnvelopeSchema, idempotent: false }, accessToken, { maybeApplied: false });
    } catch (e) {
      return { answer: { kind: "network_error", message: e instanceof Error ? e.message : "network error" } };
    }
  }

  async function postEvidence(fn: string, body: unknown, accessToken: string): Promise<ServerAnswer> {
    const raw = await rawPost(fn, body, accessToken);
    return "answer" in raw ? raw.answer : answerFromHttp(raw);
  }

  /** The HTTP a redemption needs, as the owner of `accessToken` (never whoever is signed in by now): the three calls `attest/redeemer.ts` makes. None is retried here. */
  function redeemIo(accessToken: string, deviceId: string): RedeemIo {
    return {
      post: (wire) => call({ fn: "checkin-token", method: "POST", body: wire, schema: checkinTokenResultSchema, idempotent: false, okStatus: 201, accessToken }),
      requestLiveChallenge: async () => {
        const [c] = (await call({ fn: "checkin-challenge", method: "POST", body: { deviceId }, schema: challengesResultSchema, idempotent: false, okStatus: 201, accessToken })).challenges;
        if (!c || c.kind !== "live") throw new ApiError({ kind: "bad_response", status: 201, message: "checkin-challenge returned no live challenge" });
        return c;
      },
      registerKey: async (req) => {
        await call({ fn: "devices-attest-key", method: "POST", body: req, schema: attestKeyResultSchema, idempotent: false, okStatus: [201, 200], accessToken });
      },
    };
  }

  return {
    // No server endpoint serves these yet (no `api.*` views and no policy endpoint exist in `supabase/`): the honest answers are the
    // compiled default and "nothing". They make no request, so a build with a real client never shows data it did not get.
    getPolicy: () => Promise.resolve({ minAge: DEFAULT_MIN_AGE }),
    listPlays: (): Promise<PlaySummary[]> => Promise.resolve([]),
    listAchievements: (): Promise<AchievementSummary[]> => Promise.resolve([]),
    listTrailProgrammes: (): Promise<Record<string, ProgrammeStatus>> => Promise.resolve({}),

    async listSignInMethods() {
      return (await call({ fn: "me-signin-methods", method: "GET", schema: listMethodsSchema, idempotent: true })).methods;
    },
    linkSignInMethod(req) {
      return call({
        fn: "me-signin-methods",
        method: "POST",
        body: {
          action: "link",
          provider: req.provider,
          identityToken: req.identityToken,
          authorizationCode: req.authorizationCode,
          nonce: req.nonce,
          ...(req.emailProof ? { emailProof: { code: req.emailProof.code } } : {}),
        },
        schema: linkResultSchema,
        idempotent: false,
      });
    },
    unlinkSignInMethod(provider) {
      return call({ fn: "me-signin-methods", method: "POST", body: { action: "unlink", provider }, schema: unlinkResultSchema, idempotent: false });
    },
    deleteAccount() {
      return call({ fn: "me-delete", method: "DELETE", schema: deleteResultSchema, idempotent: true });
    },
    exportData() {
      return call({ fn: "me-export", method: "GET", schema: exportResultSchema, idempotent: true });
    },
    registerPushToken(req) {
      return call({
        fn: "me-push-token",
        method: "POST",
        body: { deviceId: req.deviceId, expoToken: req.expoToken, ...(req.platform ? { platform: req.platform } : {}) },
        schema: pushTokenResultSchema,
        idempotent: true,
      });
    },

    requestCheckinChallenges(req: CheckinChallengeRequest, credentials: EvidenceCredentials) {
      if (req.prefetchCount !== undefined && (!Number.isInteger(req.prefetchCount) || req.prefetchCount < 0 || req.prefetchCount > 10)) {
        return Promise.reject(new RangeError("prefetchCount must be an integer from 0 to 10"));
      }
      return call({
        fn: "checkin-challenge",
        method: "POST",
        body: { deviceId: req.deviceId, ...(req.facilityId !== undefined ? { facilityId: req.facilityId } : {}), ...(req.prefetchCount !== undefined ? { prefetchCount: req.prefetchCount } : {}) },
        schema: challengesResultSchema,
        idempotent: false,
        okStatus: 201,
        accessToken: credentials.accessToken,
      }).then((r) => r.challenges);
    },
    redeemCheckinChallenge(req: CheckinRedeemInput, credentials: EvidenceCredentials) {
      return redeemer.redeem({ ...req, userId: credentials.userId, accessToken: credentials.accessToken }, redeemIo(credentials.accessToken, req.deviceId));
    },

    /** `POST evidence` (`evidence/send.ts`): ONE request, never retried here (the outbox owns retries; `source_ref` makes its replays safe); the
     * bearer is `credentials.accessToken`, the owner's, and no other token is ever fetched for it. The answer is mapped to the §7.6 table by
     * `evidence-answer.ts`; this method never throws for an HTTP outcome. */
    submitEvidence(item: OutboxItem, credentials: EvidenceCredentials): Promise<ServerAnswer> {
      return sendEvidenceItem(
        {
          now,
          redeem: (req, creds) => redeemer.redeem({ ...req, userId: creds.userId, accessToken: creds.accessToken }, redeemIo(creds.accessToken, req.deviceId)),
          post: (body, accessToken) => postEvidence("evidence", body, accessToken),
          ...(opts.persistEvidencePayload ? { persistPayload: opts.persistEvidencePayload } : {}),
        },
        item,
        credentials,
      ).catch((e: unknown): ServerAnswer => ({ kind: "network_error", message: e instanceof Error ? e.message : String(e) }));
    },

    planEvidenceBatches(items: readonly OutboxItem[]) {
      return planBatches(selectBatchEntries(items)).batches.map((b) => b.map((e) => e.item));
    },

    /** `POST evidence-batch` for ONE planned chunk (`planEvidenceBatches`): historic imports, sorted and split by `evidence/batch.ts`. */
    submitEvidenceBatch(items: readonly OutboxItem[], credentials: EvidenceCredentials): Promise<ServerAnswer[]> {
      return sendEvidenceBatch(
        {
          postBatch: async (bodies: WireBody[], accessToken: string) => {
            const raw = await rawPost("evidence-batch", { items: bodies }, accessToken);
            return "answer" in raw ? bodies.map(() => raw.answer) : answersFromBatchHttp(raw, bodies.length);
          },
        },
        items,
        credentials,
      ).catch((e: unknown): ServerAnswer[] => items.map(() => ({ kind: "network_error", message: e instanceof Error ? e.message : String(e) })));
    },
  };
}
