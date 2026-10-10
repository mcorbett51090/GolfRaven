/**
 * The recorded Edge Function responses (`test/fixtures/edge-contract.json`, produced by the server's own handlers: see its `_provenance`) and a
 * fake `fetch` that serves them, with every request recorded.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { HttpFetch } from "../../src/api";

interface Recorded {
  status: number;
  body: string;
  /** The request the real handler was given (the evidence-lane entries only). */
  request?: unknown;
}
const file = JSON.parse(readFileSync(fileURLToPath(new URL("../fixtures/edge-contract.json", import.meta.url)), "utf8")) as { responses: Record<string, Recorded>; vectors: Vectors };
export const RECORDED = file.responses;

/** Values the SERVER's own functions produced for fixed inputs (`scripts/record-edge-contract.rec.ts`). */
export interface Vectors {
  sourceRefs: Record<string, { request: Record<string, unknown>; sourceRef: string; inputHash: string }>;
  binding: {
    androidRequestBinding: { body: { rewardId: string; deviceId: string; platform: "android"; challengeId: string; installLinkId: string }; challengeBase64Url: string; canonicalBodyUtf8: string; canonicalBodyHex: string; hashHex: string };
    androidRequestBindingNoInstallLink: { challengeBase64Url: string; hashHex: string };
    iosActivation: { body: { rewardId: string; deviceId: string; challengeId: string; deviceCheckTokenSha256: string; nonce: string }; challengeString: string; hashHex: string };
    iosAttestKey: { body: { challengeId: string; deviceId: string; keyId: string; nonce: string }; challengeString: string; hashHex: string };
    /** The check-in binding for the fixed inputs of the security doc, as the server's own functions produced it (P4.2b-2). */
    checkin: {
      body: { challengeId: string; deviceId: string; userId: string };
      nonce: string;
      ios: { challengeString: string; clientDataHashHex: string };
      android: { canonicalBodyUtf8: string; requestHash: string };
    };
    canonicalJsonSample: { input: unknown; output: string };
  };
  /** P4.2c: the server's challenge window as observed through the REAL evidence handler (`consumed` = the token was consumed by the fix, i.e. the fix counted as a co-signal). */
  checkinWindow: {
    prefetchedCovered: { consumed: boolean };
    liveFirst: { consumed: boolean };
    liveAfterFix: { consumed: boolean };
    edges: Array<{ kind: "prefetched" | "live"; offsetFromIssueMs: number; issuedAt: number; expiresAt: number; consumed: boolean; status: number }>;
  };
  /** P4.2c: the server's own `localDateInTz` for fixed instants. */
  localDate: { samples: Array<{ tz: string; epochMs: number; localDate: string }> };
  /** Codes the SERVER's own `totp.ts` computed for the seed recorded in `responses.offlineseed_200` (P4.2b-3b). */
  offlineCode: {
    seedFrom: string;
    stepSeconds: number;
    times: Array<{ unixSeconds: number; step: number; code: string }>;
    leadingZero: { step: number; unixSeconds: number; code: string };
  };
}
export const VECTORS = file.vectors;

export function recordedRequest<T = Record<string, unknown>>(name: string): T {
  const r = recorded(name);
  if (r.request === undefined) throw new Error(`recorded response ${name} has no request`);
  return r.request as T;
}

export function recorded(name: string): Recorded {
  const r = RECORDED[name];
  if (!r) throw new Error(`no recorded response named ${name}`);
  return r;
}

export interface SeenRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
  redirect: string;
  credentials: string;
}

export type Step = { respond: string; headers?: Record<string, string> } | { status: number; body: string; headers?: Record<string, string> } | { network: string } | { hang: true };

/** A fetch that answers `steps` in order (the last repeats), recording each request. */
export function scriptedFetch(...steps: Step[]): { fetch: HttpFetch; seen: SeenRequest[] } {
  const seen: SeenRequest[] = [];
  let i = 0;
  const fetch: HttpFetch = (url, init) => {
    const rawBody = init.body;
    seen.push({
      url,
      method: init.method,
      headers: init.headers,
      body: rawBody === undefined ? undefined : typeof rawBody === "string" ? JSON.parse(rawBody) : rawBody,
      redirect: init.redirect,
      credentials: init.credentials,
    });
    const step = steps[Math.min(i, steps.length - 1)];
    i += 1;
    if (!step) return Promise.reject(new Error("scriptedFetch: no steps"));
    if ("network" in step) return Promise.reject(new TypeError(step.network));
    if ("hang" in step) {
      return new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(new Error("aborted")));
      });
    }
    const r = "respond" in step ? recorded(step.respond) : step;
    const nullBody = r.status === 204 || r.status === 205 || r.status === 304;
    return Promise.resolve(new Response(nullBody ? null : r.body, { status: r.status, headers: { "content-type": "application/json", ...(step.headers ?? {}) } }));
  };
  return { fetch, seen };
}
