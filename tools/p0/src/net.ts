/**
 * Shared outbound-fetch helpers for `x2-fetch`, `x4-verify` and `p0-desk`:
 *
 * - A generic ASCII User-Agent builder. `x5-overpass.ts`'s `buildUserAgent`
 *   (gate finding F-S5: a header value above 0xFF is not a valid ByteString
 *   and `fetch` throws on it with no indication of which header/character
 *   caused it) is now a thin wrapper over `buildAsciiUserAgent` here, so the
 *   fix is reused verbatim by every tool that sends a User-Agent, not
 *   re-copied per tool.
 *
 * - Network-policy-block detection, so a proxy denial is reported as
 *   "BLOCKED — network policy (<host>)" instead of a generic fetch
 *   failure. This session's own agent proxy (`/root/.ccr/README.md`)
 *   resolves a blocked host's `fetch()` call to a normal HTTP `403`
 *   `Response`, with an `x-deny-reason: host_not_allowed` header and a
 *   "Host not in allowlist: <host>" body `[verified this session,
 *   2026-09-23 — see task report]`. Some other proxy/fetch configurations
 *   instead REJECT the call outright with a "CONNECT tunnel failed" /
 *   "Proxy response (403) !== 200 when HTTP Tunneling"-shaped error
 *   (observed with `NODE_USE_ENV_PROXY=1` set before process start, same
 *   session). Both shapes are detected here so every caller gets one
 *   `FetchOutcome` to branch on instead of re-deriving this per call site.
 */

const LATIN1_MAX_CODE_POINT = 0xff;

/** Gate finding S6: the default response-size cap, enforced WHILE
 * STREAMING (never after buffering the whole body), so a hostile or
 * misconfigured server can't exhaust memory before the cap is checked. */
export const DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024; // 10 MB

export class ResponseTooLargeError extends Error {}

/** Gate finding F-S5 (x5-overpass.ts), generalized: a header value above
 * 0xFF is not a valid ByteString and `fetch`/`Headers` throws on it with no
 * indication of which header or character caused it — fail with a clear,
 * pointed message naming the offending env var and index instead. */
export function assertAsciiContact(contact: string, envVarName: string): void {
  for (let i = 0; i < contact.length; i += 1) {
    if (contact.charCodeAt(i) > LATIN1_MAX_CODE_POINT) {
      throw new Error(
        `${envVarName} must be Latin-1 (ByteString) text for the User-Agent header — found a non-Latin-1 ` +
          `character at index ${i}. Use plain ASCII (e.g. "-" instead of an em dash).`,
      );
    }
  }
}

export interface AsciiUserAgentOptions {
  /** e.g. "GolfRaven-P0-X2/0.1" */
  toolTag: string;
  /** e.g. "docs/p0/X2.md" */
  docRef: string;
  /** e.g. "X2_CONTACT" */
  envVarName: string;
  defaultContact?: string;
}

/** Polite, ASCII-only User-Agent per each check's outbound-fetch usage
 * norms `[unverified — training knowledge on the exact expected format;
 * the practice of identifying the client and a contact is well documented
 * across API usage policies]`. The contact is read from an env var (never
 * hard-coded personal contact info committed to the repo — x5-overpass.ts
 * gate finding B-10) and defaults to a generic project URL when unset. */
export function buildAsciiUserAgent(opts: AsciiUserAgentOptions): string {
  const fallback =
    opts.defaultContact ??
    `https://github.com/golfraven/golfraven (contact not set - export ${opts.envVarName})`;
  const contact = process.env[opts.envVarName]?.trim() || fallback;
  assertAsciiContact(contact, opts.envVarName);
  return `${opts.toolTag} (P0 desk check, ${opts.docRef}; contact: ${contact})`;
}

export function hostFromUrl(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

const BLOCKED_RESPONSE_HEADER = "x-deny-reason";
const BLOCKED_BODY_RE =
  /not in allowlist|network egress|host[_ ]not[_ ]allowed|blocked by (network|egress) policy/i;

/** True when a resolved (not thrown) HTTP response IS the proxy's own
 * denial page, not the destination site's own 403. Distinguishing the two
 * matters: a site's own 403 is real evidence about that site, a proxy
 * denial is evidence about this environment's network policy only. */
export function isPolicyBlockedResponse(
  status: number,
  headers: Headers,
  bodyTextSample: string,
): boolean {
  // Gate finding N2: a policy denial can resolve as HTTP 407 (proxy
  // authentication required), not only 403 — `/root/.ccr/README.md`.
  if (status !== 403 && status !== 407) return false;
  if (headers.has(BLOCKED_RESPONSE_HEADER)) return true;
  return BLOCKED_BODY_RE.test(bodyTextSample);
}

const BLOCKED_ERROR_RE =
  /(connect|tunnel|proxy)[\s\S]*?\b40[37]\b|\b40[37]\b[\s\S]*?(connect|tunnel|proxy)|forbidden[\s\S]*?(proxy|tunnel)/i;

/** Walks an Error's `.cause` chain (fetch/undici nest the real reason
 * several levels deep — see module doc) collecting every message, so the
 * blocked-signature check sees the whole chain, not just the outermost
 * generic "fetch failed". Bounded depth + a `seen` set guards against a
 * cyclical `.cause` (pathological, but cheap to guard). */
function collectErrorMessages(
  err: unknown,
  depth = 0,
  seen: Set<unknown> = new Set(),
): string[] {
  if (err === null || err === undefined || depth > 5 || seen.has(err)) {
    return [];
  }
  seen.add(err);
  if (err instanceof Error) {
    const rest =
      err.cause === undefined
        ? []
        : collectErrorMessages(err.cause, depth + 1, seen);
    return [err.message, ...rest];
  }
  return [String(err)];
}

export interface ClassifiedRejection {
  blocked: boolean;
  detail: string;
}

/** Classifies a THROWN/rejected `fetch` error as a network-policy block or
 * not, by matching a 403+connect/tunnel/proxy/forbidden signature anywhere
 * in the `.cause` chain (see module doc's two observed shapes). A network
 * error with no such signature (DNS failure, timeout, connection reset) is
 * NOT classified as a policy block — it is a genuine, different failure
 * mode and reported as a plain error instead. */
export function classifyFetchRejection(err: unknown): ClassifiedRejection {
  const messages = collectErrorMessages(err);
  const detail = messages.join(" <- caused by: ") || String(err);
  const blocked = messages.some((m) => BLOCKED_ERROR_RE.test(m));
  return { blocked, detail };
}

export type FetchOutcome =
  | { kind: "ok"; response: Response }
  | { kind: "blocked"; host: string; detail: string }
  | { kind: "error"; host: string; detail: string };

/**
 * Wraps `fetch` with network-policy-block detection (both shapes — see
 * module doc) so callers get one `FetchOutcome` to branch on. Never throws
 * itself for a network-shaped failure; a caller that wants "any non-ok
 * response" to be an error too still checks `response.ok` on the `"ok"`
 * branch, same as a plain `fetch` call would.
 */
export async function fetchWithBlockDetection(
  url: string,
  init: RequestInit,
): Promise<FetchOutcome> {
  const host = hostFromUrl(url);
  let response: Response;
  try {
    response = await fetch(url, init);
  } catch (err) {
    const { blocked, detail } = classifyFetchRejection(err);
    return blocked
      ? { kind: "blocked", host, detail }
      : { kind: "error", host, detail };
  }
  if (response.status === 403 || response.status === 407) {
    const sample = await response
      .clone()
      .text()
      .catch(() => "");
    if (isPolicyBlockedResponse(response.status, response.headers, sample)) {
      return {
        kind: "blocked",
        host,
        detail: `HTTP ${response.status} (${sample.slice(0, 200) || "no body"})`,
      };
    }
  }
  return { kind: "ok", response };
}

/**
 * Reads a `Response` body into a single `Buffer`, enforcing BOTH a byte cap
 * (checked WHILE STREAMING, gate S6) and `opts.signal` for the ENTIRE read —
 * not just the initial `fetch()` — via an explicit race against the
 * signal's `abort` event, so a server that sends headers and then stalls the
 * body is still bounded by the caller's timeout. Previously callers cleared
 * their abort timer as soon as `fetch()` resolved (i.e. once headers
 * arrived), leaving the body read with no timeout and no size cap at all.
 */
export async function readBodyCapped(
  response: Response,
  opts: { signal: AbortSignal; maxBytes?: number },
): Promise<Buffer> {
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  const abortRejection = new Promise<never>((_, reject) => {
    const onAbort = (): void => reject(new Error("response body read aborted (timeout)"));
    if (opts.signal.aborted) {
      onAbort();
      return;
    }
    opts.signal.addEventListener("abort", onAbort, { once: true });
  });

  const readAll = async (): Promise<Buffer> => {
    const body = response.body;
    if (!body) {
      const buf = Buffer.from(await response.arrayBuffer());
      if (buf.byteLength > maxBytes) {
        throw new ResponseTooLargeError(`response body exceeds ${maxBytes} bytes`);
      }
      return buf;
    }
    const reader = body.getReader();
    const chunks: Buffer[] = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          total += value.byteLength;
          if (total > maxBytes) {
            throw new ResponseTooLargeError(
              `response body exceeds ${maxBytes} bytes (stopped mid-stream)`,
            );
          }
          chunks.push(Buffer.from(value));
        }
      }
    } finally {
      reader.releaseLock();
    }
    return Buffer.concat(chunks);
  };

  return Promise.race([readAll(), abortRejection]);
}
