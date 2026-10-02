// supabase/functions/_shared/signin/safe-fetch.ts
//
// THE one way the sign-in modules talk to Apple and Google. An outbound HTTP call to a third party that holds user
// credentials is a place where a mistake becomes an exfiltration or an SSRF, so every call goes through this wrapper:
//
//   * https only, no userinfo, no explicit port, and the HOSTNAME must be on an allow-list given at construction
//     (`appleid.apple.com`, `oauth2.googleapis.com`). The URL is parsed, never pattern-matched, so
//     `https://appleid.apple.com.evil.test/` and `https://evil.test/#@appleid.apple.com` are not on it.
//   * `redirect: "error"`: a redirect is never followed (it would be a way to leave the allow-list after the check) and
//     is reported as unavailable.
//   * a wall-clock timeout (AbortController) per call; the caller picks it from the request-time budget (see
//     SIGNIN_VENDOR_TIMEOUT_MS).
//   * a response SIZE CAP enforced on the stream, not on Content-Length alone; the body is never buffered past the cap.
//   * the response body is returned as text and is NEVER put in an error message: failures are short machine codes.
//
// The underlying `fetch` is injected, so unit tests drive it with a scripted fake and no network, and a test can assert
// exactly what was sent (`init.redirect`, `init.signal`, the URL).

import { VendorUnavailableError } from "./errors.ts";

export interface FetchInit {
  method: "GET" | "POST";
  headers: Record<string, string>;
  body?: string;
  signal: AbortSignal;
  redirect: "error";
}
export interface FetchLike {
  (url: string, init: FetchInit): Promise<Response>;
}

export interface SafeFetchOptions {
  fetch: FetchLike;
  /** Exact lowercase hostnames. */
  allowedHosts: readonly string[];
  timeoutMs: number;
  maxBytes: number;
}

export interface SafeResponse {
  status: number;
  contentType: string;
  text: string;
}

export interface SafeRequest {
  method: "GET" | "POST";
  headers?: Record<string, string>;
  body?: string;
}

export type SafeFetcher = (url: string, req: SafeRequest) => Promise<SafeResponse>;

/** Per-call bound for every Apple/Google call, chosen against the request budget: `http.ts` races a request at 15 s, and the
 * heaviest sign-in request makes at most four vendor calls in sequence (JWKS, token exchange, then on failure a best-effort
 * revoke) around two short database transactions. */
export const SIGNIN_VENDOR_TIMEOUT_MS = 3_000;
/** Apple's JWKS is a few KB and its token responses a few hundred bytes; 64 KiB is far above either. */
export const SIGNIN_VENDOR_MAX_BYTES = 64 * 1024;

export function createSafeFetcher(opts: SafeFetchOptions): SafeFetcher {
  const allowed = new Set(opts.allowedHosts.map((h) => h.toLowerCase()));
  return async (rawUrl, req) => {
    let url: URL;
    try {
      url = new URL(rawUrl);
    } catch {
      throw new VendorUnavailableError("bad_url");
    }
    if (url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.port !== "" || !allowed.has(url.hostname.toLowerCase())) {
      throw new VendorUnavailableError("host_not_allowed");
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs);
    try {
      let res: Response;
      try {
        res = await opts.fetch(url.toString(), {
          method: req.method,
          headers: req.headers ?? {},
          ...(req.body !== undefined ? { body: req.body } : {}),
          signal: controller.signal,
          redirect: "error",
        });
      } catch (e) {
        throw new VendorUnavailableError(controller.signal.aborted ? "timeout" : isRedirectError(e) ? "redirect" : "network");
      }
      if (res.redirected || (res.status >= 300 && res.status < 400)) {
        await res.body?.cancel().catch(() => {});
        throw new VendorUnavailableError("redirect");
      }
      const declared = Number(res.headers.get("content-length") ?? "");
      if (Number.isFinite(declared) && declared > opts.maxBytes) {
        await res.body?.cancel().catch(() => {});
        throw new VendorUnavailableError("too_large");
      }
      const chunks: Uint8Array[] = [];
      let total = 0;
      if (res.body) {
        const reader = res.body.getReader();
        try {
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            total += value.byteLength;
            if (total > opts.maxBytes) {
              await reader.cancel().catch(() => {});
              throw new VendorUnavailableError("too_large");
            }
            chunks.push(value);
          }
        } catch (e) {
          if (e instanceof VendorUnavailableError) throw e;
          throw new VendorUnavailableError(controller.signal.aborted ? "timeout" : "network");
        }
      }
      const buf = new Uint8Array(total);
      let off = 0;
      for (const c of chunks) {
        buf.set(c, off);
        off += c.byteLength;
      }
      let text: string;
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(buf);
      } catch {
        throw new VendorUnavailableError("malformed_response");
      }
      return { status: res.status, contentType: res.headers.get("content-type") ?? "", text };
    } finally {
      clearTimeout(timer);
    }
  };
}

function isRedirectError(e: unknown): boolean {
  // fetch with redirect: "error" rejects with a TypeError whose message names the redirect (the exact wording is
  // runtime-specific); anything else is a plain network failure.
  return e instanceof TypeError && /redirect/i.test(e.message);
}

/** Parses a response body as a JSON object; `null` for anything else (the caller maps that to an unavailable provider). */
export function parseJsonObject(text: string): Record<string, unknown> | null {
  try {
    const v: unknown = JSON.parse(text);
    return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}
