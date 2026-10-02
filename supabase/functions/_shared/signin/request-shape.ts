// supabase/functions/_shared/signin/request-shape.ts
//
// Strict, hand-rolled validation of the CLIENT-SUBMITTED wire shape of `POST /v1/me/signin-methods` (the same style as
// evidence/request-shape.ts and rewards/request-shape.ts: no schema library, unknown keys rejected).
//
//   { "action": "link",   "provider": "apple", "identityToken": "<jwt>", "authorizationCode": "<code>", "nonce": "<raw nonce>",
//                         "emailProof"?: { "code": "<6-10 digit OTP>" } }
//   { "action": "unlink", "provider": "email" | "apple" | "google" }
//   (unlinking "email" removes the identity row only; it is NOT a claim that email sign-in stops working: see 0035 and O12 F2)
//
// There is NO field that names an account. Every operation is on the authenticated caller's own account, derived from the
// verified JWT; a body carrying `userId` / `user_id` / `uid` / `email` of someone else is not "ignored", it is REJECTED (400),
// because a field that is silently ignored today is one refactor away from being trusted.
// (`emailProof` carries a code only: the target address is the one in the verified Apple token, never client-supplied.)

export interface ParseIssue {
  path: string;
  message: string;
}
export type ParseResult<T> = { ok: true; value: T } | { ok: false; issues: ParseIssue[] };

export interface LinkRequest {
  action: "link";
  provider: "apple" | "google";
  identityToken: string;
  authorizationCode: string;
  nonce: string;
  emailProof?: { code: string };
}
export interface UnlinkRequest {
  action: "unlink";
  provider: "email" | "apple" | "google";
}
export type SigninRequest = LinkRequest | UnlinkRequest;

const MAX_TOKEN = 8 * 1024;
const MAX_CODE = 2048;
const NONCE_RE = /^[A-Za-z0-9._~+/=-]{16,256}$/;
const OTP_RE = /^[0-9]{6,10}$/;
const JWT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

function plain(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function parseSigninBody(raw: unknown): ParseResult<SigninRequest> {
  const issues: ParseIssue[] = [];
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };

  const action = raw.action;
  const known = action === "link" ? new Set(["action", "provider", "identityToken", "authorizationCode", "nonce", "emailProof"]) : new Set(["action", "provider"]);
  for (const k of Object.keys(raw)) if (!known.has(k)) issues.push({ path: k, message: "unknown field" });

  if (action !== "link" && action !== "unlink") {
    issues.push({ path: "action", message: 'must be "link" or "unlink"' });
    return { ok: false, issues };
  }

  const provider = raw.provider;
  if (action === "unlink") {
    if (provider !== "email" && provider !== "apple" && provider !== "google") issues.push({ path: "provider", message: 'must be "email", "apple" or "google"' });
    return issues.length > 0 ? { ok: false, issues } : { ok: true, value: { action, provider: provider as UnlinkRequest["provider"] } };
  }

  if (provider !== "apple" && provider !== "google") issues.push({ path: "provider", message: 'must be "apple" or "google"' });
  const token = raw.identityToken;
  if (typeof token !== "string" || token.length > MAX_TOKEN || !JWT_RE.test(token)) issues.push({ path: "identityToken", message: "must be a compact JWT" });
  const code = raw.authorizationCode;
  if (typeof code !== "string" || code.length === 0 || code.length > MAX_CODE || /\s/.test(code)) issues.push({ path: "authorizationCode", message: "must be a non-empty string" });
  const nonce = raw.nonce;
  if (typeof nonce !== "string" || !NONCE_RE.test(nonce)) issues.push({ path: "nonce", message: "must be the 16-256 character raw nonce the client generated" });

  let emailProof: { code: string } | undefined;
  if (raw.emailProof !== undefined) {
    const p = raw.emailProof;
    if (!plain(p)) issues.push({ path: "emailProof", message: "must be an object" });
    else {
      for (const k of Object.keys(p)) if (k !== "code") issues.push({ path: `emailProof.${k}`, message: "unknown field" });
      if (typeof p.code !== "string" || !OTP_RE.test(p.code)) issues.push({ path: "emailProof.code", message: "must be a 6-10 digit code" });
      else emailProof = { code: p.code };
    }
  }

  if (issues.length > 0) return { ok: false, issues };
  return {
    ok: true,
    value: {
      action: "link",
      provider: provider as "apple" | "google",
      identityToken: token as string,
      authorizationCode: code as string,
      nonce: nonce as string,
      ...(emailProof ? { emailProof } : {}),
    },
  };
}
