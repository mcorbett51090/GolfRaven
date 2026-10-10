// supabase/functions/_shared/partner/qr-print-handler.ts
//
// The `qr-print` handler: sign and register a facility's PRINTED QR (docs/security/partner-auth-design.md 6.3 "qr-print", "Course QR token format" Q2, S2b; the Edge half of migration 0055). Pure and
// unit-testable like course-qr-handler.ts: the database (`CourseQrDb`) is a PORT, this file reads no environment, opens no connection and writes no log line (PA-11).
//
// ROUTES (the function root; `GET qr-print?facilityId=` is `/qr-print`):
//   GET  ?facilityId=       the registered printed QR of a facility (class A0): kid, signature, link, when it was printed, whether it is revoked. Operator or admin.
//   POST { facilityId }     sign the printed QR with the Vault key and register it (class A3: aal 2 and a TOTP in the last 5 minutes). Operator or admin at the facility.
//
// THE POST, step by step (ONE bound transaction, so any failure rolls everything back):
//   (1) `printKey` releases the printed-QR kid and the Vault seed (and the slug) to this authorized A3 call; the facility must be one the operator has scope at (42501 otherwise);
//   (2) the Edge signs `golfraven/printed-qr/v1 NUL <facility id> NUL <qr_kid>` (Ed25519; format.ts `printedQrMessage`) and verifies the signature under the public key it derives from the seed;
//   (3) when the database already holds a public key for that kid it must be EQUAL to the derived one (a seed that is not the registered key's is a deploy fault: 503, nothing is written);
//   (4) `printWrite` ensures the PUBLIC key row (inserted when absent) and writes the facility's printed QR; a kid that is not the Vault key's, a differing public key or a revoked key is refused by the database too.
// The same inputs give the same signature (Ed25519 is deterministic), so printing again is idempotent: `changed` is false and nothing is written or audited. A new Vault key (a rotation) gives a new kid and
// REPLACES the registration: an older kid is `qr_revoked` in the player lane. The private key is never in a response, an error or a log.

import { Errors } from "../http.ts";
import { decideOrigin, preflightResponse } from "./cors.ts";
import { parseFacilityBody, parseFacilityQuery } from "./course-qr-shape.ts";
import { CourseQrKeyMismatch, signPrintedQr } from "./course-qr-signer.ts";
import { bearerHash, type Decision, mapPartnerError, matchRoute, methodRefusal, rateLimited, routeOfFunction, type RouteSpec } from "./handler-kit.ts";
import { partnerError, partnerOk, readPartnerJsonBody, runPartnerHandler, unauthenticated } from "./http.ts";
import { type CourseQrDb, PartnerNotConfigured } from "./ports.ts";

export const QR_PRINT_FUNCTION = "qr-print";

/** Printing is an operator's rare, A3-gated act; the cap only bounds a loop. */
export const PRINT_BUCKET = "course-qr:print:member";
export const PRINT_PER_MEMBER_PER_HOUR = 30;

export interface QrPrintDeps {
  readonly db: CourseQrDb;
  readonly allowedOrigin: string | null;
  /** `https://golfraven.<tld>` (privileged.ts#loadCourseQrLinkOrigin): the origin of the printed link, or null (then the response carries no link; kid and signature are the same). */
  readonly linkOrigin: string | null;
  readonly timeoutMs?: number;
}

const ROUTES: readonly RouteSpec[] = [{ name: "print", path: "", methods: ["GET", "POST"], session: true }];

/** A returned status that must not commit: thrown inside the transaction callback, answered outside it. */
class PrintRefused extends Error {
  constructor(readonly status: "no_facility") {
    super("print_refused");
    this.name = "PrintRefused";
  }
}

/** `https://golfraven.<tld>/q/f/<facility-slug>#<qr_kid>.<sig>` (the fragment, so no server or CDN log sees it), or null when no link origin is configured. */
function printedLink(origin: string | null, slug: string, qrKid: string, sig: string): string | null {
  return origin === null ? null : `${origin}/q/f/${encodeURIComponent(slug)}#${qrKid}.${sig}`;
}

export async function handleQrPrintRequest(req: Request, deps: QrPrintDeps): Promise<Response> {
  const decision = decideOrigin(req.headers, deps.allowedOrigin);
  if (decision.kind === "refused") return partnerError({ kind: "none" }, 403, "forbidden", "origin not allowed");
  if (req.method === "OPTIONS") return preflightResponse(decision);

  return await runPartnerHandler(
    decision,
    async () => {
      try {
        const matched = matchRoute(ROUTES, routeOfFunction(req.url, QR_PRINT_FUNCTION));
        if (matched === null) return partnerError(decision, 404, "not_found", "not found");
        const refusal = methodRefusal(decision, matched, req.method);
        if (refusal !== null) return refusal;
        const tokenHash = await bearerHash(req.headers);
        if (tokenHash === null) return unauthenticated(decision);
        return req.method === "POST" ? await handlePrint(req, deps, decision, tokenHash) : await handleRead(req, deps, decision, tokenHash);
      } catch (err) {
        if (err instanceof CourseQrKeyMismatch) return mapPartnerError(decision, new PartnerNotConfigured());
        return mapPartnerError(decision, err);
      }
    },
    deps.timeoutMs,
  );
}

async function handleRead(req: Request, deps: QrPrintDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseFacilityQuery(new URL(req.url));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const r = await deps.db.withCourseQr(tokenHash, (s) => s.printRead(parsed.value.facilityId));
  if (r.status === "no_facility") return partnerError(decision, 404, "not_found", "not found");
  if (r.status === "not_printed") return partnerError(decision, 404, "not_printed", "no printed QR is registered for this facility");
  return partnerOk(decision, 200, { facilityId: parsed.value.facilityId, qrKid: r.qrKid, sig: r.sig, printedAt: r.printedAt, revoked: r.revokedAt !== null, revokedAt: r.revokedAt });
}

async function handlePrint(req: Request, deps: QrPrintDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseFacilityBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const { facilityId } = parsed.value;
  const limit = await deps.db.hitRateLimit(tokenHash, PRINT_BUCKET, 3600, PRINT_PER_MEMBER_PER_HOUR);
  if (!limit.ok) return rateLimited(decision, "too many print requests", limit.retryAfterSeconds);

  let out: { readonly qrKid: string; readonly sig: string; readonly slug: string; readonly changed: boolean };
  try {
    out = await deps.db.withCourseQr(tokenHash, async (s) => {
      const k = await s.printKey(facilityId);
      if (k.status === "no_facility") throw new PrintRefused(k.status);
      // a revoked Vault key is a deploy fault (the operator must provision a new key): a bare 503, nothing written
      if (k.status !== "ok") throw new PartnerNotConfigured();
      const { sig, publicKey } = await signPrintedQr({ facilityId, qrKid: k.kid, seed: k.signingKey });
      if (k.publicKey !== null && k.publicKey !== publicKey) throw new CourseQrKeyMismatch();
      const w = await s.printWrite(facilityId, k.kid, sig, publicKey);
      if (w.status === "no_facility") throw new PrintRefused(w.status);
      if (w.status !== "ok") throw new PartnerNotConfigured();
      return { qrKid: k.kid, sig, slug: k.slug, changed: w.changed };
    });
  } catch (err) {
    if (err instanceof PrintRefused) return partnerError(decision, 404, "not_found", "not found");
    throw err;
  }
  return partnerOk(decision, out.changed ? 201 : 200, {
    facilityId,
    qrKid: out.qrKid,
    sig: out.sig,
    link: printedLink(deps.linkOrigin, out.slug, out.qrKid, out.sig),
    changed: out.changed,
  });
}
