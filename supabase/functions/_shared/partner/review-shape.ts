// supabase/functions/_shared/partner/review-shape.ts
//
// Strict, hand-rolled validation of the CLIENT-SUBMITTED wire shapes of `partner-review` (docs/security/partner-auth-design.md 27; slice S4, the Edge half of migration 0057), in the style of
// attest-shape.ts / members-shape.ts. Pure: no environment, no database, no clock.

export type ShapeOk<T> = { readonly ok: true; readonly value: T };
export type ShapeFail = { readonly ok: false; readonly issues: readonly string[] };
export type ShapeResult<T> = ShapeOk<T> | ShapeFail;

function fail(issues: readonly string[]): ShapeFail {
  return { ok: false, issues };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** POST resolve/offer-code and POST resolve/entitlement: `{ id, approve }` and nothing else. */
export function parseResolveBody(body: unknown): ShapeResult<{ readonly id: string; readonly approve: boolean }> {
  if (!isPlainObject(body)) return fail(["body must be a JSON object"]);
  const keys = Object.keys(body);
  if (keys.length !== 2 || !("id" in body) || !("approve" in body)) return fail(["body must be exactly { id, approve }"]);
  if (typeof body.id !== "string" || !UUID_RE.test(body.id)) return fail(["id must be a uuid"]);
  if (typeof body.approve !== "boolean") return fail(["approve must be a boolean"]);
  return { ok: true, value: { id: body.id.toLowerCase(), approve: body.approve } };
}

/** GET preview/receipt-cross-user: query may hold `id` (uuid) once and nothing else. */
export function parsePreviewQuery(url: string): ShapeResult<{ readonly id: string }> {
  const params = new URL(url).searchParams;
  const issues: string[] = [];
  for (const k of new Set(params.keys())) {
    if (k !== "id") issues.push(`unknown query parameter: ${k}`);
    else if (params.getAll(k).length > 1) issues.push("id must appear once");
  }
  const raw = params.get("id");
  if (raw === null || raw === "") issues.push("id is required");
  else if (!UUID_RE.test(raw)) issues.push("id must be a uuid");
  if (issues.length > 0 || raw === null || !UUID_RE.test(raw)) return fail(issues.length > 0 ? issues : ["id must be a uuid"]);
  return { ok: true, value: { id: raw.toLowerCase() } };
}
