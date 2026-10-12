// supabase/functions/_shared/partner/settlement-shape.ts
//
// Strict validation of the `settlement-export` body (docs/security/partner-auth-design.md 12, 32; P5.1b). Pure.
//
//   POST export { trailId, month }
//     month is YYYY-MM-01 (or any date in the month; the database truncates to the first of month)

import { parseTrailId } from "./programme-shape.ts";
import { type ParseIssue, type ParseResult, plain, unknownKeys } from "./session-shape.ts";

const MONTH_RE = /^\d{4}-\d{2}-\d{2}$/;

export interface SettlementExportBody {
  readonly trailId: string;
  /** ISO date (YYYY-MM-DD); the database truncates to the month. */
  readonly month: string;
}

export function parseSettlementExportBody(raw: unknown): ParseResult<SettlementExportBody> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["trailId", "month"]), "", issues);
  const trailId = parseTrailId(raw.trailId);
  if (trailId === null) issues.push({ path: "trailId", message: "must be a trail id" });
  const month = typeof raw.month === "string" && MONTH_RE.test(raw.month) ? raw.month : null;
  if (month === null) issues.push({ path: "month", message: "must be a date YYYY-MM-DD" });
  if (issues.length > 0 || trailId === null || month === null) return { ok: false, issues };
  return { ok: true, value: { trailId, month } };
}
