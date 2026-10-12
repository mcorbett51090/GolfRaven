// supabase/functions/_shared/partner/stock-shape.ts
//
// Strict, hand-rolled validation of the CLIENT-SUBMITTED wire shapes of `stock-admin` (docs/security/partner-auth-design.md 12, 28; slice S5, the Edge half of migration 0058), in the style of attest-shape.ts:
// unknown keys REJECTED, every value checked for its exact shape before any port is touched. Pure: no environment, no database, no logging.
//
//   GET  stock         ?facilityId=
//   POST stock/move    { facilityId, trailId, kind, qty, note? }   kind: delivered | transfer_in | transfer_out | count_adjustment | damaged
//                      qty is a non-zero whole number of at most 100000 in magnitude; positive unless kind is count_adjustment (a signed delta)
//
// The database re-checks every bound (it is the authority); this is the first refusal, so a malformed move never opens a transaction.

import { parseFacilityId, parseReadQuery } from "./attest-shape.ts";
import { STOCK_MOVE_KINDS, type StockMoveKind } from "./ports.ts";
import { type ParseIssue, type ParseResult, plain, unknownKeys } from "./session-shape.ts";

export const STOCK_MAX_QTY = 100000;
export const STOCK_NOTE_MAX = 200;

export function parseStockQuery(url: string): ParseResult<{ readonly facilityId: string }> {
  const q = parseReadQuery(url, new Set(["facilityId"]));
  if (!q.ok) return q;
  const facilityId = parseFacilityId(q.value.get("facilityId"));
  if (facilityId === null) return { ok: false, issues: [{ path: "facilityId", message: "must be a facility id" }] };
  return { ok: true, value: { facilityId } };
}

export interface StockMoveBody {
  readonly facilityId: string;
  readonly trailId: string;
  readonly kind: StockMoveKind;
  readonly qty: number;
  readonly note: string | null;
}

export function parseStockMoveBody(raw: unknown): ParseResult<StockMoveBody> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["facilityId", "trailId", "kind", "qty", "note"]), "", issues);
  const facilityId = parseFacilityId(raw.facilityId);
  // a trail id has the catalog id alphabet of a facility id
  const trailId = parseFacilityId(raw.trailId);
  const kind = typeof raw.kind === "string" && (STOCK_MOVE_KINDS as readonly string[]).includes(raw.kind) ? (raw.kind as StockMoveKind) : null;
  const qty = typeof raw.qty === "number" && Number.isSafeInteger(raw.qty) && raw.qty !== 0 && Math.abs(raw.qty) <= STOCK_MAX_QTY ? raw.qty : null;
  let note: string | null = null;
  let noteOk = true;
  if (raw.note !== undefined && raw.note !== null) {
    if (typeof raw.note === "string" && raw.note.length <= STOCK_NOTE_MAX) note = raw.note;
    else noteOk = false;
  }
  if (facilityId === null) issues.push({ path: "facilityId", message: "must be a facility id" });
  if (trailId === null) issues.push({ path: "trailId", message: "must be a trail id" });
  if (kind === null) issues.push({ path: "kind", message: "must be delivered, transfer_in, transfer_out, count_adjustment or damaged" });
  if (qty === null) issues.push({ path: "qty", message: `must be a non-zero whole number of at most ${STOCK_MAX_QTY}` });
  else if (kind !== null && kind !== "count_adjustment" && qty < 0) issues.push({ path: "qty", message: "must be positive unless kind is count_adjustment" });
  if (!noteOk) issues.push({ path: "note", message: `must be text of at most ${STOCK_NOTE_MAX} characters` });
  if (issues.length > 0 || facilityId === null || trailId === null || kind === null || qty === null) return { ok: false, issues };
  return { ok: true, value: { facilityId, trailId, kind, qty, note } };
}
