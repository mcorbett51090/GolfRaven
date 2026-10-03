/**
 * Historic imports (a first Health sync, a file batch) go through `POST /v1/evidence/batch` (build plan §7.6, §4.7.8), SORTED BY EVENT TIME, so that
 * onboarding a heavy golfer neither trips the live 60/h cap nor floods the velocity check (FM-28).
 *
 * Limits come from the server, not from taste: at most 100 items per request (`MAX_BATCH_ITEMS_PER_REQUEST`, `batch-handler.ts`) and a 64 KiB request
 * body (`MAX_BODY_BYTES`, `_shared/http.ts`, enforced by `readJsonBody`; the batch answer even repeats it as `maxBodyBytes`). The planner splits on
 * BOTH, with a margin under the byte cap so a body is never refused for a few bytes. Items are sorted before they are split, so every request holds
 * a contiguous stretch of the history and the requests go oldest first.
 *
 * Only `origin: "import"` items with a date-only source are batched (`payload.ts`): a fix-bearing play needs its check-in challenge redeemed first
 * and goes one at a time. Everything else (live plays, items whose body cannot be built) stays on the single-item path.
 */
import type { OutboxItem } from "../outbox";
import { buildEvidenceBody, eventTimeMs, parseEvidencePayload, type WireBody } from "./payload";

/** `MAX_BATCH_ITEMS_PER_REQUEST` of the server's `batch-handler.ts`. */
export const BATCH_MAX_ITEMS = 100;
/** The server's `MAX_BODY_BYTES` (64 KiB). */
export const SERVER_MAX_BODY_BYTES = 64 * 1024;
/** What a batch request body may weigh: the cap minus a 2 KiB margin. */
export const BATCH_MAX_BYTES = SERVER_MAX_BODY_BYTES - 2 * 1024;

export interface BatchEntry {
  item: OutboxItem;
  body: WireBody;
  eventTime: number;
}

export interface BatchPlan {
  /** Requests to make, in order; each is non-empty, at most `BATCH_MAX_ITEMS` items and `BATCH_MAX_BYTES` bytes of body. */
  batches: BatchEntry[][];
  /** Items whose single body alone exceeds the byte cap: never batchable (cannot happen with the date-only shapes; kept so nothing is dropped). */
  oversized: BatchEntry[];
}

const enc = new TextEncoder();
/** Bytes of `{"items":[` + `]}`. */
const ENVELOPE_BYTES = enc.encode('{"items":[]}').length;

export function batchRequestBytes(bodies: readonly WireBody[]): number {
  return enc.encode(JSON.stringify({ items: bodies })).length;
}

/** The items of `items` that go through the batch endpoint, with their bodies. Order is the input order. */
export function selectBatchEntries(items: readonly OutboxItem[]): BatchEntry[] {
  const out: BatchEntry[] = [];
  for (const item of items) {
    const parsed = parseEvidencePayload(item.payload);
    if (!parsed.ok || parsed.payload.origin !== "import") continue;
    const built = buildEvidenceBody(item, parsed.payload);
    if (!built.ok) continue;
    out.push({ item, body: built.body, eventTime: eventTimeMs(parsed.payload) });
  }
  return out;
}

/** Sort by event time (ties: `sourceRef`, then id, so the order is total and stable) and split on count and bytes. */
export function planBatches(entries: readonly BatchEntry[]): BatchPlan {
  const sorted = [...entries].sort((a, b) => a.eventTime - b.eventTime || (a.item.sourceRef < b.item.sourceRef ? -1 : a.item.sourceRef > b.item.sourceRef ? 1 : a.item.id < b.item.id ? -1 : a.item.id > b.item.id ? 1 : 0));
  const batches: BatchEntry[][] = [];
  const oversized: BatchEntry[] = [];
  let current: BatchEntry[] = [];
  let bytes = ENVELOPE_BYTES;
  for (const e of sorted) {
    const size = enc.encode(JSON.stringify(e.body)).length;
    if (ENVELOPE_BYTES + size > BATCH_MAX_BYTES) {
      oversized.push(e);
      continue;
    }
    const added = size + (current.length > 0 ? 1 : 0); // the comma
    if (current.length >= BATCH_MAX_ITEMS || bytes + added > BATCH_MAX_BYTES) {
      batches.push(current);
      current = [];
      bytes = ENVELOPE_BYTES;
    }
    bytes += size + (current.length > 0 ? 1 : 0);
    current.push(e);
  }
  if (current.length > 0) batches.push(current);
  return { batches, oversized };
}
