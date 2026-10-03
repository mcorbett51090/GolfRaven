/**
 * The outbox idempotency key for an evidence item, derived the way the SERVER derives `app.evidence.source_ref`
 * (`supabase/functions/_shared/evidence/source-ref.ts#deriveSourceRef`): a natural id for the sources that have one (`fix:<fixId>`,
 * `dwell:<checkinFixId>:<checkoutFixId>`), otherwise `hash:` + the SHA-256 (hex) of the canonical JSON (keys sorted recursively, no whitespace) of
 * the whole wire body. Using the same key means a local duplicate is recognised exactly when the server would recognise it.
 *
 * Cross-checked against the server's own output (`test/fixtures/edge-contract.json` `vectors.sourceRefs`, recorded from the real function).
 * Honest limit: for a date-only source the hash covers `catalogVersion` and `manifestSig` too (as the server's does), so the same play enqueued
 * under two catalog versions has two keys; that is the server's behaviour, and the local key follows it.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "../catalog/bytes";
import type { WireBody } from "./payload";

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) out[key] = canonicalize((value as Record<string, unknown>)[key]);
    return out;
  }
  return value;
}

export function canonicalBodyJson(body: WireBody): string {
  return JSON.stringify(canonicalize(body));
}

export function deriveEvidenceSourceRef(body: WireBody): string {
  const fix = body["fix"] as { fixId?: unknown } | undefined;
  if (body["source"] === "foreground_checkin" && typeof fix?.fixId === "string") return `fix:${fix.fixId}`;
  const a = body["checkinFix"] as { fixId?: unknown } | undefined;
  const b = body["checkoutFix"] as { fixId?: unknown } | undefined;
  if (body["source"] === "foreground_dwell" && typeof a?.fixId === "string" && typeof b?.fixId === "string") return `dwell:${a.fixId}:${b.fixId}`;
  return `hash:${evidenceInputHash(body)}`;
}

/** SHA-256 hex of the canonical body: the server's `input_hash` (`handler.ts#computeInputHash`). A replay is accepted only when this is unchanged. */
export function evidenceInputHash(body: WireBody): string {
  return bytesToHex(sha256(new TextEncoder().encode(canonicalBodyJson(body))));
}
