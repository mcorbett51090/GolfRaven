// supabase/functions/_shared/evidence/source-ref.ts
//
// Server-side derivation of `app.evidence.source_ref` — the NOT NULL,
// per-(user_id, source) idempotency key 0003_player_core.sql's own
// comment requires: "a client-supplied id where one exists..., otherwise
// a server-side content hash of the normalized payload — before insert;
// the constraint is the backstop that makes skipping that step a hard
// failure, not a silent gap." AT 3: "a replayed evidence payload yields
// one row and one play" — this is what makes a replay converge on the
// SAME source_ref (and therefore the SAME row via `insertEvidenceIdempotent`'s
// `ON CONFLICT (user_id, source, source_ref) DO NOTHING`).
//
// Pure: `digestHex` is injected (Web Crypto's `crypto.subtle.digest`,
// available unmodified in Deno and in this repo's Node/vitest run — no
// import needed either way) so this module has zero dependencies and is
// trivially unit-testable.

import type { EvidenceSubmission } from "./request-shape.ts";

export type DigestFn = (algorithm: "SHA-256", data: BufferSource) => Promise<ArrayBuffer>;

function toHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** A natural, client-controlled but server-meaningful id for sources that
 * carry one — using it (rather than a payload hash) means two DIFFERENT
 * payload shapes describing the same real-world event (e.g. a retried
 * upload with a slightly different accuracyMeters reading) still
 * collapse to one row, which a raw content hash would NOT do. Returns
 * null when the source has no such natural id, in which case the caller
 * falls back to a canonical content hash instead. */
function naturalRef(submission: EvidenceSubmission): string | null {
  switch (submission.source) {
    case "foreground_checkin":
      return `fix:${submission.fix.fixId}`;
    case "foreground_dwell":
      return `dwell:${submission.checkinFix.fixId}:${submission.checkoutFix.fixId}`;
    // staff_presence / booking / receipt_green_fee are rejected at parse
    // time (request-shape.ts's REJECTED_SOURCES) — they never reach this
    // function, since only player-submittable sources exist in
    // EvidenceSubmission's type at all.
    default:
      return null;
  }
}

/** Canonical JSON: sorted keys, recursively — so the SAME logical payload
 * always hashes to the SAME bytes regardless of client key ordering. */
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = canonicalize((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

export async function deriveSourceRef(submission: EvidenceSubmission, digestHex: DigestFn = crypto.subtle.digest.bind(crypto.subtle)): Promise<string> {
  const natural = naturalRef(submission);
  if (natural !== null) return natural;
  const canonical = JSON.stringify(canonicalize(submission));
  const bytes = new TextEncoder().encode(canonical);
  const digest = await digestHex("SHA-256", bytes.slice());
  return `hash:${toHex(digest)}`;
}
