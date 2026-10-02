// supabase/functions/_shared/catalog/ledger-artifact.ts
//
// Hand-rolled parsing of the `id-ledger.json` shard (build plan line 823:
// "the full ledger, so evidence is validated against every ID ever
// minted, not the last import"; `packages/catalog/src/ledger.ts`'s own
// `IdLedgerSchema`/`LedgerEntrySchema` — "read as a whole... by the
// `import-catalog` Edge Function"). Same "cannot import that package"
// reasoning as manifest-artifact.ts's own header — this is a
// deliberately NARROWER re-validation of the same shape (every field the
// importer actually reads), not a byte-for-byte port of the zod schema.
//
// Scope (see 0023_catalog_import.sql's own header): this module maps the
// artifact's `LedgerEntry` shape onto exactly what `app.catalog_id_ledger`
// (0002_catalog_tables.sql) can hold — id, kind, status, tombstoned,
// mergedInto, and the first/latest `catalogVersion` a `minted`/`verified`
// transition names. It does NOT carry `slug`/`seedRefs`/`splitFrom`
// through to the DB (no DB column for the first two; `split_from` is left
// NULL — the DB column exists but the artifact's own `LedgerEntry` has no
// matching field to populate it from, since a `split` transition's
// `siblingIds` lives on the KEPT id, not a back-reference on the new
// sibling — reconciling that is part of the full §4.2 promotion-table
// mechanics this round's "ledger import" (not "full promotion pipeline")
// deliberately defers, same as 0002's own TODO).

const ID_RE = /^(trl|fac|crs|hol|dsg|oft|ach)_[0-9A-HJKMNP-TV-Z]{26}$/;
// ⛔ FIX (P3e round 2 gate, M6): "the P1 schema (packages/catalog/src/
// ledger.ts:53) is the source of truth, and it allows any string. Conform
// the importer to it; don't tighten P1." `LedgerTransitionSchema`'s own
// `catalogVersion` field is `z.string().min(1)` — no yyyymmdd-gitsha7
// shape requirement at all (unlike the TOP-LEVEL manifest/versions.json
// `catalogVersion`, which IS always that shape — a genuinely different,
// stricter field this module used to conflate this one with).

/** `packages/catalog/src/ids.ts#ID_KINDS`'s short codes -> the full-word
 * `app.catalog_id_ledger.kind` string every existing reader
 * (evidence/handler.ts's own `facilityLedger.kind !== "facility"` /
 * `ledgerRow.kind !== "course"` checks, supabase/tests/helpers.sql's own
 * fixture rows) already expects. */
export const KIND_BY_PREFIX: Record<string, string> = {
  trl: "trail",
  fac: "facility",
  crs: "course",
  hol: "hole",
  dsg: "designer",
  oft: "offer_terms",
  ach: "achievement",
};

export type LedgerTransitionType = "minted" | "verified" | "split" | "merged" | "closed";

export interface LedgerTransition {
  type: LedgerTransitionType;
  catalogVersion: string;
  /** Only meaningful on a `split` transition: the sibling ids minted alongside the kept id. */
  siblingIds: string[];
}

export interface LedgerEntry {
  id: string;
  kind: string; // DB-shaped ("facility" | "course" | ...), already mapped from the artifact's short code
  status: "stub" | "verified" | null; // null for a kind (designer/hole/...) the artifact schema marks status-less
  tombstoned: boolean;
  mergedInto: string | null;
  transitions: LedgerTransition[];
  /** Every sibling id any `split` transition of THIS (kept) entry names. */
  splitSiblings: string[];
}

export interface ParsedLedger {
  entries: LedgerEntry[];
}

export type ParseResult<T> = { ok: true; value: T } | { ok: false; issue: string };

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const TRANSITION_TYPES = new Set<LedgerTransitionType>(["minted", "verified", "split", "merged", "closed"]);

export function parseIdLedger(raw: unknown): ParseResult<ParsedLedger> {
  if (!isPlainObject(raw) || !isPlainObject(raw.entries)) {
    return { ok: false, issue: "id-ledger.json: expected {entries: {[id]: LedgerEntry}}" };
  }
  const entries: LedgerEntry[] = [];
  for (const [key, v] of Object.entries(raw.entries)) {
    if (!isPlainObject(v)) return { ok: false, issue: `id-ledger.json.entries.${key}: not an object` };
    const id = v.id;
    if (typeof id !== "string" || !ID_RE.test(id)) {
      return { ok: false, issue: `id-ledger.json.entries.${key}: id must match ^(trl|fac|crs|hol|dsg|oft|ach)_<ULID>$` };
    }
    if (id !== key) {
      return { ok: false, issue: `id-ledger.json.entries.${key}: entry's own id "${id}" does not match its map key` };
    }
    const prefix = id.slice(0, id.indexOf("_"));
    const kind = KIND_BY_PREFIX[prefix];
    if (!kind) return { ok: false, issue: `id-ledger.json.entries.${key}: unrecognized id prefix "${prefix}"` };

    let status: "stub" | "verified" | null = null;
    if (v.status !== undefined) {
      if (v.status !== "stub" && v.status !== "verified") {
        return { ok: false, issue: `id-ledger.json.entries.${key}: status must be "stub" or "verified" when present` };
      }
      status = v.status;
    }

    const tombstoned = v.tombstoned === true;
    let mergedInto: string | null = null;
    if (v.mergedInto !== undefined) {
      if (typeof v.mergedInto !== "string" || !ID_RE.test(v.mergedInto)) {
        return { ok: false, issue: `id-ledger.json.entries.${key}: mergedInto must be a valid id when present` };
      }
      mergedInto = v.mergedInto;
    }
    if (mergedInto !== null && !tombstoned) {
      return { ok: false, issue: `id-ledger.json.entries.${key}: mergedInto is set but tombstoned is not true` };
    }
    if (mergedInto === id) {
      return { ok: false, issue: `id-ledger.json.entries.${key}: mergedInto cannot equal the entry's own id` };
    }

    if (!Array.isArray(v.transitions)) {
      return { ok: false, issue: `id-ledger.json.entries.${key}: transitions must be an array` };
    }
    const transitions: LedgerTransition[] = [];
    for (let i = 0; i < v.transitions.length; i++) {
      const t = v.transitions[i];
      if (!isPlainObject(t) || typeof t.type !== "string" || !TRANSITION_TYPES.has(t.type as LedgerTransitionType)) {
        return { ok: false, issue: `id-ledger.json.entries.${key}.transitions[${i}]: type must be one of minted|verified|split|merged|closed` };
      }
      if (typeof t.catalogVersion !== "string" || t.catalogVersion.length === 0) {
        return { ok: false, issue: `id-ledger.json.entries.${key}.transitions[${i}]: catalogVersion must be a non-empty string` };
      }
      const siblingIds: string[] = [];
      if (t.siblingIds !== undefined) {
        if (!Array.isArray(t.siblingIds)) return { ok: false, issue: `id-ledger.json.entries.${key}.transitions[${i}]: siblingIds must be an array` };
        for (const sid of t.siblingIds) {
          if (typeof sid !== "string" || !ID_RE.test(sid)) return { ok: false, issue: `id-ledger.json.entries.${key}.transitions[${i}]: siblingIds must be valid ids` };
          siblingIds.push(sid);
        }
      }
      transitions.push({ type: t.type as LedgerTransitionType, catalogVersion: t.catalogVersion, siblingIds });
    }
    if (transitions.length === 0) {
      return { ok: false, issue: `id-ledger.json.entries.${key}: transitions must be non-empty (every id is at least "minted")` };
    }

    const splitSiblings = [...new Set(transitions.filter((t) => t.type === "split").flatMap((t) => t.siblingIds))].filter((sid) => sid !== id);
    entries.push({ id, kind, status, tombstoned, mergedInto, transitions, splitSiblings });
  }
  return { ok: true, value: { entries } };
}

/** The `catalogVersion` of this entry's EARLIEST `minted` transition —
 * `app.catalog_id_ledger.first_catalog_version` is NOT NULL, so every
 * entry must have one (enforced by `parseIdLedger`'s own "transitions
 * must be non-empty" check above; this picks the minimum by
 * `compareFn`, not merely transitions[0], since the artifact's own
 * ordering within transitions[] is not itself asserted anywhere). */
export function firstMintedVersion(entry: LedgerEntry, compareFn: (a: string, b: string) => number): string {
  const minted = entry.transitions.filter((t) => t.type === "minted");
  const pool = minted.length > 0 ? minted : entry.transitions;
  return pool.reduce((min, t) => (compareFn(t.catalogVersion, min) < 0 ? t.catalogVersion : min), pool[0]!.catalogVersion);
}

/** The `catalogVersion` of this entry's LATEST `verified` transition, or
 * null if it has none (status !== 'verified', or a malformed artifact
 * that never recorded one despite the status — treated as "unknown", not
 * fabricated). */
export function latestVerifiedVersion(entry: LedgerEntry, compareFn: (a: string, b: string) => number): string | null {
  const verified = entry.transitions.filter((t) => t.type === "verified");
  if (verified.length === 0) return null;
  return verified.reduce((max, t) => (compareFn(t.catalogVersion, max) > 0 ? t.catalogVersion : max), verified[0]!.catalogVersion);
}
