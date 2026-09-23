/**
 * D1 access layer for the `signups` table (migrations/0001_create_signups.sql).
 *
 * Every write goes through a prepared statement with bound parameters —
 * never string-interpolated SQL. No IP address or user agent is ever
 * written here (task requirement / privacy notice: those never touch D1).
 */

import type { D1Like } from "./config";

export interface SignupRow {
  id: string;
  email_lc: string;
  consent_version: string;
  age_confirmed: number; // 1 (SQLite has no native boolean)
  source: string | null;
  created_at: string;
  confirmed_at: string | null;
  unsubscribed_at: string | null;
  confirm_token_hash: string | null;
  confirm_expires_at: string | null;
  unsubscribe_token_hash: string;
  /** Gate finding F-S7 / migrations/0002_unsubscribe_prev_hash.sql: the
   * row's PRIOR `unsubscribe_token_hash`, preserved here once a resend
   * detects the pepper rotated, so every unsubscribe link ever emailed
   * keeps matching even after `Env.TOKEN_PEPPER_PREVIOUS` is later unset —
   * see `rotateUnsubscribeTokenHashForPepperRotation` in index.ts. NULL
   * until the first resend after a rotation. */
  unsubscribe_token_hash_prev: string | null;
}

export async function findByEmailLc(
  db: D1Like,
  emailLc: string,
): Promise<SignupRow | null> {
  const row = await db
    .prepare("SELECT * FROM signups WHERE email_lc = ?1")
    .bind(emailLc)
    .first<SignupRow>();
  return row ?? null;
}

export interface NewSignupParams {
  id: string;
  emailLc: string;
  consentVersion: string;
  source: string | null;
  createdAt: string;
  confirmTokenHash: string;
  confirmExpiresAt: string;
  unsubscribeTokenHash: string;
}

function extractChanges(result: unknown): number {
  const meta = (result as { meta?: { changes?: number } } | undefined)?.meta;
  // Real D1 always reports meta.changes; if a caller's D1Like doesn't, we
  // can't tell — assume the write happened rather than silently no-op'ing
  // downstream logic that gates on this.
  return typeof meta?.changes === "number" ? meta.changes : 1;
}

/**
 * Inserts a brand-new pending row (case A: no existing row for this
 * email). Gate finding F3: `ON CONFLICT(email_lc) DO NOTHING` makes this
 * race-safe against a concurrent signup for the same address — instead of
 * a `UNIQUE constraint failed` 500, the loser simply inserts nothing.
 * Returns `inserted: false` in that case so the caller can re-read the row
 * and fall through to the rotate-and-resend path instead.
 */
export async function createPendingSignup(
  db: D1Like,
  p: NewSignupParams,
): Promise<{ inserted: boolean }> {
  const result = await db
    .prepare(
      `INSERT INTO signups
        (id, email_lc, consent_version, age_confirmed, source, created_at,
         confirmed_at, unsubscribed_at, confirm_token_hash, confirm_expires_at, unsubscribe_token_hash)
       VALUES (?1, ?2, ?3, 1, ?4, ?5, NULL, NULL, ?6, ?7, ?8)
       ON CONFLICT(email_lc) DO NOTHING`,
    )
    .bind(
      p.id,
      p.emailLc,
      p.consentVersion,
      p.source,
      p.createdAt,
      p.confirmTokenHash,
      p.confirmExpiresAt,
      p.unsubscribeTokenHash,
    )
    .run();
  return { inserted: extractChanges(result) !== 0 };
}

export interface RotateTokenParams {
  id: string;
  consentVersion: string;
  source: string | null;
  confirmTokenHash: string;
  confirmExpiresAt: string;
}

/**
 * Re-signup of an existing, not-yet-confirmed OR previously-unsubscribed
 * row (cases C and D): mints a fresh confirm token and refreshes the
 * consent record to the latest submission, WITHOUT touching
 * `confirmed_at`/`unsubscribed_at` — those only change when the new token
 * is actually confirmed (index.ts handleConfirmSubmit).
 */
export async function rotateConfirmToken(
  db: D1Like,
  p: RotateTokenParams,
): Promise<void> {
  await db
    .prepare(
      `UPDATE signups
         SET consent_version = ?2, source = ?3, confirm_token_hash = ?4, confirm_expires_at = ?5
       WHERE id = ?1`,
    )
    .bind(
      p.id,
      p.consentVersion,
      p.source,
      p.confirmTokenHash,
      p.confirmExpiresAt,
    )
    .run();
}

export async function findByConfirmTokenHash(
  db: D1Like,
  hash: string,
): Promise<SignupRow | null> {
  const row = await db
    .prepare("SELECT * FROM signups WHERE confirm_token_hash = ?1")
    .bind(hash)
    .first<SignupRow>();
  return row ?? null;
}

/**
 * Records a confirmation and (re-)opens the subscription.
 *
 *   - `confirmed_at` is set via COALESCE — it's written ONCE, the first
 *     time this address is ever confirmed, and never overwritten again.
 *     This is load-bearing for K2 (decision 0001 Addendum D R3 /
 *     src/k2-count.ts): the count reads confirmedAt as a permanent
 *     historical fact, so a later re-confirmation (case D: re-signup of a
 *     previously-unsubscribed address) must NOT move that timestamp.
 *   - `unsubscribed_at` is unconditionally cleared, which is exactly the
 *     "re-open" — first confirmation or the Nth, this is what makes the
 *     address deliverable again.
 *   - Gate finding F4: `confirm_token_hash`/`confirm_expires_at` are
 *     cleared here too, so the link is single-use. A second POST with the
 *     same raw token then finds no row by hash (findByConfirmTokenHash
 *     returns null) and index.ts shows the generic "invalid or already
 *     used" page instead of silently re-confirming — this is what closes
 *     the "confirm, unsubscribe, then replay the old link" re-subscribe
 *     hole the old (idempotent-forever) behavior allowed.
 */
export async function recordConfirmation(
  db: D1Like,
  id: string,
  confirmedAt: string,
): Promise<void> {
  await db
    .prepare(
      `UPDATE signups
         SET confirmed_at = COALESCE(confirmed_at, ?2),
             unsubscribed_at = NULL,
             confirm_token_hash = NULL,
             confirm_expires_at = NULL
       WHERE id = ?1`,
    )
    .bind(id, confirmedAt)
    .run();
}

/**
 * Gate finding F-S7: matches the incoming token's hash against EITHER
 * `unsubscribe_token_hash` OR `unsubscribe_token_hash_prev` (both indexed —
 * migrations/0002_unsubscribe_prev_hash.sql) — a row that has been through
 * one pepper-rotation-triggered resend has its OLD hash preserved in the
 * `_prev` column, so an older still-in-a-mailbox email's link keeps
 * matching without needing `Env.TOKEN_PEPPER_PREVIOUS` to still be set.
 */
export async function findByUnsubscribeTokenHash(
  db: D1Like,
  hash: string,
): Promise<SignupRow | null> {
  const row = await db
    .prepare(
      "SELECT * FROM signups WHERE unsubscribe_token_hash = ?1 OR unsubscribe_token_hash_prev = ?1",
    )
    .bind(hash)
    .first<SignupRow>();
  return row ?? null;
}

export interface RotateUnsubscribeTokenHashParams {
  id: string;
  unsubscribeTokenHash: string;
  unsubscribeTokenHashPrev: string;
}

/**
 * Gate finding F-S7: called on a resend when the row's stored
 * `unsubscribe_token_hash` is found to have been derived under
 * `Env.TOKEN_PEPPER_PREVIOUS` (a pepper rotation happened since this row
 * was last written) — moves that prior hash into `unsubscribe_token_hash_prev`
 * (permanently, so it survives `TOKEN_PEPPER_PREVIOUS` later being unset)
 * and stores the current-pepper derivation in `unsubscribe_token_hash`.
 */
export async function rotateUnsubscribeTokenHashForPepperRotation(
  db: D1Like,
  p: RotateUnsubscribeTokenHashParams,
): Promise<void> {
  await db
    .prepare(
      `UPDATE signups
         SET unsubscribe_token_hash = ?2, unsubscribe_token_hash_prev = ?3
       WHERE id = ?1`,
    )
    .bind(p.id, p.unsubscribeTokenHash, p.unsubscribeTokenHashPrev)
    .run();
}

export async function markUnsubscribed(
  db: D1Like,
  id: string,
  unsubscribedAt: string,
): Promise<void> {
  await db
    .prepare("UPDATE signups SET unsubscribed_at = ?2 WHERE id = ?1")
    .bind(id, unsubscribedAt)
    .run();
}

/**
 * Retention cron (gate finding F11, N8): deletes rows that were NEVER
 * confirmed, are older than `createdBeforeIso`, AND whose confirm token is
 * either absent or already expired as of `nowIso`. Unconfirmed rows never
 * count toward K2 (src/k2-count.ts only ever reads rows with a non-null
 * `confirmed_at`), so this deletion can never change a K2 count — see also
 * README.md "Data retention".
 *
 * N8: `created_at` alone isn't enough — a re-signup near the 30-day mark
 * rotates in a fresh, still-valid confirm token (48h TTL) without moving
 * `created_at`, so a `created_at`-only cutoff could delete a row out from
 * under a link someone can still legitimately click.
 */
export async function deleteStaleUnconfirmed(
  db: D1Like,
  createdBeforeIso: string,
  nowIso: string,
): Promise<number> {
  const result = await db
    .prepare(
      `DELETE FROM signups
        WHERE confirmed_at IS NULL
          AND created_at < ?1
          AND (confirm_expires_at IS NULL OR confirm_expires_at < ?2)`,
    )
    .bind(createdBeforeIso, nowIso)
    .run();
  return extractChanges(result);
}

/**
 * Retention cron (gate finding F11): deletes rows that unsubscribed more
 * than `UNSUBSCRIBED_RETENTION_DAYS` ago — but ONLY once the K2 verdict is
 * safely recorded (see index.ts's scheduled handler, which passes this
 * function a cutoff only after `Env.K2_GATE_CLOSES_AT` has passed; it
 * never calls this at all while that var is unset).
 */
export async function deleteStaleUnsubscribed(
  db: D1Like,
  unsubscribedBeforeIso: string,
): Promise<number> {
  const result = await db
    .prepare(
      "DELETE FROM signups WHERE unsubscribed_at IS NOT NULL AND unsubscribed_at < ?1",
    )
    .bind(unsubscribedBeforeIso)
    .run();
  return extractChanges(result);
}
