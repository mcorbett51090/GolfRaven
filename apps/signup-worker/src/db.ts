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
}

export async function findByEmailLc(db: D1Like, emailLc: string): Promise<SignupRow | null> {
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

/** Inserts a brand-new pending row (case A: no existing row for this email). */
export async function createPendingSignup(db: D1Like, p: NewSignupParams): Promise<void> {
  await db
    .prepare(
      `INSERT INTO signups
        (id, email_lc, consent_version, age_confirmed, source, created_at,
         confirmed_at, unsubscribed_at, confirm_token_hash, confirm_expires_at, unsubscribe_token_hash)
       VALUES (?1, ?2, ?3, 1, ?4, ?5, NULL, NULL, ?6, ?7, ?8)`,
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
export async function rotateConfirmToken(db: D1Like, p: RotateTokenParams): Promise<void> {
  await db
    .prepare(
      `UPDATE signups
         SET consent_version = ?2, source = ?3, confirm_token_hash = ?4, confirm_expires_at = ?5
       WHERE id = ?1`,
    )
    .bind(p.id, p.consentVersion, p.source, p.confirmTokenHash, p.confirmExpiresAt)
    .run();
}

export async function findByConfirmTokenHash(db: D1Like, hash: string): Promise<SignupRow | null> {
  const row = await db
    .prepare("SELECT * FROM signups WHERE confirm_token_hash = ?1")
    .bind(hash)
    .first<SignupRow>();
  return row ?? null;
}

/**
 * Records a confirmation and (re-)opens the subscription. Safe to call
 * more than once with the same row (index.ts's handler is naturally
 * idempotent within the token's expiry window, see its comment):
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
 */
export async function recordConfirmation(db: D1Like, id: string, confirmedAt: string): Promise<void> {
  await db
    .prepare(
      `UPDATE signups
         SET confirmed_at = COALESCE(confirmed_at, ?2),
             unsubscribed_at = NULL
       WHERE id = ?1`,
    )
    .bind(id, confirmedAt)
    .run();
}

export async function findByUnsubscribeTokenHash(db: D1Like, hash: string): Promise<SignupRow | null> {
  const row = await db
    .prepare("SELECT * FROM signups WHERE unsubscribe_token_hash = ?1")
    .bind(hash)
    .first<SignupRow>();
  return row ?? null;
}

export async function markUnsubscribed(db: D1Like, id: string, unsubscribedAt: string): Promise<void> {
  await db
    .prepare("UPDATE signups SET unsubscribed_at = ?2 WHERE id = ?1")
    .bind(id, unsubscribedAt)
    .run();
}
