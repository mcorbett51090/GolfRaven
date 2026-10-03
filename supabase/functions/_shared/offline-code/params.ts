// supabase/functions/_shared/offline-code/params.ts
//
// P4.2b-3a: the parameters of the offline staff code (build plan §7.6 "Offline staff path (G-P1-07)"). ONE place, imported by the provisioning
// handler, the verification core and the tests, so the numbers the mobile client must implement can never drift between them.
//
// THE CODE: a 6-digit TOTP (RFC 6238) with a 10-MINUTE step, computed on the device from a 32-byte per-(account, device) seed the server provisioned
// while the device was online. HMAC-SHA-256 (not RFC 6238's default SHA-1): both ends are ours, the seed is already a 32-byte HMAC-SHA-256 output
// (so it is exactly the RFC's SHA-256 key length), and there is no reason to carry SHA-1 into a new design. The algorithm is PINNED here and echoed
// in the provisioning response (`algorithm`), so a client that was built against another value fails loudly instead of computing wrong codes.

/** RFC 6238 time step, in seconds. Build plan §7.6: "10-minute step". */
export const OFFLINE_CODE_STEP_SECONDS = 600;

/** Digits in the code shown to the staff member. */
export const OFFLINE_CODE_DIGITS = 6;

/** The HMAC the TOTP uses. Pinned; see the header. */
export const OFFLINE_CODE_ALGORITHM = "SHA256" as const;

/** A code is accepted when its step is within this many steps of the server's current step (build plan §7.6: "± 1 step"). */
export const OFFLINE_CODE_WINDOW_STEPS = 1;

/** The seed is 32 bytes: HMAC-SHA-256's output length, and RFC 6238's key length for HMAC-SHA-256. */
export const OFFLINE_SEED_BYTES = 32;

/** The database refuses to record a used step further than this from its own clock. It is deliberately WIDER than `OFFLINE_CODE_WINDOW_STEPS`: the
 * TypeScript core is the authority on what is acceptable; the database bound only stops a caller burning steps far from now, and must never refuse
 * a step the core accepted because the two clocks sat either side of a step boundary. */
export const OFFLINE_CODE_DB_WINDOW_STEPS = 2;

// ----------------------------------------------------------------------------------------------------------------------------------------------------
// Rate-limit buckets. Every name is a KEY SUFFIX: `private.hit_actor_rate_limit` builds `<actor uid>:<key>` in the database, so each limit is per
// actor, and the `<uid>:%` purge in delete_my_data removes the account's counters with the account.
// ----------------------------------------------------------------------------------------------------------------------------------------------------

/** POST /v1/me/offline-seed: every call (a seed reveal). `[inference]` no plan-stated number: a device re-provisions on a reinstall or a lost secure
 * store, not in a loop; 20 an hour covers retries and a handful of devices while bounding a stolen session's harvesting. */
export const OFFLINE_SEED_REVEAL_BUCKET = "me-offline-seed:user";
export const OFFLINE_SEED_REVEAL_PER_HOUR = 20;

/** POST /v1/me/offline-seed with `rotate: true`, additionally. Rotation invalidates every code the device could still produce, so it is limited
 * much harder than a plain reveal. `[inference]`. */
export const OFFLINE_SEED_ROTATE_BUCKET = "me-offline-seed-rotate:user";
export const OFFLINE_SEED_ROTATE_PER_HOUR = 5;

/** THE STAFF-SIDE LIMIT, P5's to enforce (the staff verification endpoint is not in this stage): build plan §7.6, critic SP13, "5 failures per staff
 * per hour". The bucket is keyed on the STAFF member (the bound actor of the verification request), never on the player, so guessing codes for many
 * players from one staff account hits one counter. P5 must count a FAILED verification (malformed, mismatch, replayed), reserve the attempt BEFORE it
 * verifies and give it back on success (the shape of private.reserve_signin_otp_attempt / release_signin_otp_attempt, 0035 section 3k):
 * `hit_actor_rate_limit` has no release, so it cannot express "5 failures" without also counting the successes. See
 * docs/security/p3-money-path-requirements.md, "Offline TOTP seed provisioning". */
export const OFFLINE_CODE_STAFF_FAILURE_BUCKET = "offline-code-fail:staff";
export const OFFLINE_CODE_STAFF_FAILURE_WINDOW_SECONDS = 3_600;
export const OFFLINE_CODE_STAFF_MAX_FAILURES = 5;
