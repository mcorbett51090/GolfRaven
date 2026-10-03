/**
 * The parameters of the offline staff code (build plan §7.6 "Offline staff path (G-P1-07)"), as the SERVER pins them
 * (`supabase/functions/_shared/offline-code/params.ts`; a test imports that file and compares). The provisioning answer echoes `stepSeconds`, `digits` and `algorithm`
 * and `schemas.ts` refuses an answer that disagrees with these, so a client built against another value fails loudly instead of showing a code the server never accepts.
 */

/** RFC 6238 time step, in seconds ("10-minute step"). */
export const OFFLINE_CODE_STEP_SECONDS = 600;

/** Digits shown to the staff member. Leading zeros are significant. */
export const OFFLINE_CODE_DIGITS = 6;

/** HMAC-SHA-256 (RFC 6238's SHA-256 mode), not the RFC's default SHA-1. */
export const OFFLINE_CODE_ALGORITHM = "SHA256" as const;

/** The seed is 32 bytes: HMAC-SHA-256's output length and RFC 6238's key length for SHA-256. */
export const OFFLINE_SEED_BYTES = 32;

/** The server accepts a code whose step is within this many steps of ITS OWN current step (+-1 step, build plan §7.6). It is here for the documentation of the clock-skew rule below and for
 * the tests; nothing on the device enforces it (the device cannot know the server's step while offline). */
export const OFFLINE_CODE_ACCEPTED_STEP_WINDOW = 1;

/**
 * The device clock offset (server minus device, estimated at provisioning from `issuedAt`) from which the screen warns. It is DISPLAY ONLY: the code is always computed from the
 * device's own clock, exactly as the server's spec says, and the offset never changes a digit.
 *
 * Why this threshold: the server accepts the step before and the step after its own. If the device clock is off by LESS than one step (600 s) in either direction, the device's
 * step differs from the server's by at most one, so the code is ALWAYS accepted. At one step or more it MAY be refused (it depends on where in the step each clock sits; a
 * skew of 10 to 30 minutes works only part of the time), so that is where the player is told to fix the clock.
 */
export const CLOCK_SKEW_WARN_MS = OFFLINE_CODE_STEP_SECONDS * 1000;

/** After an automatic provisioning attempt that could not finish (device not registered yet, server unavailable, offline, rate limited) no further AUTOMATIC attempt is made for this
 * long. A manual attempt (the player taps) is never held back by it. It exists so a build that cannot provision yet does not loop: the server limits reveals to 20 an hour. */
export const AUTO_PROVISION_COOLDOWN_MS = 5 * 60_000;
