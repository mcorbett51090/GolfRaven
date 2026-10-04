// supabase/functions/_shared/course-qr/params.ts
//
// P5.1a S2a: the parameters of the course QR's PLAYER lane (build plan §4.6(q), §9.2 "Proving a marker purchase (O5)", §4.7.8 rate limits). ONE place, imported by the token
// format, the request shape, the handler, the entrypoint and the tests, so the numbers the mobile client and the S2b staff lane must implement cannot drift between them.

/** A rotating token is accepted when the FIX's time is within this many seconds of the token's issue time (plan §4.6(q): "within 120 s of a rotating token's issue time"; AT(19): "a token
 * more than 120 s from the fix time gives 422 qr_expired"). The database enforces it too (private.marker_scan_for_actor); the token's `exp` claim is `iat + this`. */
export const ROTATING_TOKEN_WINDOW_SECONDS = 120;

/** "It becomes `valid` only if a qualifying fix arrives within 7 days" (plan §4.6(q)). The database bounds a fix's time to this, and the pending row's deadline is this long from the scan. */
export const COSIGNAL_MAX_AGE_MS = 7 * 24 * 3_600_000;
/** A fix may not be dated further in the future than this (clock skew). Mirrors the database's own bound. */
export const COSIGNAL_MAX_FUTURE_MS = 5 * 60_000;

/** Devices per account (the evidence endpoint's own cap, so a scan cannot be used to mint device rows past it). */
export const MAX_DEVICES_PER_USER = 20;

/** POST /v1/marker-scan: "20 scans/user/day" (plan §4.7.8). Every request counts, replay or refusal included, and the hit is made BEFORE the request transaction opens
 * (privileged.ts#hitRateLimitForActor: a hit from inside a transaction deadlocks the pool). The wrong-PIN caps (5 per user per facility per facility-local date, 30 per
 * facility) are NOT here: they live in the database (private.course_pin_attempt_for_actor), because a failure has to count even when the request is refused. */
export const MARKER_SCAN_BUCKET = "marker-scan:user";
export const MARKER_SCAN_WINDOW_SECONDS = 86_400;
export const MARKER_SCAN_PER_USER_DAY = 20;

/** The two QR variants (plan §9.2): Q1 the rotating token, Q2 the printed facility QR plus today's PIN. */
export type QrVariant = "rotating" | "static_pin";
