/**
 * Build-time feature switches (constants, not environment: a release build must not change behaviour because of a variable).
 *
 * `CHECKIN_UI_ENABLED`: whether any screen can start a check-in and so consume a prefetched challenge. It is `false` in P4.2b-1, which ships the
 * challenge plumbing (store, manager, outbox redemption) but no check-in screen; with it false the app does not prefetch at startup or after a sync
 * (`src/challenges/prefetch-gate.ts`), because unused challenges expire after 24 h and count against the hourly limit. P4.2b-2/3 (the check-in
 * screens and native attestation) flip it to `true` in the same change that adds the screen.
 */
export const CHECKIN_UI_ENABLED = false;
