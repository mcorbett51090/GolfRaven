/**
 * Build-time feature switches (constants, not environment: a release build must not change behaviour because of a variable).
 *
 * `CHECKIN_UI_ENABLED`: whether any screen can start a check-in and so consume a prefetched challenge. It is `false` in P4.2b-1, which ships the
 * challenge plumbing (store, manager, outbox redemption) but no check-in screen; with it false the app does not prefetch at startup or after a sync
 * (`src/challenges/prefetch-gate.ts`), because unused challenges expire after 24 h and count against the hourly limit. P4.2b-2/3 (the check-in
 * screens and native attestation) flip it to `true` in the same change that adds the screen.
 *
 * P4.2c adds the screen (`src/screens/CheckInCard.tsx`, shown on the course page only while this is true, and the flow itself, `src/checkin/flow.ts`, refuses to run while it is false) and
 * STILL leaves this `false`: what remains before it can flip is a real-device field test, the permission copy reviewed, and the store privacy declarations for location
 * (README, "Before flipping the flags"). While it is false nothing in a release build asks for location, requests a challenge or builds evidence.
 */
export const CHECKIN_UI_ENABLED = false;

/**
 * `OFFLINE_CODE_UI_ENABLED` (P4.2b-3b): whether the app shows the player's offline staff code (Me → "Offline code": the handle, the 6-digit code, a countdown, "reset code") and, with it,
 * provisions the seed (`offline-code/gate.ts`). It is `false`: the staff side that ACCEPTS the code is P5 (the portal's verification endpoint), so a release build ships nothing
 * user-visible and reveals no seed until that exists. The client (`src/offline-code/`: provisioning, the secure-store seed, the TOTP, the manager) is built and tested; this switch is the
 * only thing between it and a player. Flip it to `true` in the same change that makes the code useful.
 */
export const OFFLINE_CODE_UI_ENABLED = false;

/**
 * `WALLET_ACTIVATION_UI_ENABLED` (P4.2b-3b): whether the Wallet shows earned rewards with an "Activate" action (`POST rewards-activate`). It is `false` because the rest of the path is not
 * there: no server endpoint LISTS a player's earned rewards (`listEarnedRewards` answers `[]` without a request), nothing earns one yet outside tests (P5), and the Wallet tab itself is a
 * placeholder. The activation client (`src/attest/activator.ts`, `src/rewards/`) is built and tested against the real handlers' recorded answers; this switch keeps the card out of a release
 * build until a reward can exist. Flip it in the change that adds the listing endpoint.
 */
export const WALLET_ACTIVATION_UI_ENABLED = false;

/**
 * `MARKER_COSIGNAL_UI_ENABLED` (P4.2c): whether the facility page shows "Buying a marker" (build plan §7.6 "Offline marker purchase", G2-03), which captures a foreground fix against a
 * prefetched challenge and keeps it LOCALLY (`src/marker/`). It is `false`, and it needs `CHECKIN_UI_ENABLED` as well (the button consumes a prefetched challenge, which only exist
 * while prefetch is on). The reason it is its own switch: NO server path accepts a marker-purchase co-signal yet (no `marker-scan` function, no evidence kind for it, `staff_presence` is
 * refused by `POST evidence`), so flipping the check-in switch alone must not put a button in front of a player that spends a challenge on a record nothing can send.
 * Flip it in the change that adds the server endpoint and the sender (README, "Before flipping the flags").
 */
export const MARKER_COSIGNAL_UI_ENABLED = false;
