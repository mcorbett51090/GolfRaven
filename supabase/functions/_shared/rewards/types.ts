// supabase/functions/_shared/rewards/types.ts
//
// P3f: shared, dependency-free types for `rewards-activate` (build plan §7.5,
// A2-08): the narrow repository interface (`RewardsRepo`, mounted on
// `Repo#rewards` in ../types.ts), and the DI'd vendor ports (DeviceCheck /
// App Attest / Play Integrity). Pure types plus four tiny error classes —
// nothing here touches Deno, fetch, crypto or a database.

export type RewardKind = "offer_code" | "entitlement";
export type Platform = "ios" | "android";
export type Grade = "attested" | "unattestable" | "failed";
export type ActivationDecision = "activate" | "held_review";

/** The caller's own reward, row-locked (`FOR UPDATE`) for the transaction. */
export interface OwnReward {
  kind: RewardKind;
  id: string;
  /** `app.offer_code_state` or `app.entitlement_state`, verbatim. */
  state: string;
  activatedDeviceId: string | null;
  /** offer_code only; null for entitlements and for codes with no expiry. */
  expiresAt: string | null;
  /** offer_code only: the expiry clock is paused (the code is held). */
  expiryPaused: boolean;
  /** §7.5 table row 3 input, EFFECTIVE: the reward's own `rests_on_unattestable`
   * flag — unless a reviewer cleared it (`review_cleared_at` set; H2) — OR its
   * backing play's `held_review` (a review of the CODE does not clear a held
   * PLAY; the database refuses to activate over one either way). Review clears
   * ROW 3 and nothing else: row 2 is released only by the signal being cleared. */
  restsOnUnattestable: boolean;
}

export interface DeviceAttestState {
  id: string;
  platform: Platform;
  attestKeyId: string | null;
  attestCounter: number;
  /** Raw uncompressed P-256 point (65 bytes), or null: no key registered. */
  attestPublicKey: Uint8Array | null;
}

export interface ApplyActivationInput {
  kind: RewardKind;
  rewardId: string;
  deviceId: string;
  /** SHA-256 hex of the DeviceCheck token / Play Integrity token, or null. */
  tokenHash: string | null;
  decision: ActivationDecision;
  /** What the reviewer sees (§7.5): the bits read, every matched table row, the
   * primary row, DeviceCheck's last-update month. Stored on a held reward;
   * `null` when the reward is activated. Never exported, never returned. */
  holdDetail: Record<string, unknown> | null;
}

/** The Android A20 substitute's inputs (§7.5): what the server itself knows about
 * the install the activating device row is linked to. */
export interface AndroidInstallSignals {
  /** Distinct accounts whose device rows carry the same install link (or the
   * same attest key id), this account included. */
  accountsOnInstall: number;
  /** An account voided for fraud used this install. */
  voidedAccountUsedInstall: boolean;
}

/** Everything `rewards-activate` needs from the database, already scoped to
 * the actor that produced the `Repo` (no method takes a user id — types.ts's
 * own header explains why). Method names say what they read or write; none
 * opens its own connection. */
export interface RewardsRepo {
  /** §4.7.7: "App-review demo account | requests an offer, a special marker or
   * any partner route | 403". The store-review demo account earns nothing and
   * activates nothing; the handler refuses it before it reads any reward. */
  isAppReviewDemoAccount(): Promise<boolean>;
  /** `null` for an id that is not the caller's own offer_code or entitlement
   * (nonexistent and someone else's are indistinguishable — both 404). Locks
   * the row for the rest of the transaction. */
  lockOwnReward(id: string): Promise<OwnReward | null>;
  deviceAttestState(deviceId: string): Promise<DeviceAttestState | null>;
  /** Atomic, monotonic: `UPDATE ... WHERE attest_counter < $new`. `false` =
   * the counter did not advance (a replay, or a lost race). */
  advanceAttestCounter(deviceId: string, counter: number): Promise<boolean>;
  /** Records the last verdict on the device row (grade + time only — the
   * column is exported to the player, so no reasons) and the token hash. */
  recordDeviceVerdict(deviceId: string, verdict: { grade: Grade; tokenHash: string | null }): Promise<void>;
  /** Table row 2's input: the account has an OPEN `attestation_failed` signal.
   * Only the signal's own `cleared_at` releases it — never a review of a reward
   * (N3). */
  hasOpenAttestationFailedSignal(): Promise<boolean>;
  /** Advisory pre-check, NO lock taken: could an `activate` of this reward still
   * reserve its budget? (An entitlement, a code that already holds a reservation
   * and a code whose offer has no face value: yes. Otherwise: does the cap have
   * room.) The database stays authoritative — `app.activate_offer_code` HOLDS a
   * code it cannot reserve for (N1) — this only lets the handler skip the vendor
   * bit0 write for a reward that is about to be held, so bit0 is not claimed for a
   * reward the account never received. */
  canReserveBudget(rewardId: string): Promise<boolean>;
  /** Inserts `fraud_signal(attestation_failed)` unless the account already has
   * an open one. Returns whether a row was inserted. */
  raiseAttestationFailedIfNone(detail: Record<string, unknown>): Promise<boolean>;
  /** Inserts a fraud_signal of `kind` unless an OPEN one with the same
   * `onceKey` exists for the account. Returns whether a row was inserted. */
  raiseFraudSignalOnce(kind: string, detail: Record<string, unknown>, onceKey: string): Promise<boolean>;
  /** Table row 5's input: the account has RECEIVED a reward ON A DEVICE — a
   * `device_reward_ledger` row, or an offer_code in issued/redeemed, or an
   * entitlement in redeemable/vouchered/redeemed, on its own record, with an
   * `activated_device_id`. Earned, held and void rewards do not count, and
   * neither does a reward no device ever ran the table on (H2: a reviewer-cleared
   * play-hold code is not evidence the account is a repeat user). Deliberately NOT "another reward":
   * re-activating the account's own already-issued reward on a reinstalled or
   * second device is a repeat user (the reward being re-run is itself the
   * prior one), while a FIRST activation of an `earned` reward finds nothing to
   * count — it is not yet received. */
  hasPriorReward(): Promise<boolean>;
  /** Calls `app.activate_offer_code` / `app.activate_entitlement`. */
  applyActivation(input: ApplyActivationInput): Promise<{ state: string }>;
  /** Android only: remember the (hashed) install link on the activating device
   * row, first writer wins. The substitute's "write". */
  recordInstallLink(deviceId: string, installLinkHash: string): Promise<void>;
  /** Android only: the A20 substitute's two signals for the install this device
   * row is linked to, or `null` when the row has no link key at all (no install
   * link, no attest key) — then nothing can be said and the table holds. */
  androidInstallSignals(deviceId: string): Promise<AndroidInstallSignals | null>;
}

// ---------------------------------------------------------------------------
// Vendor ports
// ---------------------------------------------------------------------------

/** The two persistent bits (§7.5): bit0 = "an account that received a
 * monetary reward has used this device"; bit1 = "an account later voided for
 * fraud has used this device". */
export interface DeviceBits {
  bit0: boolean;
  bit1: boolean;
  /** DeviceCheck's last-update month (YYYY-MM), shown to the reviewer. */
  lastUpdateMonth: string | null;
}

/** The vendor said no / is not there. Three distinct classes, because they map
 * to three distinct outcomes in the handler. */
export class VendorNotConfiguredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VendorNotConfiguredError";
  }
}
/** Transient: network failure, timeout, 5xx, 429. Retrying is safe. */
export class VendorUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VendorUnavailableError";
  }
}
/** The vendor understood the request and rejected the material (a malformed or
 * invalid DeviceCheck token, an undecodable integrity token). The activating
 * device's attestation is graded `failed`. */
export class VendorRejectedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VendorRejectedError";
  }
}
export type AssertionResult =
  | { ok: true; counter: number }
  | { ok: false; grade: "failed" | "unattestable"; reason: string };

export interface AppAttestAssertionInput {
  /** Base64 (standard or url-safe) of the CBOR assertion object. */
  assertionB64: string;
  /** The App Attest key id the client claims (base64). */
  keyId: string;
  /** SHA-256(canonical_body ‖ server_challenge). */
  clientDataHash: Uint8Array;
  /** What the server has on record for this device. */
  device: DeviceAttestState;
}

export interface IosPort {
  verifyAssertion(input: AppAttestAssertionInput): Promise<AssertionResult>;
  /** DeviceCheck `query_two_bits`. */
  readBits(deviceCheckToken: string): Promise<DeviceBits>;
  /** DeviceCheck `update_two_bits` with bit0 := true. `known` is the reading
   * the table just ran on: update_two_bits writes BOTH bits, so bit1 is written
   * back unchanged and an admin's bit1 is never cleared by this call. */
  setBit0(deviceCheckToken: string, known: DeviceBits): Promise<void>;
}

export interface IntegrityInput {
  integrityToken: string;
  /** base64url(SHA-256(canonical_body ‖ challenge)), no padding. */
  expectedRequestHash: string;
  nowMs: number;
}

export type IntegrityResult = { grade: "attested" } | { grade: "failed"; reasons: string[] };

/** Android has NO vendor persistent-bit port: whether Play Integrity device
 * recall exists is spike A20 `[unverified]`, and a port that reported bits it
 * cannot also WRITE would be a read with no matching write. The two bits are
 * the server-side substitute instead (`RewardsRepo#androidInstallSignals`). */
export interface AndroidPort {
  verifyIntegrity(input: IntegrityInput): Promise<IntegrityResult>;
}

/** `null` = that platform is not configured: any request carrying that
 * platform's attestation material fails closed (503). */
export interface AttestationPorts {
  ios: IosPort | null;
  android: AndroidPort | null;
}

// ---------------------------------------------------------------------------
// App Attest key registration (`POST /v1/devices/attest-key`, follow-up F2)
// ---------------------------------------------------------------------------

/** The two database operations key registration needs, already scoped to the actor (no method takes a
 * user id). Mounted on `Repo#attestKey` (../types.ts). */
export interface AttestKeyRepo {
  /** The caller's OWN device: its platform and the key id registered on it (`null` = none). `null` for a
   * device that is not the caller's — nonexistent and someone else's are indistinguishable. */
  deviceKey(deviceId: string): Promise<{ platform: Platform; keyId: string | null } | null>;
  /** `app.register_attest_key` (0034): records the key a VERIFIED attestation attested on the caller's own
   * iOS device. `"registered"` = the device had no key; `"replaced"` = a reinstall's new key replaced the old
   * one (counter restarts at 0 for the new key; the old key is retired and the change is audited). Throws an
   * `HttpError`: 409 `key_already_registered` (the same key), 409 `key_previously_retired`, 404 (not the
   * caller's device), 422 (a malformed key — the verifier makes this unreachable). */
  register(input: { deviceId: string; keyId: string; publicKey: Uint8Array }): Promise<"registered" | "replaced">;
}
