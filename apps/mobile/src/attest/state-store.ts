/**
 * What this install remembers about its own attestation, in the secure store (Keychain `AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY` / Android Keystore-backed;
 * `secure/expo-secure-store.ts`), PER USER AND PER DEVICE ID:
 *
 *  - iOS: the App Attest key id (`registered`, after the server accepted it at `devices-attest-key`), or `pending` (a registration was started and its outcome is
 *    not known: it may or may not have been applied). The server binds a key to the device row of ONE account (`app.register_attest_key`: "no such device FOR THIS
 *    USER"), so the record is per (user, device): another account on the same install never reuses it, and never sees it.
 *  - Android: whether this (user, device) ever got a token graded `attested`. The server remembers the same fact (`hasAttestedOnDevice`) and from then on grades a
 *    request that carries no token `failed` plus a fraud signal, whatever it claims; the client keeps its own copy so it never sends one (`redeemer.ts`).
 *
 * `stale` (stale App Attest key recovery) is a `registered` key the server said is not the one it holds (`checkin-token`'s `rekey: true`): it is never asserted with again, it is never
 * reused (recovery generates a FRESH key), and like `pending` it means "the server may hold a key for this device", so no token-less request while it stands. It is kept until a
 * replacement registration succeeds, and a persisted per-(user, device) recovery cooldown caps how often one is attempted (`getRekeyCooldownUntil`).
 * `pending`, `stale` and `registered` all mean "the server may already know this device can attest", so a token-less request is never sent while any of them exists.
 * A record that cannot be read back (corrupt JSON, a wrong shape) is reported as `pending`, never as absent: forgetting a registered key is the unsafe direction.
 * A store that cannot be read or written throws; the caller treats that as "cannot attest now" (a retry), never as "has never attested".
 */
import type { SecureStore } from "../secure";

export type IosKeyRecord = { state: "pending" } | { state: "registered"; keyId: string } | { state: "stale"; keyId: string };

const KEY_ID_RE = /^[A-Za-z0-9+/]{43}=$/;
const PART_RE = /^[A-Za-z0-9-]{1,64}$/;

function part(name: string, v: string): string {
  if (!PART_RE.test(v)) throw new Error(`attest state: ${name} is not a safe key part`);
  return v;
}

const unattestedKey = (userId: string, deviceId: string): string => `gr.attest.ios_unattested.${part("userId", userId)}.${part("deviceId", deviceId.toLowerCase())}`;
const backoffKey = (userId: string, deviceId: string): string => `gr.attest.ios_reg_backoff.${part("userId", userId)}.${part("deviceId", deviceId.toLowerCase())}`;
const rekeyCooldownKey = (userId: string, deviceId: string): string => `gr.attest.ios_rekey_cooldown.${part("userId", userId)}.${part("deviceId", deviceId.toLowerCase())}`;
const iosKey = (userId: string, deviceId: string): string => `gr.attest.ios_key.${part("userId", userId)}.${part("deviceId", deviceId.toLowerCase())}`;
const androidKey = (userId: string, deviceId: string): string => `gr.attest.android_attested.${part("userId", userId)}.${part("deviceId", deviceId.toLowerCase())}`;

export class AttestStateStore {
  constructor(private readonly secure: SecureStore) {}

  async getIosKey(userId: string, deviceId: string): Promise<IosKeyRecord | null> {
    const k = iosKey(userId, deviceId);
    const raw = await this.secure.get(k);
    if (raw === null) return null;
    try {
      const v = JSON.parse(raw) as { v?: unknown; state?: unknown; keyId?: unknown };
      if (v.v === 1 && v.state === "registered" && typeof v.keyId === "string" && KEY_ID_RE.test(v.keyId)) return { state: "registered", keyId: v.keyId };
      if (v.v === 1 && v.state === "stale" && typeof v.keyId === "string" && KEY_ID_RE.test(v.keyId)) return { state: "stale", keyId: v.keyId };
      if (v.v === 1 && v.state === "pending") return { state: "pending" };
    } catch {
      // fall through: unreadable
    }
    return { state: "pending" };
  }

  async setIosKey(userId: string, deviceId: string, rec: IosKeyRecord): Promise<void> {
    await this.secure.set(iosKey(userId, deviceId), JSON.stringify(rec.state === "pending" ? { v: 1, state: "pending" } : { v: 1, state: rec.state, keyId: rec.keyId }));
  }

  async clearIosKey(userId: string, deviceId: string): Promise<void> {
    await this.secure.delete(iosKey(userId, deviceId));
  }

  /** A key `generateKey` made that `attestKey` has NOT yet attested (Apple's service was unavailable): it is kept and the SAME key retried at the next registration, rather
   * than generating a new one (Apple: retry `attestKey` with the same key after a `serverUnavailable`). `null` when there is none. */
  async getUnattestedKey(userId: string, deviceId: string): Promise<string | null> {
    const v = await this.secure.get(unattestedKey(userId, deviceId));
    return v !== null && KEY_ID_RE.test(v) ? v : null;
  }

  async setUnattestedKey(userId: string, deviceId: string, keyId: string): Promise<void> {
    await this.secure.set(unattestedKey(userId, deviceId), keyId);
  }

  async clearUnattestedKey(userId: string, deviceId: string): Promise<void> {
    await this.secure.delete(unattestedKey(userId, deviceId));
  }

  /** Until when (epoch ms) a key registration must not be attempted again: set when the server answered that it cannot hold a key (503 `attestation_not_configured`, or a refusal
   * of the key itself) so that every outbox retry does not spend a live challenge and an Apple `attestKey`. Persisted, per user and device. `0` = no backoff. */
  async getRegistrationBackoffUntil(userId: string, deviceId: string): Promise<number> {
    const n = Number(await this.secure.get(backoffKey(userId, deviceId)));
    return Number.isFinite(n) && n > 0 ? n : 0;
  }

  async setRegistrationBackoffUntil(userId: string, deviceId: string, untilMs: number): Promise<void> {
    await this.secure.set(backoffKey(userId, deviceId), String(Math.trunc(untilMs)));
  }

  async clearRegistrationBackoff(userId: string, deviceId: string): Promise<void> {
    await this.secure.delete(backoffKey(userId, deviceId));
  }

  /** Until when (epoch ms) another stale-key RECOVERY (a fresh key registered at `devices-attest-key`) must not be attempted: set right before a recovery's registration request is sent,
   * whatever its outcome, so a `rekey: true` that comes back inside the cooldown (or a recovery whose answer was a 429, a refusal or a lost response) cannot loop. Persisted, per user and device. `0` = none. */
  async getRekeyCooldownUntil(userId: string, deviceId: string): Promise<number> {
    const n = Number(await this.secure.get(rekeyCooldownKey(userId, deviceId)));
    return Number.isFinite(n) && n > 0 ? n : 0;
  }

  async setRekeyCooldownUntil(userId: string, deviceId: string, untilMs: number): Promise<void> {
    await this.secure.set(rekeyCooldownKey(userId, deviceId), String(Math.trunc(untilMs)));
  }

  async hasAttestedAndroid(userId: string, deviceId: string): Promise<boolean> {
    return (await this.secure.get(androidKey(userId, deviceId))) === "1";
  }

  async markAttestedAndroid(userId: string, deviceId: string): Promise<void> {
    await this.secure.set(androidKey(userId, deviceId), "1");
  }

  /** Account deletion removes the deleted user's records for this device (the other user's, and the device id itself, stay). */
  async wipeUser(userId: string, deviceId: string): Promise<void> {
    await this.secure.delete(iosKey(userId, deviceId));
    await this.secure.delete(androidKey(userId, deviceId));
    await this.secure.delete(unattestedKey(userId, deviceId));
    await this.secure.delete(backoffKey(userId, deviceId));
    await this.secure.delete(rekeyCooldownKey(userId, deviceId));
  }
}
