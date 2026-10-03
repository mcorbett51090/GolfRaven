/**
 * Where the offline-code seed lives: the SECURE STORE and nowhere else (Keychain `AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY` on iOS, the Keystore-backed preferences on Android, both through
 * `secure/expo-secure-store.ts`, which sets that class on every item). NEVER SQLite: its file is in the iOS backup set, and a seed that rides a backup to another phone would let that phone
 * show the player's codes. NEVER a log line, an error message, an analytics event or a JS object that outlives the screen that needs it.
 *
 * One item per (user, device): `gr.offline_seed.<userId>.<deviceId>`. The user is IN THE KEY, so another account on the same install can neither read nor overwrite it, and the record names
 * its user and device again, so an item that somehow sat under the wrong key is refused as well. Policy (the same as the outbox's and the attestation state's):
 *   - SIGN-OUT keeps it, dormant: nothing here is touched, and it is the same player's again at the next sign-in, including with no network (the point of an OFFLINE code). It cannot be read
 *     by anyone else: every read names the signed-in user. (The server notes the player may want to rotate on sign-out; that needs a session and a network, which a sign-out does not have,
 *     and it would take the offline code from a player who signs back in at a no-signal course. The rotation stays an explicit "reset code".)
 *   - ACCOUNT DELETION wipes the deleted user's item (`wipe`), and only theirs.
 *   - A record that cannot be read back (corrupt JSON, a wrong shape, another user's name) is "no seed": unlike an attestation key, forgetting it is safe, because the server hands out the
 *     SAME seed again (deterministic) and `provision` restores it. A store that cannot be read or written throws, and the caller reports "unavailable", never "no seed".
 */
import type { SecureStore } from "../secure";
import { OFFLINE_SEED_BYTES } from "./params";

const PART_RE = /^[A-Za-z0-9-]{1,64}$/;
const HEX_RE = /^[0-9a-f]{64}$/;

function part(name: string, v: string): string {
  if (!PART_RE.test(v)) throw new Error(`offline seed: ${name} is not a safe key part`);
  return v;
}

/** The secure-store key of one (user, device). Exported for the tests that prove the user is in it. */
export const offlineSeedKey = (userId: string, deviceId: string): string => `gr.offline_seed.${part("userId", userId)}.${part("deviceId", deviceId.toLowerCase())}`;

export interface StoredSeed {
  /** The 32 seed bytes. */
  seed: Uint8Array;
  seedVersion: number;
  /** The server's clock when the seed was issued (epoch ms). */
  issuedAtMs: number;
  /** The device clock when the answer arrived (epoch ms): `issuedAtMs - receivedAtMs` is the clock-offset estimate. */
  receivedAtMs: number;
  /** A rotation was requested and its outcome is unknown (the answer was lost): the next provisioning must fetch the server's CURRENT seed before the code is trusted. */
  resyncNeeded: boolean;
}

const toHex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
function fromHex(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export type SaveOutcome = "saved" | "kept_newer";

export class OfflineSeedStore {
  constructor(private readonly secure: SecureStore) {}

  /** The stored seed of this user on this device, or `null` (nothing stored, or a record that is not exactly what `save` writes). Throws when the secure store cannot be read. */
  async load(userId: string, deviceId: string): Promise<StoredSeed | null> {
    const raw = await this.secure.get(offlineSeedKey(userId, deviceId));
    if (raw === null) return null;
    try {
      const v = JSON.parse(raw) as Record<string, unknown>;
      if (
        v.v === 1 &&
        v.userId === userId &&
        v.deviceId === deviceId.toLowerCase() &&
        typeof v.seedHex === "string" &&
        HEX_RE.test(v.seedHex) &&
        typeof v.seedVersion === "number" &&
        Number.isInteger(v.seedVersion) &&
        v.seedVersion >= 1 &&
        typeof v.issuedAtMs === "number" &&
        Number.isFinite(v.issuedAtMs) &&
        typeof v.receivedAtMs === "number" &&
        Number.isFinite(v.receivedAtMs) &&
        typeof v.resyncNeeded === "boolean"
      ) {
        const seed = fromHex(v.seedHex);
        if (seed.length === OFFLINE_SEED_BYTES) return { seed, seedVersion: v.seedVersion, issuedAtMs: v.issuedAtMs, receivedAtMs: v.receivedAtMs, resyncNeeded: v.resyncNeeded };
      }
    } catch {
      // fall through: unreadable
    }
    return null;
  }

  /**
   * Writes the record, EXCEPT that a record with a higher `seedVersion` is never replaced by one with a lower (PR #44 gate LOW-2, belt and braces next to the manager's per-user
   * single-flight): the server's version only grows, so a lower one is a stale answer that arrived late, and storing it would put the device on a seed the server no longer accepts.
   * Returns `"kept_newer"` (and writes nothing) in that case, `"saved"` otherwise. An equal or higher version is written, so a resync flag and the restore of an earlier record still work.
   * The one exception is `authoritative: true`, used ONLY for the answer to an explicit user "reset code" (a rotation): the server's seed is what it just answered, whatever its version. The
   * server never lowers a version in normal operation, but after a database restore (DR / point-in-time recovery) it can be BELOW what this device holds; without this the device would refuse
   * every seed (a rotation gives n+1, still lower) until its record is wiped, and on iOS the Keychain survives a reinstall. The per-user single-flight (`manager.ts`) is what makes it safe: a
   * rotation answer cannot be a late answer overtaken by another request of the same user, so a lower version there is the server's truth, not a stale reply.
   */
  async save(userId: string, deviceId: string, s: StoredSeed, opts: { authoritative?: boolean } = {}): Promise<SaveOutcome> {
    if (s.seed.length !== OFFLINE_SEED_BYTES) throw new Error(`offline seed: the seed must be ${OFFLINE_SEED_BYTES} bytes`);
    const current = await this.load(userId, deviceId);
    if (current !== null && current.seedVersion > s.seedVersion && opts.authoritative !== true) {
      current.seed.fill(0);
      return "kept_newer";
    }
    const record = { v: 1, userId, deviceId: deviceId.toLowerCase(), seedHex: toHex(s.seed), seedVersion: s.seedVersion, issuedAtMs: s.issuedAtMs, receivedAtMs: s.receivedAtMs, resyncNeeded: s.resyncNeeded };
    await this.secure.set(offlineSeedKey(userId, deviceId), JSON.stringify(record));
    return "saved";
  }

  /** Account deletion: removes this user's seed for this device (another user's, and the device id, stay). */
  async wipe(userId: string, deviceId: string): Promise<void> {
    await this.secure.delete(offlineSeedKey(userId, deviceId));
  }
}
