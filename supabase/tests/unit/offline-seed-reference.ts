// supabase/tests/unit/offline-seed-reference.ts
//
// TEST-ONLY reference implementation of the offline-seed derivation (migration 0045, private.offline_seed_derive), written independently of the database
// function: used by the fake Repo (so a handler test sees the real shape of a seed), by the unit tests, and by the Deno integration suite, which compares
// the REAL database's answer with it. It is the ONLY place the derivation exists in TypeScript, and it lives under tests/ on purpose: the production Edge
// code never holds the key K, so it must never be able to derive a seed. (A test fails if supabase/functions grows a copy of it.)
//
// seed = HMAC-SHA256(K, 'golfraven/offline-seed/v1' || 0x00 || user_id (16 bytes) || device_id (16 bytes) || seed_version (4 bytes, big-endian))
// K = the UTF-8 bytes of the Vault secret `offline_seed_key`.

export const OFFLINE_SEED_LABEL = "golfraven/offline-seed/v1";

/** The shim's K (supabase/tests/shim.sql): a harness constant, not a secret. Built from parts so the literal does not sit in one string in this file. */
export const SHIM_OFFLINE_SEED_KEY = ["shim-test-only-offline-seed-key", "32bytes-minimum", "z".repeat(24)].join("-");

export function uuidBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, "");
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) throw new Error(`not a uuid: ${uuid}`);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export async function deriveSeedReference(key: string, userId: string, deviceId: string, seedVersion: number): Promise<Uint8Array> {
  const label = new TextEncoder().encode(OFFLINE_SEED_LABEL);
  const msg = new Uint8Array(label.length + 1 + 16 + 16 + 4);
  msg.set(label, 0);
  msg[label.length] = 0;
  msg.set(uuidBytes(userId), label.length + 1);
  msg.set(uuidBytes(deviceId), label.length + 17);
  new DataView(msg.buffer).setUint32(label.length + 33, seedVersion, false);
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, msg));
}

export const toHex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
