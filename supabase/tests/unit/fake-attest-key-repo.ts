// supabase/tests/unit/fake-attest-key-repo.ts
//
// In-memory implementation of `AttestKeyRepo` (supabase/functions/_shared/rewards/types.ts) for unit-testing
// attest-key-handler.ts without a database. `register` MIRRORS app.register_attest_key (0034): the same refusals
// (not the caller's device, same key, retired key, key id that is not the hash of the key), the same replacement
// (counter back to 0, old key retired, last 16 kept). The Deno integration suite
// (supabase/tests/integration/attest-key.deno.test.ts) runs the same scenarios against the real SQL, which is
// what keeps this fake honest. State lives in a WeakMap keyed by the shared `FakeState`.

import { Errors } from "../../functions/_shared/http.ts";
import type { AttestKeyRepo, Platform } from "../../functions/_shared/rewards/types.ts";
import type { FakeState } from "./fake-repo.ts";

export interface FakeAttestDevice {
  id: string;
  userId: string;
  platform: Platform;
  keyId: string | null;
  publicKey: Uint8Array | null;
  counter: number;
  registeredAt: string | null;
  retired: string[];
}

const registry = new WeakMap<FakeState, Map<string, FakeAttestDevice>>();

export function fakeAttestDevices(state: FakeState): Map<string, FakeAttestDevice> {
  let m = registry.get(state);
  if (!m) {
    m = new Map();
    registry.set(state, m);
  }
  return m;
}

export function seedAttestDevice(state: FakeState, d: Partial<FakeAttestDevice> & { id: string; userId: string }): FakeAttestDevice {
  const row: FakeAttestDevice = { platform: "ios", keyId: null, publicKey: null, counter: 0, registeredAt: null, retired: [], ...d };
  fakeAttestDevices(state).set(row.id, row);
  return row;
}

async function sha256Hex(s: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
  return [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function makeFakeAttestKeyRepo(state: FakeState, uid: string): AttestKeyRepo {
  const devices = () => fakeAttestDevices(state);
  return {
    async deviceKey(deviceId: string) {
      const d = devices().get(deviceId);
      if (!d || d.userId !== uid) return null;
      return { platform: d.platform, keyId: d.keyId };
    },
    async register(input) {
      const d = devices().get(input.deviceId);
      if (!d || d.userId !== uid) throw Errors.notFound("no such device");
      if (d.platform !== "ios") throw Errors.unprocessable("attestation_rejected", "the attestation could not be verified");
      const keyHash = await sha256Hex(input.keyId);
      if (d.keyId === input.keyId) throw Errors.conflict("key_already_registered", "this key is already registered on this device");
      if (d.retired.includes(keyHash)) throw Errors.conflict("key_previously_retired", "this key was retired on this device and cannot be registered again");
      const replaced = d.keyId !== null;
      if (replaced) {
        d.retired = [...d.retired, await sha256Hex(d.keyId!)].slice(-16);
        d.counter = 0;
      }
      d.keyId = input.keyId;
      d.publicKey = input.publicKey;
      d.registeredAt = state.now.toISOString();
      return replaced ? "replaced" : "registered";
    },
  };
}
