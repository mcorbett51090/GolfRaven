// supabase/tests/integration/apple-config.deno.test.ts
//
// `loadRewardsAttestationConfig` (privileged.ts: the ONLY reader of the DeviceCheck environment variables) trims its values exactly as the App
// Attest and Sign in with Apple loaders do, and the key it hands the DeviceCheck client is read by the SHARED PKCS#8 parser (_shared/pem.ts), so
// the same `.p8` pasted any of the usual ways is configured, and a malformed one is "not configured" (503-class), never a crash.
// Needs no database; it lives here because privileged.ts (a Deno-only module) can only be imported under Deno.

import { assert, assertEquals, assertInstanceOf } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { loadRewardsAttestationConfig } from "../../functions/_shared/privileged.ts";
import { createDeviceCheckClient } from "../../functions/_shared/rewards/devicecheck-client.ts";
import { VendorNotConfiguredError } from "../../functions/_shared/rewards/types.ts";
import type { VendorHttp } from "../../functions/_shared/rewards/vendor-http.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };
const NAMES = ["GR_APPLE_TEAM_ID", "GR_APPLE_BUNDLE_ID", "GR_APPLE_DEVICECHECK_KEY_ID", "GR_APPLE_DEVICECHECK_PRIVATE_KEY", "GR_APPLE_DEVICECHECK_ENV"];

async function withEnv(values: Record<string, string | undefined>, fn: () => Promise<void> | void): Promise<void> {
  const saved = NAMES.map((n) => [n, Deno.env.get(n)] as const);
  try {
    for (const n of NAMES) {
      const v = values[n];
      if (v === undefined) Deno.env.delete(n);
      else Deno.env.set(n, v);
    }
    await fn();
  } finally {
    for (const [n, v] of saved) v === undefined ? Deno.env.delete(n) : Deno.env.set(n, v);
  }
}

// Fences assembled at run time: no source line carries a literal PEM header (gitleaks' private-key rule would read one; nothing here is a key).
const FENCE = "-".repeat(5);
const block = (body: string) => `${FENCE}BEGIN PRIVATE KEY${FENCE}\n${body}\n${FENCE}END PRIVATE KEY${FENCE}`;

async function makePem(): Promise<string> {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  const b64 = btoa(String.fromCharCode(...der)).replace(/(.{64})/g, "$1\n");
  return block(b64);
}

const okEnv = (pem: string, over: Record<string, string> = {}) => ({
  GR_APPLE_TEAM_ID: "TEAMX",
  GR_APPLE_BUNDLE_ID: "com.example.app",
  GR_APPLE_DEVICECHECK_KEY_ID: "KEYX",
  GR_APPLE_DEVICECHECK_PRIVATE_KEY: pem,
  GR_APPLE_DEVICECHECK_ENV: "production",
  ...over,
});

function http(): VendorHttp & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    timeoutMs: 1_000,
    nowMs: () => 1_780_000_000_000,
    randomUuid: () => "00000000-0000-4000-8000-000000000001",
    fetch: (url) => {
      calls.push(url);
      return Promise.resolve(new Response('{"bit0":false,"bit1":false}', { status: 200 }));
    },
  };
}

Deno.test("loadRewardsAttestationConfig: a clean environment is configured, and every other shape is null (nothing half-set)", DT, async () => {
  const pem = await makePem();
  await withEnv(okEnv(pem), () => {
    const c = loadRewardsAttestationConfig();
    assertEquals(c.apple?.teamId, "TEAMX");
    assertEquals(c.apple?.environment, "production");
  });
  for (const drop of NAMES) {
    await withEnv({ ...okEnv(pem), [drop]: undefined }, () => assertEquals(loadRewardsAttestationConfig().apple, null, `${drop} unset`));
  }
  await withEnv(okEnv(pem, { GR_APPLE_DEVICECHECK_ENV: "staging" }), () => assertEquals(loadRewardsAttestationConfig().apple, null, "an unknown environment is not a default"));
  await withEnv(okEnv(pem, { GR_APPLE_DEVICECHECK_PRIVATE_KEY: "  \n " }), () => assertEquals(loadRewardsAttestationConfig().apple, null, "a blank key"));
});

Deno.test("loadRewardsAttestationConfig: trims like the App Attest and Sign in with Apple loaders (a trailing newline on the environment is still `production`)", DT, async () => {
  const pem = await makePem();
  await withEnv(okEnv(pem, { GR_APPLE_DEVICECHECK_ENV: "production\n" }), () => {
    assertEquals(loadRewardsAttestationConfig().apple?.environment, "production", "trailing newline on the environment");
  });
  await withEnv(okEnv(pem, { GR_APPLE_DEVICECHECK_ENV: "  development \r\n" }), () => {
    assertEquals(loadRewardsAttestationConfig().apple?.environment, "development");
  });
  await withEnv(okEnv(pem, { GR_APPLE_TEAM_ID: " TEAMX\n", GR_APPLE_BUNDLE_ID: "com.example.app\n", GR_APPLE_DEVICECHECK_KEY_ID: "\tKEYX \n" }), () => {
    const a = loadRewardsAttestationConfig().apple;
    assertEquals([a?.teamId, a?.bundleId, a?.keyId], ["TEAMX", "com.example.app", "KEYX"]);
  });
  // whitespace INSIDE an id is refused, as in loadCheckinAttestationConfig / loadAttestKeyVerifierConfig (it would corrupt `<team>.<bundle>`)
  await withEnv(okEnv(pem, { GR_APPLE_TEAM_ID: "TEAM X" }), () => assertEquals(loadRewardsAttestationConfig().apple, null, "inner whitespace in the team id"));
  await withEnv(okEnv(pem, { GR_APPLE_BUNDLE_ID: "com.example. app" }), () => assertEquals(loadRewardsAttestationConfig().apple, null, "inner whitespace in the bundle id"));
});

Deno.test("loadRewardsAttestationConfig + DeviceCheck client: the key is accepted with real newlines AND as one line with a literal backslash-n", DT, async () => {
  const pem = await makePem();
  for (const [name, value] of [["real newlines", pem], ["literal backslash-n", pem.replace(/\n/g, "\\n")], ["trailing newline", `${pem}\n`]] as const) {
    await withEnv(okEnv(value), async () => {
      const apple = loadRewardsAttestationConfig().apple;
      assert(apple !== null, name);
      const h = http();
      const bits = await createDeviceCheckClient(apple, h).queryTwoBits("dG9rZW4=");
      assertEquals(bits.bit0, false, name);
      assertEquals(h.calls, ["https://api.devicecheck.apple.com/v1/query_two_bits"], name);
    });
  }
});

Deno.test("a MALFORMED DeviceCheck key stays unconfigured at the client (VendorNotConfiguredError, which the handler answers 503), never a crash, and nothing is sent", DT, async () => {
  const pem = await makePem();
  for (const bad of ["garbage", block("!!!"), pem.replace("END PRIVATE", "END PUBLIC"), `${pem}\n${pem}`, "\\n"]) {
    await withEnv(okEnv(bad), async () => {
      const apple = loadRewardsAttestationConfig().apple;
      assert(apple !== null, "non-blank, so the loader hands it on; the client refuses it");
      const h = http();
      let thrown: unknown;
      try {
        await createDeviceCheckClient(apple, h).queryTwoBits("dG9rZW4=");
      } catch (e) {
        thrown = e;
      }
      assertInstanceOf(thrown, VendorNotConfiguredError, JSON.stringify(bad).slice(0, 30));
      assertEquals(h.calls, []);
    });
  }
});
