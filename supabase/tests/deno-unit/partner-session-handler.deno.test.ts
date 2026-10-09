// supabase/tests/deno-unit/partner-session-handler.deno.test.ts
//
// docs/security/partner-auth-design.md PA-12 (slice S1.2), the pure half: the `partner-session` handler with the REAL S0 wrapper (through webauthn-port.ts) and the software authenticator, against an
// in-memory model of the minter lane. The model reproduces exactly what the database does that this suite needs (a stored counter advanced by compare-and-set, the per-credential failure counter
// and cooldown of design 8); the real database is supabase/tests/integration/partner-session.deno.test.ts. PURE: no network, no files, no environment (CI runs it with `--deny-net --cached-only`).
//
// What this file proves that the vitest handler suite (fake verifier) cannot: that a REAL assertion by a real software authenticator passes the wrapper and reaches the mint, that every way a real
// assertion can be wrong is refused by the wrapper BEFORE the mint (wrong origin, RP ID, challenge, user verification, user handle, signature, credential id, cross-origin), that a counter that does not
// advance is isolated from every other fault (so a clone reaches the database's alarm and a forgery does not), and that five forgeries put a credential into cooldown while a valid assertion is
// refused during it.

import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { handlePartnerSessionRequest, type PartnerSessionDeps } from "../../functions/_shared/partner/session-handler.ts";
import type { CredentialLookup, EmailOtpPort, MintInput, PartnerDb, PartnerMintTx, RpConfig } from "../../functions/_shared/partner/ports.ts";
import { assertionVerifier } from "../../functions/_shared/partner/webauthn-port.ts";
import { newPartnerSessionToken, toB64u } from "../../functions/_shared/partner/token.ts";
import { uuidToBytes } from "../../functions/_shared/partner/session-shape.ts";
import { type AssertOptions, SoftwareAuthenticator } from "./software-authenticator.ts";

const RP: RpConfig = { rpId: "partners.example.test", origin: "https://partners.example.test" };
/** The sign-in cells never reach the email proof (S1.3): a call to it is a failure of the test, not a fake answer. */
const NO_OTP: EmailOtpPort = {
  send: () => Promise.reject(new Error("the sign-in suite must not send an email")),
  verify: () => Promise.reject(new Error("the sign-in suite must not verify an email code")),
};
const USER_ID = "00000000-0000-0000-0000-1000000000a1";
const NOW = Date.UTC(2030, 0, 1, 12, 0, 0);

interface Model {
  deps: PartnerSessionDeps;
  auth: SoftwareAuthenticator;
  /** the database's view of the credential */
  stored: { signCount: number; failures: number; cooldown: boolean };
  mints: MintInput[];
  statuses: string[];
  failuresRecorded: number;
  committed: number;
  /** one fresh challenge for the next assertion */
  nonce: Uint8Array;
  token: string;
}

async function model(alg: "ES256" | "RS256", storedCount = 0): Promise<Model> {
  const auth = await SoftwareAuthenticator.create(alg, uuidToBytes(USER_ID)!);
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const exp = NOW / 1000 + 100;
  const m: Model = {
    auth,
    stored: { signCount: storedCount, failures: 0, cooldown: false },
    mints: [],
    statuses: [],
    failuresRecorded: 0,
    committed: 0,
    nonce,
    token: `${toB64u(nonce)}.${exp}.${toB64u(new Uint8Array(32).fill(2))}`,
    deps: undefined as unknown as PartnerSessionDeps,
  };
  const tx: PartnerMintTx = {
    rpConfig: async () => RP,
    issueChallenge: async () => ({ nonce, exp, mac: new Uint8Array(32).fill(2) }),
    lookupCredential: async (id): Promise<CredentialLookup> =>
      toB64u(id) !== auth.id ? { status: "unknown" } : m.stored.cooldown ? { status: "cooldown" } : { status: "ok", credential: { id: "11111111-1111-1111-1111-111111111111", userId: USER_ID, alg: alg === "ES256" ? -7 : -257, publicKey: auth.cosePublicKey, signCount: m.stored.signCount } },
    recordFailure: async () => {
      m.failuresRecorded += 1;
      m.stored.failures += 1;
      if (m.stored.failures >= 5) {
        m.stored.cooldown = true;
        m.stored.failures = 0;
        return "cooldown";
      }
      return "counted";
    },
    mint: async (input) => {
      m.mints.push(input);
      // the database's compare-and-set on the counter, from the SIGNED authenticator data (bytes 33 to 36)
      const ad = input.authenticatorData;
      const counter = ad[33]! * 16777216 + ad[34]! * 65536 + ad[35]! * 256 + ad[36]!;
      if (m.stored.signCount < counter || (m.stored.signCount === 0 && counter === 0)) {
        m.stored.signCount = counter;
        m.statuses.push("ok");
        return { status: "ok", aal: 1, expiresAt: "2030-01-01T20:00:00.000Z" };
      }
      m.statuses.push("counter_regression");
      return { status: "counter_regression", aal: null, expiresAt: null };
    },
  };
  const db: PartnerDb = {
    withMint: async (op) => {
      const r = await op(tx);
      m.committed += 1;
      return r;
    },
    withInviteMint: () => Promise.reject(new Error("not used")),
    withSession: () => Promise.reject(new Error("not used")),
    withInvites: () => Promise.reject(new Error("not used")),
    withMembers: () => Promise.reject(new Error("not used")),
    withAttest: () => Promise.reject(new Error("not used")),
    withReview: () => Promise.reject(new Error("not used")),
    withStock: () => Promise.reject(new Error("not used")),
    withEntitlements: () => Promise.reject(new Error("not used")),
    withProgramme: () => Promise.reject(new Error("not used")),
    withOffersAdmin: () => Promise.reject(new Error("not used")),
    withSponsorships: () => Promise.reject(new Error("not used")),
    withOffersRedeem: () => Promise.reject(new Error("not used")),
    withSettlementExport: () => Promise.reject(new Error("not used")),
    hitRateLimit: () => Promise.reject(new Error("not used")),
    hitSystemRateLimit: () => Promise.reject(new Error("not used")),
  };
  m.deps = { db, allowedOrigin: RP.origin, webauthn: assertionVerifier, otp: NO_OTP, nowMs: () => NOW, newSessionToken: newPartnerSessionToken };
  return m;
}

async function present(m: Model, o: Partial<AssertOptions> = {}): Promise<Response> {
  const credential = await m.auth.assert({ rpId: RP.rpId, origin: RP.origin, challenge: m.nonce, ...o });
  return await handlePartnerSessionRequest(
    new Request("https://project.example.test/functions/v1/partner-session/verify", {
      method: "POST",
      headers: { "content-type": "application/json", origin: RP.origin },
      body: JSON.stringify({ challengeToken: m.token, credential }),
    }),
    m.deps,
  );
}

const UNIFORM = JSON.stringify({ error: { code: "unauthenticated", message: "authentication failed" } });

for (const alg of ["ES256", "RS256"] as const) {
  Deno.test(`verify: a real ${alg} assertion passes the wrapper, reaches the mint and returns the opaque token once`, async () => {
    const m = await model(alg);
    const res = await present(m);
    assertEquals(res.status, 201);
    const data = (await res.json()).data as { token: string; aal: number };
    assert(/^gr_ps_[A-Za-z0-9_-]{43}$/.test(data.token));
    assertEquals(m.mints.length, 1);
    assertEquals(m.failuresRecorded, 0);
    assertEquals(m.stored.signCount, 1);
    assertEquals(m.committed, 1);
  });
}

Deno.test("verify: counter 0 against a stored 0 (a synced passkey) is accepted", async () => {
  const m = await model("ES256", 0);
  assertEquals((await present(m, { counter: 0 })).status, 201);
});

// every way a real assertion can be wrong, each by changing exactly ONE thing; each is the uniform 401, never reaches the mint, and counts one failure
const FORGERIES: Array<[string, (m: Model) => Partial<AssertOptions> | Promise<Partial<AssertOptions>>]> = [
  ["wrong origin", () => ({ origin: "https://evil.example.test" })],
  ["a sibling subdomain of the RP ID as the origin", () => ({ origin: "https://sub.partners.example.test" })],
  ["wrong RP ID hash", () => ({ rpIdHashOf: "other.example.test" })],
  ["no user verification", () => ({ flags: { uv: false } })],
  ["no user presence", () => ({ flags: { up: false, uv: true } })],
  ["a different challenge in the client data", () => ({ client: { challenge: toB64u(new Uint8Array(32).fill(9)) } })],
  ["crossOrigin true", () => ({ client: { crossOrigin: true } })],
  ["a registration-type client data", () => ({ client: { type: "webauthn.create" } })],
  ["a tampered signature", () => ({ tamperSignature: true })],
  ["a signature over other authenticator data", () => ({ tamperAuthenticatorData: true })],
  ["a signature by another key", async () => ({ signWith: await SoftwareAuthenticator.create("ES256") })],
  ["a different user handle", () => ({ userHandle: new Uint8Array(16).fill(1) })],
  ["no user handle", () => ({ userHandle: null })],
];
for (const [label, mutate] of FORGERIES) {
  Deno.test(`verify (PA-12): ${label} is the uniform 401, never reaches the mint and counts one failure`, async () => {
    const m = await model("ES256");
    const res = await present(m, await mutate(m));
    assertEquals(res.status, 401);
    assertEquals(await res.text(), UNIFORM);
    assertEquals(m.mints.length, 0);
    assertEquals(m.failuresRecorded, 1);
    assertEquals(m.committed, 1, "the refusal's transaction committed (the counter is kept)");
  });
}

Deno.test("verify (PA-12): an assertion presented under a credential id nobody holds is the uniform 401: nothing is verified, nothing is counted (so presenting made-up ids costs the database nothing and grows no table)", async () => {
  const m = await model("ES256");
  const res = await present(m, { reportedId: toB64u(new Uint8Array(32).fill(7)) });
  assertEquals(res.status, 401);
  assertEquals(await res.text(), UNIFORM);
  assertEquals(m.mints.length, 0);
  assertEquals(m.failuresRecorded, 0);
  assertEquals(m.committed, 1);
});

Deno.test("verify (PA-12): a counter that does not advance reaches the mint (so the database can raise its alarm), is not counted as a failure and is the uniform 401", async () => {
  for (const [label, counter] of [["lower", 3], ["equal", 5], ["zero", 0]] as const) {
    const m = await model("ES256", 5);
    const res = await present(m, { counter });
    assertEquals(res.status, 401, label);
    assertEquals(await res.text(), UNIFORM, label);
    assertEquals(m.mints.length, 1, `${label}: the assertion reached the mint`);
    assertEquals(m.statuses, ["counter_regression"], label);
    assertEquals(m.failuresRecorded, 0, `${label}: a clone indicator is not a guess`);
    assertEquals(m.stored.signCount, 5, `${label}: the counter did not move`);
    assertEquals(m.committed, 1, `${label}: the transaction committed (the alarm rows live there)`);
  }
  const ok = await model("ES256", 5);
  assertEquals((await present(ok, { counter: 6 })).status, 201, "control: counter 6 against 5 mints");
});

Deno.test("verify (PA-12): a FORGED assertion with a lower counter is NOT passed to the mint: the isolation re-verifies against a zero counter and the forgery fails again", async () => {
  for (const mutate of [{ tamperSignature: true }, { origin: "https://evil.example.test" }, { flags: { uv: false } }] as Array<Partial<AssertOptions>>) {
    const m = await model("ES256", 5);
    const res = await present(m, { counter: 3, ...mutate });
    assertEquals(res.status, 401);
    assertEquals(m.mints.length, 0, JSON.stringify(mutate));
    assertEquals(m.failuresRecorded, 1, JSON.stringify(mutate));
  }
});

Deno.test("verify (PA-12): a replayed assertion reaches the mint again and the model's database refuses it by its counter; the Edge itself does not remember challenges (stateless)", async () => {
  const m = await model("ES256");
  const credential = await m.auth.assert({ rpId: RP.rpId, origin: RP.origin, challenge: m.nonce });
  const send = () => handlePartnerSessionRequest(new Request("https://p.example.test/partner-session/verify", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ challengeToken: m.token, credential }) }), m.deps);
  assertEquals((await send()).status, 201);
  // the second presentation: the stored counter is now the assertion's own, so the wrapper refuses it on the counter alone, which the isolation recognises: it goes to the mint (the real database answers `replayed` there)
  const again = await send();
  assertEquals(again.status, 401);
  assertEquals(m.mints.length, 2);
  assertEquals(m.failuresRecorded, 0);
});

Deno.test("verify (design 8): five forgeries put the credential into cooldown; a VALID assertion is then refused without being verified, and nothing more is counted", async () => {
  const m = await model("ES256");
  for (let i = 0; i < 5; i++) {
    const res = await present(m, { tamperSignature: true });
    assertEquals(res.status, 401);
  }
  assertEquals(m.failuresRecorded, 5);
  assertEquals(m.stored.cooldown, true);
  const valid = await present(m);
  assertEquals(valid.status, 401, "a valid assertion during the cooldown is refused");
  assertEquals(await valid.text(), UNIFORM);
  assertEquals(m.mints.length, 0);
  assertEquals(m.failuresRecorded, 5, "nothing is counted during the cooldown");
  m.stored.cooldown = false; // the cooldown ends (the database's clock)
  assertEquals((await present(m)).status, 201, "and a valid assertion mints again");
});

Deno.test("verify: an unknown origin header is refused before the body, and a body that is not an assertion never reaches the wrapper", async () => {
  const m = await model("ES256");
  const bad = await handlePartnerSessionRequest(
    new Request("https://p.example.test/partner-session/verify", { method: "POST", headers: { "content-type": "application/json", origin: "https://evil.example.test" }, body: "{}" }),
    m.deps,
  );
  assertEquals(bad.status, 403);
  const notAssertion = await handlePartnerSessionRequest(
    new Request("https://p.example.test/partner-session/verify", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ challengeToken: m.token, credential: { id: "x" } }) }),
    m.deps,
  );
  assertEquals(notAssertion.status, 400);
  assertEquals(m.mints.length, 0);
  assertEquals(m.committed, 0);
});

Deno.test("this suite was not granted network access (the pure suite runs with --deny-net)", async () => {
  const status = await Deno.permissions.query({ name: "net" });
  assertEquals(status.state, "denied");
});
