/**
 * Me → Sign-in methods: the §3.4 linking rules as the client state machine (P4 AT 18).
 * The server's answers used here are the recorded ones (`fixtures/edge-contract.json`) wherever a status/code pair appears.
 */
import { describe, expect, it } from "vitest";
import { apiError, FakeApple, FakeAuth, FakeLinkApi, fixedRandom, gateIn, jwt } from "./support/fakes";
import { AppleLinkFlow, LINK_FAILURES, linkFailureFrom, type LinkDeps, type LinkState } from "../src/account";
import { AuthError } from "../src/auth";
import { ApiError } from "../src/api";
import { recorded } from "./support/edge-fixtures";

async function setup(state: "unknown" | "eligible" | "ineligible" = "eligible") {
  const apple = new FakeApple();
  apple.result = { status: "ok", identityToken: jwt({ email: "bob@example.test", email_verified: "true" }), authorizationCode: "auth-code-1" };
  const auth = new FakeAuth();
  const api = new FakeLinkApi();
  const deps: LinkDeps = { gate: await gateIn(state), auth, api, apple, random: fixedRandom() };
  const flow = new AppleLinkFlow(deps);
  const states: LinkState[] = [];
  flow.subscribe((s) => states.push(s));
  return { flow, apple, auth, api, states };
}
const proofRequired = () => apiError("conflict", 409, "email_proof_required", { emailProofRequired: true });
const self = { linked: { provider: "apple" as const, created: true, isPrivateRelay: false }, linkedTo: "self" as const, methods: [] };

describe("linking Apple to a signed-in account", () => {
  it("the plain case: one link call (no emailProof), state linked/self, no OTP involved", async () => {
    const { flow, api, auth } = await setup();
    api.script = [self];
    const s = await flow.start();
    expect(s).toEqual({ step: "linked", where: "self", methods: [] });
    expect(api.calls).toHaveLength(1);
    expect("emailProof" in api.calls[0]!).toBe(false);
    expect(auth.emailCodeRequests).toEqual([]);
  });

  it("hashed nonce to Apple, raw nonce to the server", async () => {
    const { flow, apple, api } = await setup();
    api.script = [self];
    await flow.start();
    expect(apple.hashedNonces[0]).toMatch(/^[0-9a-f]{64}$/);
    expect(api.calls[0]!.nonce).not.toBe(apple.hashedNonces[0]);
    expect(api.calls[0]!.nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe("NEVER AUTO-LINK: an email match stops and waits for the player (AT 18)", () => {
  it("409 email_proof_required => needs_proof; NO code is requested and NO proof is sent until the player acts", async () => {
    const { flow, api, auth } = await setup();
    api.script = [proofRequired()];
    const s = await flow.start();
    expect(s).toEqual({ step: "needs_proof", email: "bob@example.test", notice: null, retryAfterSeconds: null });
    expect(api.calls).toHaveLength(1); // the initial attempt only
    expect(auth.emailCodeRequests).toEqual([]);
    // time passes, nothing else happens by itself
    await new Promise((r) => setTimeout(r, 20));
    expect(api.calls).toHaveLength(1);
    expect(auth.emailCodeRequests).toEqual([]);
  });

  it("two explicit actions are needed: sendCode() requests the OTP to THAT address with createUser false; submitCode() sends the proof", async () => {
    const { flow, api, auth } = await setup();
    api.script = [proofRequired(), { linked: { provider: "apple", created: true, isPrivateRelay: false }, linkedTo: "proven_account", methods: null }];
    await flow.start();

    const afterSend = await flow.sendCode();
    expect(afterSend).toMatchObject({ step: "code_sent", email: "bob@example.test" });
    expect(auth.emailCodeRequests).toEqual([{ email: "bob@example.test", createUser: false }]); // never creates an account, never signs in
    expect(api.calls).toHaveLength(1); // still no proof sent

    const done = await flow.submitCode("123456");
    expect(done).toEqual({ step: "linked", where: "proven_account", methods: null });
    expect(api.calls).toHaveLength(2);
    expect(api.calls[1]!.emailProof).toEqual({ code: "123456" });
    // the same credential and nonce as the first attempt (the server checks the proof before it exchanges the code)
    expect(api.calls[1]!.identityToken).toBe(api.calls[0]!.identityToken);
    expect(api.calls[1]!.nonce).toBe(api.calls[0]!.nonce);
    expect(auth.verifyCalls).toEqual([]); // the client never verifies the code itself: it never signs in as the other account
  });

  it("submitCode() before sendCode() does nothing; sendCode() from idle does nothing", async () => {
    const { flow, api, auth } = await setup();
    expect(await flow.submitCode("123456")).toEqual({ step: "idle" });
    expect(await flow.sendCode()).toEqual({ step: "idle" });
    api.script = [proofRequired()];
    await flow.start();
    const before = api.calls.length;
    const s = await flow.submitCode("123456"); // needs_proof, not code_sent
    expect(s.step).toBe("needs_proof");
    expect(api.calls).toHaveLength(before);
    expect(auth.emailCodeRequests).toEqual([]);
  });

  it("the proof is only ever attached by submitCode (every emailProof in a whole session of calls comes from a typed code)", async () => {
    const { flow, api } = await setup();
    api.script = [proofRequired(), apiError("rejected", 422, "email_proof_invalid", { attemptsRemaining: 4 }), self];
    await flow.start();
    await flow.sendCode();
    await flow.submitCode("111111");
    await flow.submitCode("222222");
    expect(api.calls.map((c) => c.emailProof?.code ?? null)).toEqual([null, "111111", "222222"]);
  });
});

describe("the proof step", () => {
  it("a wrong code: 422 email_proof_invalid keeps the credential, shows attempts left, and the player may try again", async () => {
    const { flow, api } = await setup();
    api.script = [proofRequired(), apiError("rejected", 422, "email_proof_invalid", { attemptsRemaining: 4 }), self];
    await flow.start();
    await flow.sendCode();
    const wrong = await flow.submitCode("000000");
    expect(wrong).toMatchObject({ step: "code_sent", wrongCode: true, attemptsRemaining: 4 });
    const ok = await flow.submitCode("123456");
    expect(ok.step).toBe("linked");
    expect(api.calls[2]!.authorizationCode).toBe("auth-code-1"); // unspent code reused: the server had not exchanged it
  });

  it("429 on the proof (5 wrong per address per hour): stays in code_sent with the lockout shown; no further calls by itself", async () => {
    const { flow, api } = await setup();
    api.script = [proofRequired(), apiError("rate_limited", 429, "rate_limited", { retryAfterSeconds: 3600 }, 3600)];
    await flow.start();
    await flow.sendCode();
    const s = await flow.submitCode("123456");
    expect(s).toMatchObject({ step: "code_sent", notice: "rate_limited", retryAfterSeconds: 3600 });
    expect(api.calls).toHaveLength(2);
  });

  it("a malformed code is refused locally (no request, so no attempt is burned)", async () => {
    const { flow, api } = await setup();
    api.script = [proofRequired()];
    await flow.start();
    await flow.sendCode();
    const s = await flow.submitCode("12ab");
    expect(s).toMatchObject({ step: "code_sent", notice: "bad_code" });
    expect(api.calls).toHaveLength(1);
  });

  it("any other failure after the proof is terminal and the Apple credential is dropped (the code may be spent)", async () => {
    const { flow, api } = await setup();
    api.script = [proofRequired(), apiError("rejected", 422, "authorization_code_mismatch")];
    await flow.start();
    await flow.sendCode();
    const s = await flow.submitCode("123456");
    expect(s).toEqual({ step: "failed", reason: "authorization_code_mismatch", retryAfterSeconds: null });
    expect(await flow.submitCode("123456")).toEqual(s); // nothing to submit with any more
    expect(api.calls).toHaveLength(2);
  });

  it("no address in the token: needs_proof asks the player for one, and a bad one is refused without sending anything", async () => {
    const { flow, apple, api, auth } = await setup();
    apple.result = { status: "ok", identityToken: jwt({ sub: "x" }), authorizationCode: "c" };
    api.script = [proofRequired()];
    const s = await flow.start();
    expect(s).toMatchObject({ step: "needs_proof", email: null });
    expect(await flow.sendCode()).toMatchObject({ step: "needs_proof", notice: "no_email" });
    expect(await flow.sendCode("nope")).toMatchObject({ step: "needs_proof", notice: "no_email" });
    expect(auth.emailCodeRequests).toEqual([]);
    expect(await flow.sendCode("bob@example.test")).toMatchObject({ step: "code_sent", email: "bob@example.test" });
    expect(auth.emailCodeRequests).toEqual([{ email: "bob@example.test", createUser: false }]);
  });

  it("the code could not be sent (no such account, rate limited, offline): stays in needs_proof with the reason", async () => {
    for (const [err, reason] of [
      [new AuthError("unknown_user"), "unknown_user"],
      [new AuthError("rate_limited"), "rate_limited"],
      [new AuthError("network"), "network"],
    ] as const) {
      const { flow, api, auth } = await setup();
      api.script = [proofRequired()];
      await flow.start();
      auth.failWith = err;
      expect(await flow.sendCode()).toMatchObject({ step: "needs_proof", notice: reason });
    }
  });

  it("cancel drops the credential: a later submit has nothing to send", async () => {
    const { flow, api } = await setup();
    api.script = [proofRequired()];
    await flow.start();
    await flow.sendCode();
    expect(flow.cancel()).toEqual({ step: "cancelled" });
    await flow.submitCode("123456");
    expect(api.calls).toHaveLength(1);
  });
});

describe("a private-relay Apple account links only from this screen (AT 18)", () => {
  it("this flow is the only place a relay identity is linked, and it links to the CALLER (no proof path): 200 self", async () => {
    const { flow, api } = await setup();
    api.script = [{ linked: { provider: "apple", created: true, isPrivateRelay: true }, linkedTo: "self", methods: [] }];
    expect((await flow.start()).step).toBe("linked");
    expect(api.calls).toHaveLength(1);
  });

  it("a relay address that belongs to another account never gets a proof path: 409 email_belongs_to_another_account", async () => {
    const { flow, api, auth } = await setup();
    api.script = [apiError("conflict", 409, "email_belongs_to_another_account")];
    expect(await flow.start()).toEqual({ step: "failed", reason: "relay_belongs_to_other_account", retryAfterSeconds: null });
    expect(auth.emailCodeRequests).toEqual([]);
  });
});

describe("the age gate and the platform", () => {
  it.each([
    ["unknown", "age_required"],
    ["ineligible", "blocked"],
  ] as const)("gate %s => %s, Apple is not shown and nothing is sent", async (gate, step) => {
    const { flow, apple, api } = await setup(gate);
    expect(await flow.start()).toEqual({ step });
    expect(apple.hashedNonces).toEqual([]);
    expect(api.calls).toEqual([]);
  });

  it("Apple unavailable on this device, and the player cancelling, are reported", async () => {
    const a = await setup();
    a.apple.availabilityResult = "unsupported_platform";
    expect(await a.flow.start()).toEqual({ step: "unsupported_platform" });
    const b = await setup();
    b.apple.result = { status: "cancelled" };
    expect(await b.flow.start()).toEqual({ step: "cancelled" });
    expect(b.api.calls).toEqual([]);
  });
});

describe("every server answer maps to a failure the screen has copy for (recorded statuses and codes)", () => {
  const cases: [string, ApiError, string][] = [
    ["link_409_provider_already_linked", apiError("conflict", 409, "provider_already_linked"), "provider_already_linked"],
    ["link_409_email_proof_mismatch", apiError("conflict", 409, "email_proof_mismatch"), "proof_refused"],
    ["link_409_email_belongs_to_another_account", apiError("conflict", 409, "email_belongs_to_another_account"), "relay_belongs_to_other_account"],
    ["link_422_invalid_identity_token", apiError("rejected", 422, "invalid_identity_token"), "invalid_identity_token"],
    ["link_422_authorization_code_rejected", apiError("rejected", 422, "authorization_code_rejected"), "authorization_code_rejected"],
    ["link_422_authorization_code_mismatch", apiError("rejected", 422, "authorization_code_mismatch"), "authorization_code_mismatch"],
    ["link_429_proof_rate_limited", apiError("rate_limited", 429, "rate_limited", undefined, 3600), "rate_limited"],
    ["link_501_google", apiError("not_supported", 501, "provider_not_supported"), "not_supported"],
    ["link_502_upstream_unavailable", apiError("unavailable", 502, "upstream_unavailable"), "not_available"],
    ["link_503_provider_not_configured", apiError("unavailable", 503, "provider_not_configured"), "not_available"],
    ["err_401_unauthorized", apiError("unauthenticated", 401, "unauthorized"), "unauthenticated"],
  ];
  it.each(cases)("%s", (fixtureName, err, reason) => {
    expect(recorded(fixtureName).status).toBe(err.status); // the fixture exists and has the status this test assumes
    expect(JSON.parse(recorded(fixtureName).body).error.code).toBe(err.code);
    expect(linkFailureFrom(err).reason).toBe(reason);
  });

  it("network and unknown are covered, and every LinkFailure value is one the table can produce or a local one", () => {
    expect(linkFailureFrom(new ApiError({ kind: "network" })).reason).toBe("network");
    expect(linkFailureFrom(new Error("x")).reason).toBe("unknown");
    expect(new Set(LINK_FAILURES).size).toBe(LINK_FAILURES.length);
  });
});
