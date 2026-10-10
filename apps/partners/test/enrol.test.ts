/**
 * Accepting an invite or an enrolment token, end to end through the controller (docs/security/partner-auth-design.md 6.1 branch N): the REAL
 * `partner-invites` and `partner-session` handlers (strict bodies, the one-403 policy, the constant start answer) over the fake database, a software
 * authenticator that really creates a key pair, and the controller's screens. The property that defines "enrolled": the credential the page created
 * is stored by the server and SIGNS IN afterwards; and the first screen after enrolment is the forced PIN.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPartnerApi } from "../src/api/client";
import { createController, type AppState } from "../src/app/controller";
import { extractToken } from "../src/app/enrol-flow";
import { consumeInviteLink } from "../src/app/invite-link";
import { installPageLifecycle } from "../src/app/lifecycle";
import { createSoftAuthenticator } from "./support/soft-authenticator";
import { installStorageSpies, type StorageSpies } from "./support/storage-spies";
import { API_BASE, makeWorld, PAGE_ORIGIN, RP_ID, type World } from "./support/world";

const EMAIL = "new.hire@partners.example.test";
const CODE = "123456";

function setup(over: Parameters<typeof makeWorld>[0] = {}) {
  const w = makeWorld(over);
  const api = createPartnerApi({ baseUrl: API_BASE, fetch: w.fetch });
  const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true } });
  const states: AppState[] = [];
  controller.subscribe((s) => states.push(s));
  return { w, api, controller, states };
}
type Setup = ReturnType<typeof setup>;

const enrolState = (c: Setup["controller"]) => {
  const s = c.getState();
  if (s.screen !== "enrol") throw new Error(`expected the enrol screen, got ${s.screen}`);
  return s;
};
const requests = (w: World, route: string) => w.server.log.filter((r) => r.method === "POST" && r.path.endsWith(route));

/** Walks the happy path up to the passkey step. */
async function toPasskeyStep(s: Setup, token: string) {
  s.controller.startEnrol({ token });
  await s.controller.requestEnrolCode();
  await s.controller.submitEnrolCode(CODE);
  expect(enrolState(s.controller).step).toBe("passkey");
}

let spies: StorageSpies;
beforeEach(() => {
  spies = installStorageSpies();
});
afterEach(() => spies.restore());

describe("the invite, start to first PIN", () => {
  it("token -> emailed code -> passkey -> signed in with the forced first PIN; the passkey the page created then signs in on its own", async () => {
    const s = setup();
    const { token } = s.w.server.addInvite({ email: EMAIL });

    s.controller.startEnrol({ token });
    expect(enrolState(s.controller)).toEqual({ screen: "enrol", step: "token", hasToken: true, kind: "invite", busy: false, notice: null });
    // opening the link sends nothing: the person presses "email me a code"
    expect(s.w.server.log).toEqual([]);

    await s.controller.requestEnrolCode();
    expect(s.w.server.state.mailed).toEqual([EMAIL]);
    expect(enrolState(s.controller)).toMatchObject({ step: "code", busy: false, notice: { kind: "enrol-code-sent" } });
    expect(JSON.parse(requests(s.w, "/invites/accept/start")[0]!.body)).toEqual({ token });

    await s.controller.submitEnrolCode(CODE);
    expect(enrolState(s.controller)).toMatchObject({ step: "passkey", busy: false, notice: null });
    // the server accepted the invite and handed back the ceremony; nothing was created yet
    expect(s.w.auth.created).toHaveLength(0);

    await s.controller.createPasskey();
    const state = s.controller.getState();
    expect(state.screen).toBe("signed-in");
    if (state.screen !== "signed-in") return;
    expect(s.api.hasSession()).toBe(true);
    expect(state.panel).toEqual({ kind: "pin-setup", mode: "set", forced: true, canSkip: false, busy: false, notice: null });
    // the first session carries the enrolment window: the PIN may be set with no further proof
    expect(Date.parse(state.session.stepUp.enrolmentUntil!)).toBeGreaterThan(Date.now());
    expect(state.session.memberships[0]).toMatchObject({ role: "staff" });
    expect(s.w.auth.created).toHaveLength(1);

    // the credential the page created is the one the server stored
    const userId = s.w.server.userByEmail(EMAIL)!.id;
    expect(s.w.server.credentialsOf(userId).map((c) => c.credentialId)).toEqual([Buffer.from(s.w.auth.created[0]!.credentialId).toString("base64url")]);

    // forced PIN: a mismatch and a rule-refused PIN send nothing; a good PIN is saved and lands on the home screen
    const before = requests(s.w, "/pin/set").length;
    await s.controller.submitPinSetup({ current: "", pin: "7391", confirm: "7392" });
    await s.controller.submitPinSetup({ current: "", pin: "1234", confirm: "1234" });
    expect(requests(s.w, "/pin/set")).toHaveLength(before);
    await s.controller.submitPinSetup({ current: "", pin: "7391", confirm: "7391" });
    const home = s.controller.getState();
    expect(home).toMatchObject({ screen: "signed-in", panel: null, notice: { kind: "pin-set" } });
    expect(s.w.server.pinRecord(userId)).not.toBeNull();

    // and the new passkey signs in later (the stored key verifies a real assertion)
    await s.controller.signOut();
    const second = createSoftAuthenticator({ origin: PAGE_ORIGIN, rpId: RP_ID, credential: s.w.auth.created[0]! });
    const again = createController({ api: s.w.newClient(), webauthn: { credentials: second.credentials, supported: true } });
    await again.signIn();
    expect(again.getState()).toMatchObject({ screen: "signed-in", session: { userId } });
  });

  it("the invite token and the one-time code are in NO state at any step, and no storage or console is touched", async () => {
    const s = setup();
    const { token } = s.w.server.addInvite({ email: EMAIL });
    await toPasskeyStep(s, token);
    await s.controller.createPasskey();
    for (const state of s.states) {
      const text = JSON.stringify(state);
      expect(text).not.toContain(token);
      expect(text).not.toContain(token.slice(7));
      expect(text).not.toContain("gr_inv_");
      expect(text).not.toContain("gr_ps_");
      expect(text).not.toContain(CODE);
    }
    expect(spies.calls).toEqual([]);
  });

  it("a pasted token works too (the whole link, with spaces); a pasted non-token is refused before any request", async () => {
    const s = setup();
    const { token } = s.w.server.addInvite({ email: EMAIL });
    s.controller.startEnrol();
    expect(enrolState(s.controller)).toMatchObject({ step: "token", hasToken: false });
    await s.controller.requestEnrolCode("not a token");
    expect(enrolState(s.controller).notice).toEqual({ kind: "error", message: { key: "enrol.tokenInvalid" } });
    expect(s.w.server.log).toEqual([]);
    await s.controller.requestEnrolCode(`  ${PAGE_ORIGIN}/invite#${token}  \n`);
    expect(enrolState(s.controller)).toMatchObject({ step: "code", hasToken: true });
    expect(s.w.server.state.mailed).toEqual([EMAIL]);
  });

  it("an unknown token looks exactly like a good one at the start (the server's constant answer), and the code step then refuses it with the one error", async () => {
    const s = setup();
    s.controller.startEnrol({ token: `gr_inv_${"Z".repeat(43)}` });
    await s.controller.requestEnrolCode();
    expect(enrolState(s.controller)).toMatchObject({ step: "code", notice: { kind: "enrol-code-sent" } });
    expect(s.w.server.state.mailed).toEqual([]);
    await s.controller.submitEnrolCode(CODE);
    expect(enrolState(s.controller)).toMatchObject({ step: "code", busy: false, notice: { kind: "error", message: { key: "enrol.refused" } } });
  });

  it("a wrong code stays on the code step with the refusal, and the right one then goes on", async () => {
    const s = setup();
    const { token } = s.w.server.addInvite({ email: EMAIL });
    s.controller.startEnrol({ token });
    await s.controller.requestEnrolCode();
    await s.controller.submitEnrolCode("999999");
    expect(enrolState(s.controller)).toMatchObject({ step: "code", notice: { kind: "error", message: { key: "enrol.refused" } } });
    await s.controller.submitEnrolCode("12ab");
    expect(enrolState(s.controller).notice).toEqual({ kind: "error", message: { key: "enrol.codeInvalid" } });
    expect(requests(s.w, "/accept/verify")).toHaveLength(1); // the malformed code never left the page
    await s.controller.submitEnrolCode(CODE);
    expect(enrolState(s.controller).step).toBe("passkey");
  });

  it("a person who already has a passkey (409 existing_member_sign_in) is sent to sign-in with that notice; a recovery case says so", async () => {
    for (const [outcome, notice] of [["existing_member_sign_in", "enrol-existing-member"], ["recover_required", "enrol-recover-required"]] as const) {
      const s = setup();
      const { token } = s.w.server.addInvite({ email: EMAIL });
      s.controller.startEnrol({ token });
      await s.controller.requestEnrolCode();
      s.w.server.state.acceptOutcome = outcome;
      await s.controller.submitEnrolCode(CODE);
      expect(s.controller.getState()).toEqual({ screen: "signed-out", notice: { kind: notice } });
      expect(s.api.hasSession()).toBe(false);
    }
  });

  it("cancelling the passkey prompt keeps the step and the challenge: pressing again succeeds", async () => {
    const s = setup();
    const { token } = s.w.server.addInvite({ email: EMAIL });
    await toPasskeyStep(s, token);
    s.w.auth.failNextCreateWith = "NotAllowedError";
    await s.controller.createPasskey();
    expect(enrolState(s.controller)).toMatchObject({ step: "passkey", busy: false, notice: { kind: "error", message: { key: "error.cancelled" } } });
    expect(requests(s.w, "/partner-invites/credentials")).toHaveLength(0);
    await s.controller.createPasskey();
    expect(s.controller.getState().screen).toBe("signed-in");
  });

  it("a refused registration (the server no longer knows the challenge) starts over at the token step, with the refusal shown and nothing held", async () => {
    const s = setup();
    const { token } = s.w.server.addInvite({ email: EMAIL });
    await toPasskeyStep(s, token);
    s.w.server.reset(); // the challenge is gone, as it would be once spent or expired
    await s.controller.createPasskey();
    expect(enrolState(s.controller)).toMatchObject({ step: "token", hasToken: false, kind: null, busy: false, notice: { kind: "error", message: { key: "enrol.refused" } } });
    expect(s.api.hasSession()).toBe(false);
  });

  it("cancelEnrol drops everything: back at sign-in, and a late answer is ignored", async () => {
    const s = setup();
    const { token } = s.w.server.addInvite({ email: EMAIL });
    s.controller.startEnrol({ token });
    await s.controller.requestEnrolCode();
    s.controller.cancelEnrol();
    expect(s.controller.getState()).toEqual({ screen: "signed-out", notice: null });
    await s.controller.submitEnrolCode(CODE); // no token held any more: nothing happens
    await s.controller.requestEnrolCode();
    expect(s.controller.getState()).toEqual({ screen: "signed-out", notice: null });
    expect(requests(s.w, "/accept/verify")).toHaveLength(0);
  });

  it("the page going away mid-enrolment (reset, as pagehide does) drops it and leaves nothing held", async () => {
    const s = setup();
    const { token } = s.w.server.addInvite({ email: EMAIL });
    await toPasskeyStep(s, token);
    s.controller.reset();
    expect(s.controller.getState().screen).toBe("signed-out");
    await s.controller.createPasskey();
    expect(s.api.hasSession()).toBe(false);
    expect(s.w.auth.created).toHaveLength(0);
  });

  it("a cancel while the first credential is on the wire revokes the session it opened, and none is held", async () => {
    const s = setup();
    const { token } = s.w.server.addInvite({ email: EMAIL });
    await toPasskeyStep(s, token);
    // the server stores the credential and opens the session, then holds the RESPONSE back: the cancel arrives while the token is still on its way
    s.w.server.state.delayAfter = { credentials: 150 };
    const pending = s.controller.createPasskey();
    await new Promise((r) => setTimeout(r, 50));
    expect(s.w.server.sessions()).toHaveLength(1);
    s.controller.cancelEnrol();
    await pending;
    expect(s.api.hasSession()).toBe(false);
    expect(s.controller.getState().screen).toBe("signed-out");
    expect(s.w.server.sessions()).toEqual([]); // the session the server opened was revoked on arrival, not left to idle out
  });
});

describe("an enrolment token (recovery) follows the same path through the enrolments routes", () => {
  it("accepts a gr_enr_ token and, for a person whose PIN is already set, lands on the home screen with no forced PIN", async () => {
    const s = setup();
    await s.w.server.seedPin("7391");
    const { token } = s.w.server.addEnrolment({ email: "staff@partners.example.test" });
    s.controller.startEnrol({ token });
    expect(enrolState(s.controller).kind).toBe("enrolment");
    await s.controller.requestEnrolCode();
    expect(requests(s.w, "/enrolments/accept/start")).toHaveLength(1);
    await s.controller.submitEnrolCode(CODE);
    await s.controller.createPasskey();
    expect(s.controller.getState()).toMatchObject({ screen: "signed-in", panel: null });
  });

  it("the same person with no PIN is asked for one", async () => {
    const s = setup();
    const { token } = s.w.server.addEnrolment({ email: "staff@partners.example.test" });
    await toPasskeyStep(s, token);
    await s.controller.createPasskey();
    expect(s.controller.getState()).toMatchObject({ screen: "signed-in", panel: { kind: "pin-setup", forced: true } });
  });
});

describe("the forced first PIN", () => {
  async function enrolled() {
    const s = setup();
    const { token } = s.w.server.addInvite({ email: EMAIL });
    await toPasskeyStep(s, token);
    await s.controller.createPasskey();
    return s;
  }

  it("cannot be closed, but Lock and Sign out still end the session", async () => {
    const s = await enrolled();
    s.controller.closePanel();
    expect(s.controller.getState()).toMatchObject({ screen: "signed-in", panel: { kind: "pin-setup", forced: true } });
    await s.controller.signOut();
    expect(s.controller.getState().screen).toBe("signed-out");
    expect(s.api.hasSession()).toBe(false);
  });

  it("may be left only once the server has refused to give THIS person a PIN (an operator or admin has none)", async () => {
    const s = await enrolled();
    // the server already has a PIN for this person: a set is a 409, which is not an input error
    await s.w.server.seedPin("7391", { userId: s.w.server.userByEmail(EMAIL)!.id });
    await s.controller.submitPinSetup({ current: "", pin: "5072", confirm: "5072" });
    const st = s.controller.getState();
    expect(st).toMatchObject({ screen: "signed-in", panel: { kind: "pin-setup", forced: true, canSkip: true, mode: "change" } });
    s.controller.closePanel();
    expect(s.controller.getState()).toMatchObject({ screen: "signed-in", panel: null });
  });
});

describe("extractToken", () => {
  const inv = `gr_inv_${"a-_9".repeat(10)}abc`;
  it.each([
    ["the bare token", inv],
    ["a link", `https://partners.example.test/invite#${inv}`],
    ["surrounding text", `  Your link: ${inv}\n`],
  ])("finds the token in %s", (_name, text) => {
    expect(extractToken(text)).toEqual({ token: inv, kind: "invite" });
  });
  it("tells the two kinds apart and refuses short, other-prefixed and empty input", () => {
    expect(extractToken(`gr_enr_${"c".repeat(43)}`)).toEqual({ token: `gr_enr_${"c".repeat(43)}`, kind: "enrolment" });
    expect(extractToken(`gr_ps_${"c".repeat(43)}`)).toBeNull();
    expect(extractToken(`gr_inv_${"c".repeat(42)}`)).toBeNull();
    expect(extractToken("")).toBeNull();
  });
});

describe("the invite link (token in the URL fragment)", () => {
  function env(hash: string) {
    const replaced: unknown[][] = [];
    return {
      replaced,
      env: { location: { hash, pathname: "/invite", search: "?x=1" }, history: { replaceState: (...a: unknown[]) => void replaced.push(a) } },
    };
  }

  it("starts the flow with the token, removes the fragment from the address bar without navigating, and sends nothing", () => {
    const s = setup();
    const { token } = s.w.server.addInvite({ email: EMAIL });
    const e = env(`#${token}`);
    expect(consumeInviteLink(e.env, s.controller)).toBe(true);
    expect(e.replaced).toEqual([[null, "", "/invite?x=1"]]);
    expect(enrolState(s.controller)).toMatchObject({ step: "token", hasToken: true, kind: "invite" });
    expect(JSON.stringify(s.controller.getState())).not.toContain(token);
    expect(s.w.server.log).toEqual([]);
  });

  it("ignores any other fragment (and leaves it alone)", () => {
    const s = setup();
    const e = env("#section");
    expect(consumeInviteLink(e.env, s.controller)).toBe(false);
    expect(e.replaced).toEqual([]);
    expect(s.controller.getState().screen).toBe("signed-out");
  });

  it("a second link while one flow is open replaces it; while signed in it is cleared and ignored", async () => {
    const s = setup();
    const a = s.w.server.addInvite({ email: EMAIL });
    const b = s.w.server.addInvite({ email: "other@partners.example.test" });
    consumeInviteLink(env(`#${a.token}`).env, s.controller);
    await s.controller.requestEnrolCode();
    consumeInviteLink(env(`#${b.token}`).env, s.controller);
    expect(enrolState(s.controller)).toMatchObject({ step: "token", hasToken: true });
    await s.controller.requestEnrolCode();
    expect(s.w.server.state.mailed).toEqual([EMAIL, "other@partners.example.test"]);

    const signed = setup();
    await signed.controller.signIn();
    const e = env(`#${a.token}`);
    expect(consumeInviteLink(e.env, signed.controller)).toBe(true);
    expect(e.replaced).toHaveLength(1);
    expect(signed.controller.getState().screen).toBe("signed-in");
  });
});

describe("page lifecycle covers the enrolment screen", () => {
  it("pagehide mid-enrolment resets to signed-out and holds nothing", async () => {
    const s = setup();
    const { token } = s.w.server.addInvite({ email: EMAIL });
    await toPasskeyStep(s, token);
    const handlers: Record<string, (ev: Event) => void> = {};
    installPageLifecycle({ addEventListener: (t, l) => void (handlers[t] = l) }, s.api, s.controller);
    handlers["pagehide"]!(new Event("pagehide"));
    expect(s.controller.getState().screen).toBe("signed-out");
    expect(s.api.hasSession()).toBe(false);
  });
});
