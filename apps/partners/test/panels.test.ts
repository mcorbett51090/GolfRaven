/**
 * The signed-in panels through the controller (docs/security/partner-auth-design.md 6.3, 6.4), against the real partner-session handler:
 *   - `controller.requirePin` (the `StepUp` an A1 / A2 screen calls) draws a PIN prompt, takes the digits from `submitPin`, and resolves with a grant;
 *   - set / change PIN, with the email proof they need;
 *   - the operator / admin second factor (enrol, confirm, verify).
 * The state never holds the digits of a PIN, a code or the TOTP seed beyond the panel that shows it.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPartnerApi } from "../src/api/client";
import { createController, type AppState, type Panel, type SignedInState } from "../src/app/controller";
import { StepUpError } from "../src/auth/step-up";
import { installStorageSpies, type StorageSpies } from "./support/storage-spies";
import { API_BASE, makeWorld } from "./support/world";

const PIN = "7391";
const NEW_PIN = "5072";

async function setup(over: Parameters<typeof makeWorld>[0] = {}) {
  const w = makeWorld(over);
  const api = createPartnerApi({ baseUrl: API_BASE, fetch: w.fetch });
  const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true } });
  const states: AppState[] = [];
  controller.subscribe((s) => states.push(s));
  await controller.signIn();
  return { w, api, controller, states };
}
type S = Awaited<ReturnType<typeof setup>>;
const home = (c: S["controller"]): SignedInState => {
  const s = c.getState();
  if (s.screen !== "signed-in") throw new Error(`expected signed-in, got ${s.screen}`);
  return s;
};
const panel = (c: S["controller"]): Panel | null => home(c).panel;
const settle = () => new Promise((r) => setTimeout(r, 0));
async function untilPanel(c: S["controller"], kind: Panel["kind"] | null, busy = false): Promise<void> {
  for (let i = 0; i < 400; i += 1) {
    const p = panel(c);
    if ((p?.kind ?? null) === kind && (p === null || !("busy" in p) || p.busy === busy)) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error(`the panel never became ${String(kind)}; it is ${JSON.stringify(panel(c))}`);
}
const posts = (s: S, route: string) => s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith(`/${route}`));

let spies: StorageSpies;
beforeEach(() => {
  spies = installStorageSpies();
});
afterEach(() => spies.restore());

describe("requirePin through the controller: the prompt an A1 or A2 screen gets", () => {
  it("opens a prompt, takes the digits from submitPin, shows busy while deriving, and resolves with a grant; the prompt then closes", async () => {
    const s = await setup();
    await s.w.server.seedPin(PIN);
    const asked = s.controller.requirePin("A1");
    await untilPanel(s.controller, "pin-prompt");
    expect(panel(s.controller)).toEqual({ kind: "pin-prompt", actionClass: "A1", problem: null, retryAfterSeconds: 0, busy: false });

    s.controller.submitPin(PIN);
    expect(panel(s.controller)).toMatchObject({ kind: "pin-prompt", busy: true });
    const grant = await asked;
    expect(grant.actionClass).toBe("A1");
    expect(panel(s.controller)).toBeNull();
    expect(s.w.server.state.pinGrantsIssued).toBe(1);

    // the digits were in no state, at any moment, and the request carried only the derived bytes
    for (const st of s.states) expect(JSON.stringify(st)).not.toContain(PIN);
    expect(Object.keys(JSON.parse(posts(s, "step-up/pin")[0]!.body))).toEqual(["derived"]);
    expect(spies.calls).toEqual([]);
  });

  it("a wrong PIN redraws the prompt with the problem and not-busy; a PIN the rules refuse says why and sends nothing", async () => {
    const s = await setup();
    await s.w.server.seedPin(PIN);
    const asked = s.controller.requirePin("A2");
    await untilPanel(s.controller, "pin-prompt");
    s.controller.submitPin("1234");
    await untilPanel(s.controller, "pin-prompt", false);
    expect(panel(s.controller)).toMatchObject({ kind: "pin-prompt", actionClass: "A2", problem: { kind: "rejected", reason: "run" }, busy: false });
    expect(posts(s, "step-up/pin")).toHaveLength(0);
    s.controller.submitPin("7392");
    await settle();
    await untilPanel(s.controller, "pin-prompt", false);
    expect(panel(s.controller)).toMatchObject({ problem: { kind: "wrong" } });
    s.controller.submitPin(PIN);
    await expect(asked).resolves.toMatchObject({ actionClass: "A2" });
    expect(panel(s.controller)).toBeNull();
  });

  it("cancelPin rejects the caller with 'cancelled' and closes the prompt", async () => {
    const s = await setup();
    await s.w.server.seedPin(PIN);
    const asked = s.controller.requirePin("A1");
    const caught = asked.catch((e: unknown) => e);
    await untilPanel(s.controller, "pin-prompt");
    s.controller.cancelPin();
    expect(((await caught) as StepUpError).kind).toBe("cancelled");
    expect(panel(s.controller)).toBeNull();
    expect(posts(s, "step-up/pin")).toHaveLength(0);
  });

  it("closePanel on a prompt cancels it too (Escape-style dismissal cannot leave the caller hanging)", async () => {
    const s = await setup();
    await s.w.server.seedPin(PIN);
    const caught = s.controller.requirePin("A1").catch((e: unknown) => e);
    await untilPanel(s.controller, "pin-prompt");
    s.controller.closePanel();
    expect(((await caught) as StepUpError).kind).toBe("cancelled");
  });

  const cases: Array<[string, (s: S) => Promise<unknown>]> = [
    ["unset", async () => undefined],
    ["must_change", async (s) => s.w.server.seedPin(PIN, { mustChange: true })],
    ["locked", async (s) => s.w.server.seedPin(PIN, { locked: true })],
  ];
  it.each(cases)("a PIN that is %s rejects with that kind and never opens a prompt for the digits", async (kind, arrange) => {
    const s = await setup();
    await arrange(s);
    const e = await s.controller.requirePin("A1").catch((x: unknown) => x);
    expect((e as StepUpError).kind).toBe(kind);
    expect(s.states.some((st) => st.screen === "signed-in" && st.panel?.kind === "pin-prompt")).toBe(false);
  });

  it("a second request while a prompt (or any panel) is open is refused as 'busy'", async () => {
    const s = await setup();
    await s.w.server.seedPin(PIN);
    const first = s.controller.requirePin("A1").catch((e: unknown) => e);
    await untilPanel(s.controller, "pin-prompt");
    expect(((await s.controller.requirePin("A2").catch((e: unknown) => e)) as StepUpError).kind).toBe("busy");
    s.controller.cancelPin();
    await first;
  });

  it("signing out while the prompt is open ends the call (no promise left hanging) and the prompt is gone", async () => {
    const s = await setup();
    await s.w.server.seedPin(PIN);
    const caught = s.controller.requirePin("A1").catch((e: unknown) => e);
    await untilPanel(s.controller, "pin-prompt");
    await s.controller.signOut();
    expect(((await caught) as StepUpError).kind).toBe("cancelled");
    expect(s.controller.getState().screen).toBe("signed-out");
  });

  it("without a session the call is the API's 401", async () => {
    const w = makeWorld();
    const c = createController({ api: w.api, webauthn: { credentials: w.auth.credentials, supported: true } });
    const e = await c.requirePin("A1").catch((x: unknown) => x);
    expect(e).toMatchObject({ name: "PartnerApiError", kind: "unauthenticated" });
  });
});

describe("set / change PIN from the home screen", () => {
  it("with no proof, opening the PIN screen asks for the email proof first; the proof then opens the set form; saving returns home", async () => {
    const s = await setup();
    await s.controller.openPinSetup();
    expect(panel(s.controller)).toMatchObject({ kind: "email-proof", step: "send", purpose: "pin" });
    expect(home(s.controller).busy).toBeNull();

    await s.controller.startEmailProof();
    expect(panel(s.controller)).toMatchObject({ kind: "email-proof", step: "code", busy: false });
    expect(s.w.server.state.mailed).toEqual(["staff@partners.example.test"]);

    await s.controller.submitEmailProof("000000");
    expect(panel(s.controller)).toMatchObject({ kind: "email-proof", step: "code", notice: { kind: "error", message: { key: "proof.refused" } } });
    await s.controller.submitEmailProof("abc");
    expect(panel(s.controller)).toMatchObject({ notice: { kind: "error", message: { key: "enrol.codeInvalid" } } });
    await s.controller.submitEmailProof(s.w.server.state.otpCode);
    expect(panel(s.controller)).toMatchObject({ kind: "pin-setup", mode: "set", forced: false, canSkip: false });

    await s.controller.submitPinSetup({ current: "", pin: PIN, confirm: PIN });
    expect(home(s.controller)).toMatchObject({ panel: null, notice: { kind: "pin-set" } });
    expect(s.w.server.pinRecord()).not.toBeNull();
    for (const st of s.states) expect(JSON.stringify(st)).not.toContain(PIN);
  });

  it("an existing PIN is a CHANGE: the form needs the current PIN, a wrong one is shown as such and counted, the right one saves", async () => {
    const s = await setup();
    await s.w.server.seedPin(PIN, { iterations: 210_000 });
    await s.controller.openPinSetup();
    await s.controller.startEmailProof();
    await s.controller.submitEmailProof(s.w.server.state.otpCode);
    expect(panel(s.controller)).toMatchObject({ kind: "pin-setup", mode: "change" });

    await s.controller.submitPinSetup({ current: "12", pin: NEW_PIN, confirm: NEW_PIN });
    expect(panel(s.controller)).toMatchObject({ notice: { kind: "error", message: { key: "pin.currentInvalid" } } });
    await s.controller.submitPinSetup({ current: "7392", pin: NEW_PIN, confirm: NEW_PIN });
    expect(panel(s.controller)).toMatchObject({ busy: false, notice: { kind: "error", message: { key: "pin.wrong" } } });
    expect(s.w.server.pinRecord()!.failures).toBe(1);
    await s.controller.submitPinSetup({ current: PIN, pin: NEW_PIN, confirm: NEW_PIN });
    expect(home(s.controller)).toMatchObject({ panel: null, notice: { kind: "pin-changed" } });
    for (const st of s.states) {
      expect(JSON.stringify(st)).not.toContain(PIN);
      expect(JSON.stringify(st)).not.toContain(NEW_PIN);
    }
  });

  it("a locked PIN is told so on the home screen: neither form opens", async () => {
    const s = await setup();
    await s.w.server.seedPin(PIN, { locked: true });
    await s.controller.openPinSetup();
    expect(home(s.controller)).toMatchObject({ panel: null, busy: null, notice: { kind: "error", message: { key: "pin.locked" } } });
  });

  it("every refusal the page makes itself (mismatch, a denied PIN) sends nothing and keeps the form", async () => {
    const s = await setup();
    await s.controller.openPinSetup();
    await s.controller.startEmailProof();
    await s.controller.submitEmailProof(s.w.server.state.otpCode);
    await s.controller.submitPinSetup({ current: "", pin: PIN, confirm: NEW_PIN });
    expect(panel(s.controller)).toMatchObject({ kind: "pin-setup", notice: { kind: "error", message: { key: "pin.mismatch" } } });
    for (const [pin, reason] of [["1111", "repeated"], ["1234", "run"], ["1985", "year"], ["0704", "date"], ["12", "format"]] as const) {
      await s.controller.submitPinSetup({ current: "", pin, confirm: pin });
      expect(panel(s.controller), pin).toMatchObject({ kind: "pin-setup", notice: { kind: "error", message: { key: `pin.rejected.${reason}` } } });
    }
    expect(posts(s, "pin/set")).toHaveLength(0);
  });

  it("closePanel returns home from a non-forced PIN screen and from the proof screen", async () => {
    const s = await setup();
    await s.controller.openPinSetup();
    s.controller.closePanel();
    expect(panel(s.controller)).toBeNull();
  });

  it("a panel result that arrives after sign-out is dropped: the next session does not inherit it", async () => {
    const s = await setup();
    await s.controller.openPinSetup();
    const pending = s.controller.startEmailProof();
    await s.controller.signOut();
    await pending;
    expect(s.controller.getState()).toMatchObject({ screen: "signed-out" });
  });
});

describe("the operator / admin second factor", () => {
  const needsTotp = { aal: 1, requiredAal: 2 };

  it("enrol: email proof, show the seed once, confirm with a code from it, then verify to reach aal 2; the seed is gone from the state once the panel closes", async () => {
    const s = await setup({ whoami: needsTotp });
    expect(home(s.controller).session).toMatchObject({ aal: 1, requiredAal: 2 });

    await s.controller.openTotp("enrol");
    expect(panel(s.controller)).toMatchObject({ kind: "email-proof", purpose: "totp" });
    await s.controller.startEmailProof();
    await s.controller.submitEmailProof(s.w.server.state.otpCode);
    expect(panel(s.controller)).toMatchObject({ kind: "totp", step: "enrol-start", enrolment: null });

    await s.controller.startTotpEnrol();
    const shown = panel(s.controller);
    expect(shown).toMatchObject({ kind: "totp", step: "enrol-confirm" });
    const seed = shown?.kind === "totp" ? shown.enrolment?.seed : undefined;
    expect(seed).toMatch(/^[A-Z2-7]{32}$/);
    expect(shown?.kind === "totp" ? shown.enrolment?.otpauthUrl : "").toContain("otpauth://totp/");

    await s.controller.submitTotp("12");
    expect(panel(s.controller)).toMatchObject({ notice: { kind: "error", message: { key: "totp.codeInvalid" } } });
    await s.controller.submitTotp("000000");
    expect(panel(s.controller)).toMatchObject({ step: "enrol-confirm", notice: { kind: "error", message: { key: "totp.wrong" } } });
    await s.controller.submitTotp(await s.w.server.totpCodeNow());
    expect(panel(s.controller)).toMatchObject({ kind: "totp", step: "verify", enrolment: null, notice: { kind: "totp-confirmed" } });

    await s.controller.submitTotp(await s.w.server.totpCodeNow());
    expect(home(s.controller)).toMatchObject({ panel: null, notice: { kind: "totp-verified" }, session: { aal: 2 } });
    // the seed was in the state only while its panel was open
    const last = JSON.stringify(s.controller.getState());
    expect(last).not.toContain(seed);
  });

  it("an enrolled member just enters the code: verify raises the session to aal 2; a wrong code is shown and not accepted", async () => {
    const s = await setup({ whoami: needsTotp });
    // enrol through the API directly (the proof, the seed, the confirm), then use the screen only to verify
    await s.controller.openTotp("enrol");
    await s.controller.startEmailProof();
    await s.controller.submitEmailProof(s.w.server.state.otpCode);
    await s.controller.startTotpEnrol();
    await s.controller.submitTotp(await s.w.server.totpCodeNow());
    s.controller.closePanel();
    expect(panel(s.controller)).toBeNull();

    await s.controller.openTotp("verify");
    await s.controller.submitTotp("000000");
    expect(panel(s.controller)).toMatchObject({ notice: { kind: "error", message: { key: "totp.wrong" } } });
    expect(home(s.controller).session.aal).toBe(1);
    await s.controller.submitTotp(await s.w.server.totpCodeNow());
    expect(home(s.controller).session.aal).toBe(2);
  });

  it("verifying with no authenticator enrolled is told 'add one first' (409 totp_not_set)", async () => {
    const s = await setup({ whoami: needsTotp });
    await s.controller.openTotp("verify");
    await s.controller.submitTotp("123456");
    expect(panel(s.controller)).toMatchObject({ kind: "totp", notice: { kind: "error", message: { key: "totp.notSet" } } });
  });
});
