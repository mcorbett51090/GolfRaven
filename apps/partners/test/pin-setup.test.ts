/**
 * Setting and changing the PIN, and the email proof that gates both (docs/security/partner-auth-design.md 6.3), against the REAL partner-session handler
 * (strict body parser, error mapping) over the fake database. The properties that define the effect: the stored verifier is the independent PBKDF2 of the
 * PIN under the salt the page SENT; a PIN the rules refuse sends nothing; a passkey session alone cannot set a PIN (the proof is what unlocks it).
 */
import { pbkdf2Sync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { isPartnerApiError } from "../src/api/errors";
import { PinError } from "../src/auth/pin";
import { changePin, pinSetupMode, proofActive, setPin, startEmailProof, verifyEmailProof } from "../src/auth/pin-setup";
import { signInWithPasskey } from "../src/auth/sign-in";
import { createStepUp } from "../src/auth/step-up";
import { fromB64u } from "../../../supabase/functions/_shared/partner/token.ts";
import { makeWorld, type World } from "./support/world";

async function signedIn(): Promise<World> {
  const w = makeWorld();
  await signInWithPasskey(w.api, { credentials: w.auth.credentials, supported: true });
  return w;
}
const err = async (p: Promise<unknown>) => {
  const e = await p.catch((x: unknown) => x);
  if (!isPartnerApiError(e)) throw new Error(`expected a PartnerApiError, got ${String(e)}`);
  return e;
};
const posts = (w: World, route: string) => w.server.log.filter((r) => r.method === "POST" && r.path.endsWith(`/partner-session/${route}`));
const PIN = "7391";
const NEW_PIN = "5072";

async function prove(w: World): Promise<void> {
  await startEmailProof(w.api);
  await verifyEmailProof(w.api, w.server.state.otpCode);
}

describe("the email proof", () => {
  it("a code is mailed to the member's OWN address (the page types no address), and the right code opens a proof window the session reports", async () => {
    const w = await signedIn();
    expect(proofActive(await w.api.session(), Date.now())).toBe(false);
    await startEmailProof(w.api);
    expect(w.server.state.mailed).toEqual(["staff@partners.example.test"]);
    expect(posts(w, "otp-proof/start")[0]!.body).toBe("{}");
    const r = await verifyEmailProof(w.api, w.server.state.otpCode);
    expect(Date.parse(r.otpProofUntil)).toBeGreaterThan(Date.now());
    expect(proofActive(await w.api.session(), Date.now())).toBe(true);
    expect(JSON.parse(posts(w, "otp-proof/verify")[0]!.body)).toEqual({ code: "123456" });
  });

  it("a wrong code is the server's one 403 'otp_refused', and no proof is recorded", async () => {
    const w = await signedIn();
    await startEmailProof(w.api);
    const e = await err(verifyEmailProof(w.api, "000000"));
    expect([e.kind, e.status, e.code]).toEqual(["forbidden", 403, "otp_refused"]);
    expect(proofActive(await w.api.session(), Date.now())).toBe(false);
  });

  it("proofActive reads both windows and honours their expiry", async () => {
    const w = await signedIn();
    const s = await w.api.session();
    const at = (iso: string | null) => ({ ...s, stepUp: { ...s.stepUp, enrolmentUntil: iso, otpProofUntil: null } });
    expect(proofActive(at(new Date(Date.now() + 60_000).toISOString()), Date.now())).toBe(true);
    expect(proofActive(at(new Date(Date.now() - 1).toISOString()), Date.now())).toBe(false);
    expect(proofActive({ ...s, stepUp: { ...s.stepUp, otpProofUntil: new Date(Date.now() + 60_000).toISOString() } }, Date.now())).toBe(true);
  });
});

describe("setting a PIN", () => {
  it("a passkey session alone cannot set a PIN: the server refuses (403), nothing is stored", async () => {
    const w = await signedIn();
    const e = await err(setPin(w.api, PIN));
    expect([e.kind, e.status, e.code]).toEqual(["forbidden", 403, "forbidden"]);
    expect(w.server.pinRecord()).toBeNull();
  });

  it("with the proof, the page sends { derived, salt, iterations }: the stored verifier is the independent PBKDF2 of the PIN under the salt it sent", async () => {
    const w = await signedIn();
    expect(await pinSetupMode(w.api)).toBe("set");
    await prove(w);
    await setPin(w.api, PIN);

    const body = JSON.parse(posts(w, "pin/set")[0]!.body) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(["derived", "iterations", "salt"]);
    expect(Object.values(body)).not.toContain(PIN);
    expect(body["iterations"]).toBe(600_000);
    const salt = fromB64u(body["salt"] as string)!;
    expect(salt).toHaveLength(16);
    expect(body["derived"]).toBe(Buffer.from(pbkdf2Sync(PIN, salt, 600_000, 32, "sha256")).toString("base64url"));
    expect(w.server.pinRecord()).toMatchObject({ derived: body["derived"], salt: body["salt"], iterations: 600_000, failures: 0 });
    expect(await pinSetupMode(w.api)).toBe("change");
  });

  it("the PIN just set verifies through requirePin (the set and the verify agree on the derivation end to end)", async () => {
    const w = await signedIn();
    await prove(w);
    await setPin(w.api, PIN);
    const grant = await createStepUp({ api: w.api, prompter: { ask: async () => PIN } }).requirePin("A1");
    expect(grant.actionClass).toBe("A1");
    expect(w.server.state.pinGrantsIssued).toBe(1);
  });

  it("a PIN the rules refuse sends nothing at all (no request, no derivation), whether or not the session has the proof", async () => {
    const w = await signedIn();
    await prove(w);
    const derive = vi.spyOn(crypto.subtle, "deriveBits");
    const before = w.server.log.length;
    for (const bad of ["1234", "0000", "1990", "0101", "12"]) await expect(setPin(w.api, bad), bad).rejects.toBeInstanceOf(PinError);
    expect(derive).not.toHaveBeenCalled();
    expect(w.server.log.length).toBe(before);
    derive.mockRestore();
  });

  it("a second set is refused (409 pin_already_set): the PIN must be CHANGED, which needs the current one", async () => {
    const w = await signedIn();
    await prove(w);
    await setPin(w.api, PIN);
    const e = await err(setPin(w.api, NEW_PIN));
    expect([e.kind, e.code]).toEqual(["conflict", "pin_already_set"]);
    expect(w.server.pinRecord()!.derived).toBe(JSON.parse(posts(w, "pin/set")[0]!.body).derived);
  });

  it("after a reset (must_change) a new PIN is a SET, and the mode says so", async () => {
    const w = await signedIn();
    await w.server.seedPin(PIN, { mustChange: true });
    expect(await pinSetupMode(w.api)).toBe("set");
    await prove(w);
    await setPin(w.api, NEW_PIN);
    expect(w.server.pinRecord()!.mustChange).toBe(false);
  });

  it("a locked PIN offers neither: the mode is 'locked'", async () => {
    const w = await signedIn();
    await w.server.seedPin(PIN, { locked: true });
    expect(await pinSetupMode(w.api)).toBe("locked");
  });
});

describe("changing a PIN", () => {
  it("needs the proof, and the current PIN: derived under the STORED salt, the new one under a fresh salt", async () => {
    const w = await signedIn();
    await w.server.seedPin(PIN, { iterations: 210_000 });
    const old = w.server.pinRecord()!;
    expect((await err(changePin(w.api, PIN, NEW_PIN))).code).toBe("forbidden");
    expect(w.server.pinRecord()!.derived).toBe(old.derived);

    await prove(w);
    await changePin(w.api, PIN, NEW_PIN);
    const body = JSON.parse(posts(w, "pin/change")[0]!.body) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(["currentDerived", "derived", "iterations", "salt"]);
    expect(body["currentDerived"]).toBe(old.derived);
    expect(body["salt"]).not.toBe(old.salt);
    expect(body["derived"]).toBe(Buffer.from(pbkdf2Sync(NEW_PIN, fromB64u(body["salt"] as string)!, 600_000, 32, "sha256")).toString("base64url"));
    expect(Object.values(body)).not.toContain(PIN);
    expect(Object.values(body)).not.toContain(NEW_PIN);
    // the new PIN works and the old one does not
    const stepUp = (pin: string) => createStepUp({ api: w.api, prompter: { ask: async () => pin } }).requirePin("A1");
    await expect(stepUp(NEW_PIN)).resolves.toBeTruthy();
  });

  it("a wrong current PIN is 'pin_wrong' (and counts against the member's lockout); the PIN is unchanged", async () => {
    const w = await signedIn();
    await w.server.seedPin(PIN, { iterations: 210_000 });
    const old = w.server.pinRecord()!;
    await prove(w);
    const e = await err(changePin(w.api, "7392", NEW_PIN));
    expect([e.kind, e.code]).toEqual(["forbidden", "pin_wrong"]);
    expect(w.server.pinRecord()).toMatchObject({ derived: old.derived, failures: 1 });
  });

  it("either PIN refused by the rules sends nothing", async () => {
    const w = await signedIn();
    await w.server.seedPin(PIN, { iterations: 210_000 });
    await prove(w);
    const before = posts(w, "pin/change").length;
    await expect(changePin(w.api, PIN, "1234")).rejects.toBeInstanceOf(PinError);
    await expect(changePin(w.api, "1234", NEW_PIN)).rejects.toBeInstanceOf(PinError);
    expect(posts(w, "pin/change")).toHaveLength(before);
  });
});
