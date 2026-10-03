/** Every outcome the new flows can produce has copy in both languages (the catalogue parity test checks the two files agree with each other). */
import { describe, expect, it } from "vitest";
import { LINK_FAILURES } from "../src/account";
import { en } from "../src/i18n/messages/en";
import { frCA } from "../src/i18n/messages/fr-CA";

const SIGN_IN_FAILURES = ["invalid_code", "invalid_email", "rate_limited", "network", "unknown"] as const;

describe("copy for the P4.2a screens", () => {
  it.each(LINK_FAILURES)("methods.error.%s exists in en and fr-CA", (reason) => {
    expect(en).toHaveProperty(`methods.error.${reason}`);
    expect(frCA).toHaveProperty(`methods.error.${reason}`);
  });

  it.each(SIGN_IN_FAILURES)("signIn.error.%s exists in en and fr-CA", (reason) => {
    expect(en).toHaveProperty(`signIn.error.${reason}`);
    expect(frCA).toHaveProperty(`signIn.error.${reason}`);
  });

  it("the deletion confirmation says what is deleted, that it is permanent, and what stays on the device (en and fr-CA)", () => {
    expect(en["me.delete.confirmBody"]).toMatch(/permanently/i);
    expect(en["me.delete.confirmBody"]).toMatch(/cannot be undone/i);
    expect(en["me.delete.confirmBody"]).toMatch(/age check/i);
    expect(frCA["me.delete.confirmBody"]).toMatch(/définitivement/i);
    expect(frCA["me.delete.confirmBody"]).toMatch(/irréversible/i);
    expect(frCA["me.delete.confirmBody"]).toMatch(/vérification d'âge/i);
    expect(en["me.delete.confirm"]).toBeTruthy();
    expect(frCA["me.delete.confirm"]).toBeTruthy();
  });

  it("the age screen copy still names no cutoff", () => {
    for (const k of Object.keys(en).filter((x) => x.startsWith("ageGate."))) expect(en[k as keyof typeof en]).not.toMatch(/\b1[0-9]\b|\bsixteen\b/i);
  });
});
