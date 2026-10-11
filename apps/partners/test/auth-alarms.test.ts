/**
 * §96 Review auth-alarms labels: closed kinds → catalogue; unknown stays raw; subject prefix from detail.
 */
import { describe, expect, it } from "vitest";
import { authAlarmKindLabel, authAlarmSubjectPrefix } from "../src/ui/auth-alarms";

describe("authAlarmKindLabel", () => {
  it("maps every closed kind in EN and fr-CA", () => {
    expect(authAlarmKindLabel("en", "signature_invalid")).toBe("Invalid signature");
    expect(authAlarmKindLabel("fr-CA", "signature_invalid")).toBe("Signature invalide");
    expect(authAlarmKindLabel("en", "totp_reset")).toBe("TOTP reset");
    expect(authAlarmKindLabel("fr-CA", "totp_reset")).toBe("Réinitialisation TOTP");
    expect(authAlarmKindLabel("en", "credential_add")).toBe("Passkey added");
    expect(authAlarmKindLabel("en", "rate_member")).toBe("Member call rate");
    expect(authAlarmKindLabel("en", "pin_locked")).toBe("PIN locked");
    expect(authAlarmKindLabel("fr-CA", "pin_locked")).toBe("NIP verrouillé");
    expect(authAlarmKindLabel("en", "pin_reset")).toBe("PIN reset");
    expect(authAlarmKindLabel("fr-CA", "pin_reset")).toBe("Réinitialisation du NIP");
    expect(authAlarmKindLabel("en", "member_recover")).toBe("Member recover");
    expect(authAlarmKindLabel("fr-CA", "member_recover")).toBe("Récupération de membre");
    expect(authAlarmKindLabel("en", "org_revoke_all")).toBe("Org revoke-all");
    expect(authAlarmKindLabel("fr-CA", "org_revoke_all")).toBe("Révocation globale d'organisation");
    expect(authAlarmKindLabel("en", "member_revoke")).toBe("Member revoke");
    expect(authAlarmKindLabel("fr-CA", "member_revoke")).toBe("Révocation de membre");
    expect(authAlarmKindLabel("en", "credential_revoke")).toBe("Passkey revoked");
    expect(authAlarmKindLabel("fr-CA", "credential_revoke")).toBe("Clé d'accès révoquée");
    expect(authAlarmKindLabel("en", "invite_revoke")).toBe("Invite revoked");
    expect(authAlarmKindLabel("fr-CA", "invite_revoke")).toBe("Invitation révoquée");
    expect(authAlarmKindLabel("en", "enrolment_issue")).toBe("Admin enrolment issued");
    expect(authAlarmKindLabel("fr-CA", "enrolment_issue")).toBe("Inscription admin émise");
    expect(authAlarmKindLabel("en", "invite_create")).toBe("Invite created");
    expect(authAlarmKindLabel("fr-CA", "invite_create")).toBe("Invitation créée");
  });

  it("falls back to the raw kind for an unknown token", () => {
    expect(authAlarmKindLabel("en", "future_kind")).toBe("future_kind");
    expect(authAlarmKindLabel("fr-CA", "future_kind")).toBe("future_kind");
  });
});

describe("authAlarmSubjectPrefix", () => {
  it("returns the first 8 chars of detail.subject, detail.org, or detail.invite", () => {
    expect(authAlarmSubjectPrefix({ subject: "22222222-2222-4222-8222-222222222222", status: "ok" })).toBe("22222222");
    expect(authAlarmSubjectPrefix({ org: "10000000-0000-0000-0000-000000000001", status: "ok" })).toBe("10000000");
    expect(authAlarmSubjectPrefix({ invite: "a5300000-0000-0000-0000-000000000077", status: "ok" })).toBe("a5300000");
  });

  it("returns null when subject/org/invite is missing or not a string", () => {
    expect(authAlarmSubjectPrefix(null)).toBeNull();
    expect(authAlarmSubjectPrefix({ status: "ok" })).toBeNull();
    expect(authAlarmSubjectPrefix({ subject: 1 })).toBeNull();
    expect(authAlarmSubjectPrefix("nope")).toBeNull();
  });
});
