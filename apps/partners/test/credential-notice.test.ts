/**
 * §93 U1 credential-add blocking interstitial: after sign-in, unacked notices replace home until ack (A0)
 * or revoke+ack (A2). Forced first PIN still wins when both apply.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPartnerApi } from "../src/api/client";
import { createController, type AppState, type SignedInState } from "../src/app/controller";
import { installStorageSpies, type StorageSpies } from "./support/storage-spies";
import { API_BASE, makeWorld } from "./support/world";

const PIN = "7391";
const EXTRA_CRED = "22222222-2222-4222-8222-222222222222";
const NOTICE_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const NOTICE_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const EXTRA_CRED_B = "33333333-3333-4333-8333-333333333333";

async function setup(opts: { seedNotice?: boolean | { noticeId?: string; credentialId?: string; label?: string } } = {}) {
  const w = makeWorld();
  await w.server.seedPin(PIN);
  if (opts.seedNotice === true) w.server.seedCredentialAddNotice({ noticeId: NOTICE_A, credentialId: EXTRA_CRED, label: "Passkey · 22222222" });
  else if (opts.seedNotice !== undefined && opts.seedNotice !== false) w.server.seedCredentialAddNotice(opts.seedNotice);
  const api = createPartnerApi({ baseUrl: API_BASE, fetch: w.fetch });
  const controller = createController({ api, webauthn: { credentials: w.auth.credentials, supported: true } });
  const states: AppState[] = [];
  controller.subscribe((s) => states.push(s));
  await controller.signIn();
  return { w, api, controller, states };
}

const home = (c: Awaited<ReturnType<typeof setup>>["controller"]): SignedInState => {
  const s = c.getState();
  if (s.screen !== "signed-in") throw new Error(`expected signed-in, got ${s.screen}`);
  return s;
};

async function until(cond: () => boolean, label: string, ms = 2000): Promise<void> {
  const steps = Math.max(1, Math.ceil(ms / 5));
  for (let i = 0; i < steps; i += 1) {
    if (cond()) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error(label);
}

let spies: StorageSpies;
beforeEach(() => {
  spies = installStorageSpies();
});
afterEach(() => spies.restore());

describe("§93 credential-add notice interstitial", () => {
  it("does not open a panel when there are no unacked notices", async () => {
    const s = await setup();
    expect(home(s.controller).panel).toBeNull();
    expect(s.w.server.log.some((r) => r.method === "GET" && r.path.endsWith("/partner-members/credentials/notices"))).toBe(true);
  });

  it("opens a blocking panel after sign-in when a notice is pending", async () => {
    const s = await setup({ seedNotice: true });
    expect(home(s.controller).panel).toMatchObject({
      kind: "credential-add-notice",
      notice: { noticeId: NOTICE_A, credentialId: EXTRA_CRED, label: "Passkey · 22222222" },
      busy: false,
    });
    s.controller.closePanel();
    expect(home(s.controller).panel?.kind).toBe("credential-add-notice");
  });

  it("ack posts and returns to home when no more notices remain", async () => {
    const s = await setup({ seedNotice: true });
    await s.controller.ackCredentialAddNotice();
    expect(home(s.controller).panel).toBeNull();
    expect(home(s.controller).notice).toEqual({ kind: "credential-notice-acked" });
    const acks = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith(`/partner-members/credentials/notices/${NOTICE_A}/ack`));
    expect(acks).toHaveLength(1);
  });

  it("shows the next notice after ack when several are pending", async () => {
    const s = await setup({
      seedNotice: { noticeId: NOTICE_A, credentialId: EXTRA_CRED, label: "First" },
    });
    s.w.server.seedCredentialAddNotice({ noticeId: NOTICE_B, credentialId: EXTRA_CRED_B, label: "Second" });
    // re-open via a fresh list: current panel still shows First; ack advances
    await s.controller.ackCredentialAddNotice();
    expect(home(s.controller).panel).toMatchObject({
      kind: "credential-add-notice",
      notice: { noticeId: NOTICE_B, label: "Second" },
    });
    await s.controller.ackCredentialAddNotice();
    expect(home(s.controller).panel).toBeNull();
  });

  it("revoke runs reauth + A2 PIN, deletes the credential, acks, and clears the panel", async () => {
    const s = await setup({ seedNotice: true });
    const pending = s.controller.revokeCredentialAddNotice();
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened for notice revoke");
    expect(home(s.controller).panel).toMatchObject({ kind: "pin-prompt", actionClass: "A2" });
    s.controller.submitPin(PIN);
    await pending;

    expect(home(s.controller).panel).toBeNull();
    expect(home(s.controller).notice).toEqual({ kind: "credential-revoked" });
    expect(s.w.server.log.some((r) => r.method === "POST" && r.path.endsWith("/reauth/options"))).toBe(true);
    const deletes = s.w.server.log.filter((r) => r.method === "DELETE" && r.path.endsWith(`/partner-members/credentials/${EXTRA_CRED}`));
    expect(deletes).toHaveLength(1);
    const acks = s.w.server.log.filter((r) => r.method === "POST" && r.path.endsWith(`/partner-members/credentials/notices/${NOTICE_A}/ack`));
    expect(acks).toHaveLength(1);
  });

  it("restores the interstitial when PIN step-up is cancelled", async () => {
    const s = await setup({ seedNotice: true });
    const pending = s.controller.revokeCredentialAddNotice();
    await until(() => home(s.controller).panel?.kind === "pin-prompt", "PIN prompt never opened");
    s.controller.cancelPin();
    await pending;
    expect(home(s.controller).panel).toMatchObject({
      kind: "credential-add-notice",
      notice: { noticeId: NOTICE_A },
      panelNotice: { kind: "error", message: { key: "error.cancelled" } },
    });
  });

  it("Lock still ends the session while the interstitial is open", async () => {
    const s = await setup({ seedNotice: true });
    expect(home(s.controller).panel?.kind).toBe("credential-add-notice");
    await s.controller.lock();
    expect(s.controller.getState().screen).toBe("signed-out");
    expect(s.api.hasSession()).toBe(false);
  });
});
