/**
 * The Playwright harness page: drives the exported `reauthWithPasskey` helper (no screen uses it in S7a) against the fake partner API, in a real browser
 * under the real CSP. Built only when GOLFRAVEN_PARTNERS_E2E=1 (scripts/build.mjs); a production build scans for it and fails if it is there.
 * Results are written as text into `#out`: `{ ok: true, ... }` or `{ ok: false, kind, status, code }`.
 */
import { createPartnerApi } from "../../../src/api/client";
import { isPartnerApiError } from "../../../src/api/errors";
import { reauthWithPasskey } from "../../../src/auth/reauth";
import { signInWithPasskey } from "../../../src/auth/sign-in";

declare const __GR_PARTNERS_API_BASE__: string;

const api = createPartnerApi({ baseUrl: __GR_PARTNERS_API_BASE__ });
const webauthn = { credentials: navigator.credentials };
const out = document.getElementById("out") as HTMLElement;

async function run(label: string, fn: () => Promise<Record<string, unknown>>): Promise<void> {
  try {
    out.textContent = JSON.stringify({ label, ok: true, ...(await fn()) });
  } catch (e) {
    out.textContent = JSON.stringify(isPartnerApiError(e) ? { label, ok: false, kind: e.kind, status: e.status, code: e.code } : { label, ok: false, kind: "other", name: e instanceof Error ? e.name : "unknown" });
  }
}

const on = (id: string, fn: () => Promise<Record<string, unknown>>) => document.getElementById(id)?.addEventListener("click", () => void run(id, fn));
on("sign-in", async () => ({ ...(await signInWithPasskey(api, webauthn)) }));
on("reauth", async () => ({ ...(await reauthWithPasskey(api, webauthn)) }));
on("session", async () => ({ aal: (await api.session()).aal }));
on("forget", async () => {
  api.forgetSession();
  return { hasSession: api.hasSession() };
});
