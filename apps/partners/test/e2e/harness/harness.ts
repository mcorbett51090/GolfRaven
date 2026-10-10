/**
 * The Playwright harness page: drives the exported `reauthWithPasskey` helper (no screen uses it in S7a) against the fake partner API, in a real browser
 * under the real CSP. Built only when GOLFRAVEN_PARTNERS_E2E=1 (scripts/build.mjs); a production build scans for it and fails if it is there.
 * Results are written as text into `#out`: `{ ok: true, ... }` or `{ ok: false, kind, status, code }`.
 */
import { createPartnerApi } from "../../../src/api/client";
import { createController } from "../../../src/app/controller";
import { resolveLocale } from "../../../src/i18n";
import { render } from "../../../src/ui/render";
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
    out.textContent = JSON.stringify(isPartnerApiError(e) ? { label, ok: false, kind: e.kind, status: e.status, code: e.code, retryAfterSeconds: e.retryAfterSeconds } : { label, ok: false, kind: "other", name: e instanceof Error ? e.name : "unknown" });
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

/**
 * The real app screens inside this page, mounted on demand (so every other harness cell is unchanged), with a button that stands in for the first A1 screen:
 * it calls `controller.requirePin("A1")` exactly as a screen would and writes the outcome (a grant, or why not) into `#out`.
 */
let controller: ReturnType<typeof createController> | null = null;
on("mount-app", async () => {
  const appRoot = document.getElementById("app") as HTMLElement;
  const appApi = createPartnerApi({ baseUrl: __GR_PARTNERS_API_BASE__ });
  const c = createController({ api: appApi, webauthn: { credentials: navigator.credentials } });
  controller = c;
  const env = { locale: resolveLocale(navigator.languages ?? [navigator.language]), setLocale() {} };
  const draw = () => render(appRoot, c.getState(), c, env);
  c.subscribe(draw);
  draw();
  return { mounted: true };
});
on("request-pin-a1", async () => {
  if (controller === null) throw new Error("mount-app first");
  try {
    const grant = await controller.requirePin("A1");
    return { granted: grant.actionClass };
  } catch (e) {
    return { stepUp: e instanceof Error && "kind" in e ? String((e as { kind: unknown }).kind) : "other" };
  }
});
