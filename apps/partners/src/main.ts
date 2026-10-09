/**
 * Entry point: wires the API client, the controller and the renderer to the page. Nothing here reads or writes any storage API, and nothing is
 * exposed on `window`: the controller and the client live in this module's closure only.
 *
 * `__GR_PARTNERS_API_BASE__` is replaced at build time by esbuild (`scripts/build.mjs`, from `GOLFRAVEN_PARTNERS_API_BASE`).
 */

import { createPartnerApi } from "./api/client";
import { createController } from "./app/controller";
import { consumeInviteLink } from "./app/invite-link";
import { installPageLifecycle } from "./app/lifecycle";
import { LOCALES, resolveLocale, type Locale } from "./i18n";
import { render } from "./ui/render";

declare const __GR_PARTNERS_API_BASE__: string;

const root = document.getElementById("app");
if (root === null) throw new Error("missing #app");

const api = createPartnerApi({ baseUrl: __GR_PARTNERS_API_BASE__ });
const controller = createController({ api, webauthn: { credentials: navigator.credentials } });
const link = { location: window.location, history: window.history };

let locale: Locale = resolveLocale(navigator.languages ?? [navigator.language]);
const env = {
  get locale() {
    return locale;
  },
  setLocale(l: Locale) {
    if (!LOCALES.includes(l)) return;
    locale = l;
    draw();
  },
};

function draw(): void {
  render(root as HTMLElement, controller.getState(), controller, env);
}

controller.subscribe(draw);
installPageLifecycle(window, api, controller);
draw();
// an invite link opens the enrolment screen; the token is read from the fragment and removed from the address bar (invite-link.ts)
consumeInviteLink(link, controller);
window.addEventListener("hashchange", () => void consumeInviteLink(link, controller));
