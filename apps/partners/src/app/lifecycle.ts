/**
 * Page lifecycle (threat model: a shared shop iPad; the browser must never hold a live bearer, or show a signed-in screen, when the user believes the
 * page is gone).
 *
 * A page that is navigated away from can be kept whole in the browser's back/forward cache and restored by Back with every variable and every node
 * as it was: a signed-in screen and a live token. So:
 *
 *   - `pagehide` ends the session: the token is wiped and the listeners are told at once, then a keepalive `sign-out` (best effort: a request that
 *     is allowed to outlive the page) revokes it on the server. This runs whether or not the page is about to enter the bfcache.
 *   - `pageshow` with `persisted` (a restore from the bfcache) forces the signed-out state: nothing a restored page shows or holds is trusted.
 *
 * The page itself is also served `Cache-Control: no-store` (scripts/lib/csp.mjs), which keeps it out of the HTTP cache and, in Chromium, out of the
 * bfcache; this module is the part that does not depend on the browser honouring that.
 */

import type { PartnerApi } from "../api/client";
import type { AppController } from "./controller";

export interface PageEvents {
  addEventListener(type: "pagehide" | "pageshow", listener: (ev: Event) => void): void;
}

export function installPageLifecycle(target: PageEvents, api: PartnerApi, controller: AppController): void {
  target.addEventListener("pagehide", () => {
    controller.reset({ keepalive: true });
    api.forgetSession();
  });
  target.addEventListener("pageshow", (ev) => {
    if ((ev as Event & { persisted?: boolean }).persisted === true) {
      controller.reset(); // wipes, shows signed-out and revokes what the restored page was holding
      api.forgetSession(); // a no-op once reset() has run; kept so the token cannot survive a controller that did not
    }
  });
}
