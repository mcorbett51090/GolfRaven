/**
 * The invite link (docs/security/partner-auth-design.md 6.1 / §89): `https://partners.<tld>/invite#<gr_inv_ token>`.
 * The token rides in the URL FRAGMENT, which a browser never sends to a server, so no CDN or access log holds it and a
 * mail scanner that prefetches the link cannot consume it.
 *
 * `consumeInviteLink` runs at load and on `hashchange`: if the fragment holds a token it is REMOVED from the address bar
 * (`history.replaceState`, no navigation, no new history entry). Signed-out → enrol flow (branch N). Signed-in with a
 * `gr_inv_` → branch E hold (join org). Enrolment tokens while signed in are cleared without starting enrol.
 */

import type { AppController } from "./controller";
import { extractToken } from "./enrol-flow";

export interface LinkEnv {
  readonly location: Pick<Location, "hash" | "pathname" | "search">;
  readonly history: Pick<History, "replaceState">;
}

/** True when the fragment held a token (it is then cleared and the flow started, or held for branch E). */
export function consumeInviteLink(env: LinkEnv, controller: AppController): boolean {
  const fragment = env.location.hash.startsWith("#") ? env.location.hash.slice(1) : env.location.hash;
  const found = extractToken(fragment);
  if (found === null) return false;
  env.history.replaceState(null, "", env.location.pathname + env.location.search);
  const screen = controller.getState().screen;
  if (screen === "signed-in") {
    if (found.kind === "invite") controller.holdInviteAccept(found.token);
    return true;
  }
  if (screen === "enrol") controller.cancelEnrol();
  controller.startEnrol({ token: fragment });
  return true;
}
