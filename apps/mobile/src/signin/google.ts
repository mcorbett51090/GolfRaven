/**
 * Google sign-in: the integration layer exists (`GoogleAdapter`, the flow in `flow.ts`), the NATIVE SDK does not.
 *
 * No Expo SDK 57 Google sign-in package is in the lockfile, and adding one (a native module plus an OAuth client created under the
 * organisation's Google account, P0) is an owner decision, so this build ships `notConfiguredGoogle`: the flow answers
 * `{ status: "not_configured" }`, and `offeredProviders` leaves the Google button out. To enable it: add the package (pinned, with its
 * config plugin on the policy allow-list and a reason), implement `GoogleAdapter` over it, and pass it in `runtime/services.ts`.
 * Server side, `link` for Google is still a 501 `provider_not_supported` (no code exchange built), so a Google grant cannot be revoked yet
 * either (server O2); sign-in itself goes through Supabase Auth's id-token exchange.
 */
import type { GoogleAdapter } from "./adapters";

export function notConfiguredGoogle(): GoogleAdapter {
  return {
    availability: () => Promise.resolve("not_configured"),
    authenticate: () => Promise.reject(new Error("Google sign-in is not configured in this build")),
  };
}
