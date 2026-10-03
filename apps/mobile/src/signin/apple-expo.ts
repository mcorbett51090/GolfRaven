/**
 * `AppleAdapter` over `expo-apple-authentication` 57.0.2. Imported only by the composition root. Type-checked against the package's `.d.ts`;
 * never run on a device `[unverified]` (it cannot run off iOS, and this environment has no iOS device or simulator).
 *
 * Requests the EMAIL scope only (no name: the app does not need it). `nonce` is passed through as given: per the package's `.d.ts` it is
 * "an arbitrary string that is used to prevent replay attacks"; the flow passes `SHA-256(raw)` and the server checks the token's claim against
 * that hash `[Apple embedding the string unchanged: the server's documented assumption, unverified until a real iOS run]`.
 */
import * as AppleAuthentication from "expo-apple-authentication";
import type { AppleAdapter } from "./adapters";

export function createExpoAppleAdapter(platform: string): AppleAdapter {
  return {
    async availability() {
      if (platform !== "ios") return "unsupported_platform";
      return (await AppleAuthentication.isAvailableAsync()) ? "available" : "unsupported_platform";
    },
    async authenticate(hashedNonce) {
      try {
        const c = await AppleAuthentication.signInAsync({ requestedScopes: [AppleAuthentication.AppleAuthenticationScope.EMAIL], nonce: hashedNonce });
        if (!c.identityToken || !c.authorizationCode) throw new Error("Apple returned no identity token or authorization code");
        return { status: "ok", identityToken: c.identityToken, authorizationCode: c.authorizationCode };
      } catch (e) {
        if ((e as { code?: unknown } | null)?.code === "ERR_REQUEST_CANCELED") return { status: "cancelled" };
        throw e;
      }
    },
  };
}
