/**
 * The native sign-in modules behind interfaces (so the flow state machines are tested without them, and so a build without a module
 * degrades to an explicit "not available" instead of a crash).
 *
 * Both adapters receive ONLY the hashed nonce: the raw nonce never crosses this boundary, so it cannot be sent to Apple or Google by mistake.
 */
export type AppleAuthResult =
  | {
      status: "ok";
      /** The signed identity token (a compact JWT whose `nonce` claim is the hashed nonce we passed). */
      identityToken: string;
      /** Single-use; the server exchanges it for the refresh token it must keep to revoke the grant on deletion (§7.8). */
      authorizationCode: string;
    }
  | { status: "cancelled" };

export interface AppleAdapter {
  /** "unsupported_platform" where there is no native Sign in with Apple (Android: a web flow is follow-up work). */
  availability(): Promise<"available" | "unsupported_platform">;
  /** Shows Apple's sheet. `hashedNonce` is `SHA-256(raw)` as lowercase hex. A failure other than the player cancelling THROWS. */
  authenticate(hashedNonce: string): Promise<AppleAuthResult>;
}

export type GoogleAuthResult = { status: "ok"; idToken: string } | { status: "cancelled" };

export interface GoogleAdapter {
  /** "not_configured": this binary has no native Google sign-in (no package, or no owner-supplied client id). */
  availability(): Promise<"available" | "not_configured">;
  /** `hashedNonce` is what the id token's `nonce` claim must carry. `[unverified: Supabase's expectation for Google's nonce]` */
  authenticate(hashedNonce: string): Promise<GoogleAuthResult>;
}
