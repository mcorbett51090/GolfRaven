// supabase/functions/_shared/signin/methods-handler.ts
//
// The pure, DI'd core of `me-signin-methods` (build plan §4.7.1a inventory: "me-signin-methods ... link or unlink Apple /
// Google / email under the §3.4 rules, and capture the provider token for revocation; O12"). Everything outside the process
// (the database, Apple, Supabase Auth's OTP check, the clock) arrives through `SigninDeps`.
//
// THE §3.4 ACCOUNT-LINKING RULES, and where each one is enforced
//   (1) one account per verified email   -> findAccountByEmail on the Apple token's (verified) email; a match with ANOTHER
//                                           account is never merged (below). The database also refuses to move or duplicate an
//                                           identity (private.signin_link_identity, 23505 -> 409).
//   (2) a social sign-in whose email matches an existing account is NEVER auto-linked; the player proves the existing account
//       with an email OTP to that address first
//                                        -> a link request whose Apple email belongs to another account is refused with 409
//                                           `email_proof_required` unless it carries `emailProof.code`; the code is checked by the
//                                           injected EmailOtpVerifier against THAT account's address, failures are counted (5 per
//                                           target email per hour, 429 after) and only on a verified proof is the identity
//                                           linked — to the account the proof was for.
//   (3) an Apple private-relay address is its own email
//                                        -> it is stored as given and flagged; a relay address never takes the OTP-proof path (it
//                                           is not a mailbox the player reads as that account): a relay account links only from
//                                           this endpoint while signed in, to the CALLER.
//   (4) a method can be unlinked only while another remains
//                                        -> private.signin_unlink_identity (one transaction, per-account advisory lock) raises
//                                           55000 and the repo maps it to 422 `last_sign_in_method`.
//   (5) partner roles still need their passkey: not this endpoint's concern (§3.6); nothing here grants or reads a role.
//
// What is deliberately NOT done here: the 16+ age screen (O18) runs on the client before any provider is called; the rate limit
// of 10/user/hour is applied by the entrypoint before a transaction opens (privileged.ts#hitRateLimitForActor's own ordering rule).

import { AppleGrantError, AppleTokenError, NotConfiguredError, VendorUnavailableError } from "./errors.ts";
import { encryptToken } from "./envelope.ts";
import { sha256Hex } from "./bytes.ts";
import { HttpError, Errors } from "../http.ts";
import type { LinkRequest, UnlinkRequest } from "./request-shape.ts";
import { runRevocationsBestEffort, type RevocationDeps, type RevocationOutcome } from "./revocation.ts";
import { OTP_FAILURES_PER_EMAIL_PER_HOUR, type AppleSigninPort, type EmailOtpVerifier, type OtpFailureCounter, type SigninMethodRow, type SigninRepo } from "./types.ts";

export interface SigninDeps {
  /** Runs `op` inside ONE transaction scoped to the authenticated caller (privileged.ts#withOwnership). */
  withRepo<T>(op: (repo: SigninRepo) => Promise<T>): Promise<T>;
  otpFailures: OtpFailureCounter;
  /** `null` = Apple is not configured: every Apple operation answers 503, never a fallback. */
  apple: AppleSigninPort | null;
  emailOtp: EmailOtpVerifier | null;
  revocation: RevocationDeps;
  log(event: Record<string, unknown>): void;
}

export interface MethodView {
  provider: string;
  linkedAt: string;
  isPrivateRelay: boolean;
  /** false for the only remaining method (unlinking it is a 422). */
  canUnlink: boolean;
}

function view(methods: SigninMethodRow[]): MethodView[] {
  return methods.map((m) => ({ provider: m.provider, linkedAt: m.linkedAt, isPrivateRelay: m.isPrivateRelay, canUnlink: methods.length > 1 }));
}

export async function handleListMethods(deps: SigninDeps): Promise<{ methods: MethodView[] }> {
  const methods = await deps.withRepo((repo) => repo.listMethods());
  return { methods: view(methods) };
}

// ---------------------------------------------------------------------------------------------------------------------
// link
// ---------------------------------------------------------------------------------------------------------------------
export interface LinkResult {
  linked: { provider: "apple"; created: boolean; isPrivateRelay: boolean };
  /** 'self': linked to the caller's account. 'proven_account': the Apple email belongs to ANOTHER account whose mailbox the
   * caller proved by OTP, so the identity was linked THERE; the client signs in with Apple next and lands in that account. */
  linkedTo: "self" | "proven_account";
  /** The caller's methods after the change; null when the identity went to another account. */
  methods: MethodView[] | null;
}

const notConfigured = (what: string) => new HttpError(503, "provider_not_configured", `${what} sign-in is not configured on this server`);
const upstream = () => new HttpError(502, "upstream_unavailable", "the sign-in provider could not be reached; try again");

function mapProviderError(e: unknown): unknown {
  if (e instanceof AppleTokenError) return Errors.unprocessable("invalid_identity_token", "the Apple identity token did not verify", { reason: e.reason });
  if (e instanceof AppleGrantError) return Errors.unprocessable("authorization_code_rejected", "Apple rejected the authorization code");
  if (e instanceof NotConfiguredError) return notConfigured("Apple");
  if (e instanceof VendorUnavailableError) return upstream();
  return e;
}

export async function handleLinkProvider(req: LinkRequest, actorUid: string, deps: SigninDeps): Promise<LinkResult> {
  if (req.provider === "google") {
    // ⚠ TODO(P4): Google identity-token verification and the authorization-code exchange are not built (no client secret and no
    // native-flow decision yet); see google-client.ts. Until then no Google grant is ever created, so nothing could be revoked.
    throw new HttpError(501, "provider_not_supported", "linking Google is not available yet");
  }
  const apple = deps.apple;
  if (apple === null) throw notConfigured("Apple");

  // 1. The identity token: signature, issuer, audience, expiry, nonce. Nothing is read from the database before it verifies.
  let identity;
  try {
    identity = await apple.verifyIdentityToken(req.identityToken, req.nonce);
  } catch (e) {
    throw mapProviderError(e);
  }
  // An unverified email claim is not an email we act on (never matched, never stored).
  const email = identity.emailVerified ? identity.email : null;

  // 2. What the database says about the caller and about the email.
  const state = await deps.withRepo(async (repo) => ({
    methods: await repo.listMethods(),
    owner: email !== null ? await repo.findAccountByEmail(email) : null,
    crossAccountLink: repo.crossAccountLink,
  }));
  const existingApple = state.methods.find((m) => m.provider === "apple");
  if (existingApple && existingApple.subject !== identity.subject) {
    throw Errors.conflict("provider_already_linked", "this account already has a different Apple ID linked; unlink it first");
  }

  // 3. Rules (1)-(3): another account holds this email -> never auto-link; OTP proof first.
  let targetUid = actorUid;
  if (email !== null && state.owner !== null && state.owner !== actorUid) {
    if (identity.isPrivateRelay) {
      throw Errors.conflict("email_belongs_to_another_account", "that Apple relay address is already the sign-in email of another account");
    }
    if (!state.crossAccountLink) {
      // `edge` mode has no definer that attaches an identity to another account (edge-role-design.md §12). Say so BEFORE inviting a
      // proof, so no OTP is requested, counted or consumed and no authorization code is exchanged for a link that cannot happen.
      throw new HttpError(501, "email_proof_link_unavailable", "linking this Apple ID to the existing account is not available in this mode");
    }
    if (!req.emailProof) {
      throw Errors.conflict("email_proof_required", "an account with this email already exists; prove it with a code sent to that address", { emailProofRequired: true });
    }
    targetUid = await proveEmail(email, req.emailProof.code, state.owner, deps);
  }

  // 4. The authorization code -> the refresh token, and the proof that the code belongs to the SAME Apple user as the token.
  let grant;
  try {
    grant = await apple.exchangeAuthorizationCode(req.authorizationCode);
  } catch (e) {
    throw mapProviderError(e);
  }
  if (grant.subject !== identity.subject) {
    await bestEffortRevoke(apple, grant.refreshToken, deps);
    throw Errors.unprocessable("authorization_code_mismatch", "the authorization code does not belong to the signed-in Apple user");
  }

  // 5. Envelope-encrypt the refresh token under the newest Vault KEK. (The plaintext exists only in this function's scope.)
  let envelope;
  try {
    const kek = await deps.withRepo((repo) => repo.currentKek());
    envelope = await encryptToken(grant.refreshToken, "apple", kek);
  } catch (e) {
    await bestEffortRevoke(apple, grant.refreshToken, deps);
    throw e instanceof NotConfiguredError ? new HttpError(503, "kek_unavailable", "the token-encryption key is not available") : e;
  }

  // 6. One transaction: the identity and its grant, together or not at all.
  let created: boolean;
  try {
    created = await deps.withRepo(async (repo) => {
      const made = await repo.linkIdentity(targetUid, {
        provider: "apple",
        subject: identity.subject,
        email,
        emailVerified: identity.emailVerified,
        isPrivateRelay: identity.isPrivateRelay,
      });
      await repo.storeToken(targetUid, "apple", envelope);
      return made;
    });
  } catch (e) {
    // The grant exists at Apple but we could not record it: do not leave a live token nobody can revoke.
    await bestEffortRevoke(apple, grant.refreshToken, deps);
    throw e;
  }

  deps.log({ event: "signin_link", provider: "apple", created, to: targetUid === actorUid ? "self" : "proven_account", relay: identity.isPrivateRelay });
  const methods = targetUid === actorUid ? view(await deps.withRepo((repo) => repo.listMethods())) : null;
  return { linked: { provider: "apple", created, isPrivateRelay: identity.isPrivateRelay }, linkedTo: targetUid === actorUid ? "self" : "proven_account", methods };
}

/** §3.4 rule 2 + §4.7 item 8: an email OTP to the target address, at most 5 failures per target email per hour. Returns the
 * account id the proof was for. */
async function proveEmail(email: string, code: string, ownerUid: string, deps: SigninDeps): Promise<string> {
  const hash = await sha256Hex(email.trim().toLowerCase());
  if (deps.emailOtp === null) throw notConfigured("Email proof");
  // The attempt is TAKEN before the code is checked, atomically (cap check + increment in one statement), so N parallel wrong proofs
  // cannot all pass a read of the count and reach the verifier (security gate F3: check-then-act let 20 through). It is given back only
  // when the proof succeeded or never produced a verdict.
  const used = await deps.otpFailures.reserve(hash);
  if (used === null) {
    throw Errors.tooManyRequests("too many failed email proofs for this address; try again in an hour", 3600);
  }
  const giveBack = async () => {
    try {
      await deps.otpFailures.release(hash);
    } catch {
      // A release that fails leaves the attempt charged: the safe direction.
    }
  };
  let result;
  try {
    result = await deps.emailOtp.verify(email, code);
  } catch {
    // A transport failure says nothing about the code: not counted against the address.
    await giveBack();
    throw upstream();
  }
  if (!result.ok) {
    throw Errors.unprocessable("email_proof_invalid", "that code is not valid", { attemptsRemaining: Math.max(0, OTP_FAILURES_PER_EMAIL_PER_HOUR - used) });
  }
  await giveBack();
  if (result.userId !== ownerUid) {
    // The address changed hands between the lookup and the proof. Refuse; never link to a different account than was looked up.
    throw Errors.conflict("email_proof_mismatch", "the proven account is not the account that was looked up; try again");
  }
  return result.userId;
}

async function bestEffortRevoke(apple: AppleSigninPort, refreshToken: string, deps: SigninDeps): Promise<void> {
  try {
    await apple.revokeRefreshToken(refreshToken);
  } catch (e) {
    deps.log({ event: "signin_orphan_grant", provider: "apple", note: "could not revoke a grant that was not recorded", error: e instanceof VendorUnavailableError ? e.code : "unexpected" });
  }
}

// ---------------------------------------------------------------------------------------------------------------------
// unlink
// ---------------------------------------------------------------------------------------------------------------------
export interface UnlinkResult {
  methods: MethodView[];
  /** The provider-grant revocation attempted right after the unlink (empty for a method with no stored grant). */
  revocation: RevocationOutcome[];
}

export async function handleUnlinkProvider(req: UnlinkRequest, deps: SigninDeps): Promise<UnlinkResult> {
  // The database enforces rule (4) and "someone else's method is not yours" in one transaction: 422 / 404 come out of the repo.
  const queueIds = await deps.withRepo((repo) => repo.unlinkIdentity(req.provider));
  const revocation = await runRevocationsBestEffort(deps.revocation, queueIds.map((queueId) => ({ queueId, provider: req.provider })));
  const methods = await deps.withRepo((repo) => repo.listMethods());
  return { methods: view(methods), revocation };
}
