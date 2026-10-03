/**
 * Linking Sign in with Apple to the signed-in account (Me → Sign-in methods), i.e. the §3.4 rules as the client sees them
 * (`supabase/functions/_shared/signin/methods-handler.ts` is the enforcement; this is the UI-side state machine). P4 AT 18.
 *
 * ```
 * idle ──start()──▶ working ──▶ linked                           the Apple identity is on THIS account            (200 linkedTo "self")
 *                          ├──▶ linked (elsewhere)                the identity went to the account whose mailbox was proven (200 "proven_account")
 *                          ├──▶ needs_proof ──sendCode()──▶ code_sent ──submitCode()──▶ working ─▶ linked | code_sent (wrong code) | failed
 *                          │        409 email_proof_required: an account with the Apple address exists. NOTHING is sent until the player asks.
 *                          └──▶ failed(reason)                    everything else
 * ```
 *
 * **Never auto-link.** After the 409 the machine STOPS in `needs_proof`. The one-time code is requested only by `sendCode()` and the
 * proof is submitted only by `submitCode()`: two explicit player actions, each a method call the screen makes from a button. There is no
 * path from "the emails match" to "linked" that does not pass both. (An Apple private-relay address never gets that far: the server answers
 * 409 `email_belongs_to_another_account` and the player sees `relay_belongs_to_other_account`.)
 *
 * The code goes to the address in the (server-verified) Apple token, via Supabase Auth with `createUser: false` (it can only reach an existing
 * account); the player types it and WE send it to the server (`emailProof.code`), which verifies it. The client never verifies it itself,
 * so it never signs in as the other account.
 *
 * Failure semantics after a wrong code (422 `email_proof_invalid`, `attemptsRemaining`): the server checks the proof BEFORE exchanging the
 * authorization code, so the same Apple credential is still good and the player may try again (kept in memory only, dropped on any
 * terminal state). Any failure after the proof may have spent the single-use authorization code, so those are terminal and the player restarts.
 */
import type { AgeGate } from "../age";
import { ApiError } from "../api/errors";
import { attemptsDetailsSchema } from "../api/schemas";
import type { ApiClient, SignInMethod } from "../api/types";
import { AuthError, type AuthService } from "../auth/types";
import type { AppleAdapter } from "../signin/adapters";
import { checkEligible } from "../signin/flow";
import { EMAIL_RE, emailFromIdentityToken } from "../signin/jwt";
import { createNonce, type RandomBytes } from "../signin/nonce";

/** Every reason the linking flow can fail. Each has `methods.error.<reason>` copy in both languages (`test/i18n.test.ts`). */
export const LINK_FAILURES = [
  "provider_already_linked", // 409: a different Apple ID is already linked to this account
  "identity_conflict", // 409: this Apple ID is already linked to another account
  "relay_belongs_to_other_account", // 409 email_belongs_to_another_account
  "proof_refused", // 409 email_proof_refused / email_proof_mismatch: request a new code and start again
  "invalid_identity_token", // 422
  "authorization_code_rejected", // 422
  "authorization_code_mismatch", // 422
  "rate_limited", // 429 (link: 10/user/h; proof: 5 failures per address per hour)
  "not_supported", // 501
  "not_available", // 502 / 503 / provider_not_configured / kek_unavailable
  "network",
  "unauthenticated",
  "bad_code",
  "no_email", // the token carries no usable address and the player has not given one
  "unknown_user", // Auth has no account at that address (it cannot be proven)
  "unknown",
] as const;
export type LinkFailure = (typeof LINK_FAILURES)[number];

export type LinkState =
  | { step: "idle" }
  | { step: "working" }
  | { step: "needs_proof"; email: string | null; notice: LinkFailure | null; retryAfterSeconds: number | null }
  | { step: "code_sent"; email: string; attemptsRemaining: number | null; wrongCode: boolean; notice: LinkFailure | null; retryAfterSeconds: number | null }
  | { step: "linked"; where: "self" | "proven_account"; methods: SignInMethod[] | null }
  | { step: "failed"; reason: LinkFailure; retryAfterSeconds: number | null }
  | { step: "age_required" }
  | { step: "blocked" }
  | { step: "cancelled" }
  | { step: "unsupported_platform" };

export interface LinkDeps {
  gate: AgeGate;
  auth: Pick<AuthService, "requestEmailCode">;
  api: Pick<ApiClient, "linkSignInMethod">;
  apple: AppleAdapter;
  random: RandomBytes;
}

export function linkFailureFrom(e: unknown): { reason: LinkFailure; retryAfterSeconds: number | null } {
  if (e instanceof ApiError) {
    const r = e.retryAfterSeconds;
    switch (e.kind) {
      case "network":
        return { reason: "network", retryAfterSeconds: null };
      case "unauthenticated":
        return { reason: "unauthenticated", retryAfterSeconds: null };
      case "rate_limited":
        return { reason: "rate_limited", retryAfterSeconds: r };
      case "not_supported":
        return { reason: "not_supported", retryAfterSeconds: null };
      case "unavailable":
        return { reason: "not_available", retryAfterSeconds: null };
      case "conflict":
        if (e.code === "provider_already_linked") return { reason: "provider_already_linked", retryAfterSeconds: null };
        if (e.code === "identity_conflict") return { reason: "identity_conflict", retryAfterSeconds: null };
        if (e.code === "email_belongs_to_another_account") return { reason: "relay_belongs_to_other_account", retryAfterSeconds: null };
        if (e.code === "email_proof_refused" || e.code === "email_proof_mismatch") return { reason: "proof_refused", retryAfterSeconds: null };
        return { reason: "unknown", retryAfterSeconds: null };
      case "rejected":
        if (e.code === "invalid_identity_token") return { reason: "invalid_identity_token", retryAfterSeconds: null };
        if (e.code === "authorization_code_rejected") return { reason: "authorization_code_rejected", retryAfterSeconds: null };
        if (e.code === "authorization_code_mismatch") return { reason: "authorization_code_mismatch", retryAfterSeconds: null };
        return { reason: "unknown", retryAfterSeconds: null };
      default:
        if (e.status === 503 || e.code === "provider_not_configured" || e.code === "kek_unavailable") return { reason: "not_available", retryAfterSeconds: null };
        return { reason: "unknown", retryAfterSeconds: null };
    }
  }
  if (e instanceof AuthError) {
    if (e.kind === "network") return { reason: "network", retryAfterSeconds: null };
    if (e.kind === "rate_limited") return { reason: "rate_limited", retryAfterSeconds: null };
    if (e.kind === "unknown_user") return { reason: "unknown_user", retryAfterSeconds: null };
  }
  return { reason: "unknown", retryAfterSeconds: null };
}

interface Held {
  identityToken: string;
  authorizationCode: string;
  nonceRaw: string;
}

export class AppleLinkFlow {
  private s: LinkState = { step: "idle" };
  private held: Held | null = null;
  private readonly listeners = new Set<(s: LinkState) => void>();

  constructor(private readonly deps: LinkDeps) {}

  get state(): LinkState {
    return this.s;
  }

  subscribe(l: (s: LinkState) => void): () => void {
    this.listeners.add(l);
    return () => void this.listeners.delete(l);
  }

  private set(s: LinkState): void {
    this.s = s;
    if (s.step !== "needs_proof" && s.step !== "code_sent" && s.step !== "working") this.held = null; // never keep a credential past a terminal state
    for (const l of [...this.listeners]) l(s);
  }

  /** Player tapped "Link Apple". Shows Apple's sheet, then asks the server to link. Valid from idle and from any terminal state. */
  async start(): Promise<LinkState> {
    if (this.s.step === "working") return this.s;
    this.held = null;
    this.set({ step: "working" });
    const eligible = await checkEligible(this.deps.gate);
    if (!eligible.ok) {
      this.set({ step: eligible.status });
      return this.s;
    }
    if ((await this.deps.apple.availability()) !== "available") {
      this.set({ step: "unsupported_platform" });
      return this.s;
    }
    const nonce = createNonce(this.deps.random);
    let result;
    try {
      result = await this.deps.apple.authenticate(nonce.hashed);
    } catch {
      this.set({ step: "failed", reason: "unknown", retryAfterSeconds: null });
      return this.s;
    }
    if (result.status === "cancelled") {
      this.set({ step: "cancelled" });
      return this.s;
    }
    this.held = { identityToken: result.identityToken, authorizationCode: result.authorizationCode, nonceRaw: nonce.raw };
    return this.submit(null);
  }

  /** Player chose "Send me a code" (after `needs_proof`). Sends the one-time code to the address in the Apple token (or the one the player typed). */
  async sendCode(typedEmail?: string): Promise<LinkState> {
    const cur = this.s;
    if ((cur.step !== "needs_proof" && cur.step !== "code_sent") || this.held === null) return this.s;
    const email = (typedEmail?.trim() || cur.email) ?? null;
    if (email === null || !EMAIL_RE.test(email)) {
      this.set({ step: "needs_proof", email: cur.email, notice: "no_email", retryAfterSeconds: null });
      return this.s;
    }
    try {
      await this.deps.auth.requestEmailCode(email, { createUser: false });
    } catch (e) {
      const f = linkFailureFrom(e);
      this.set({ step: "needs_proof", email, notice: f.reason, retryAfterSeconds: f.retryAfterSeconds });
      return this.s;
    }
    this.set({ step: "code_sent", email, attemptsRemaining: null, wrongCode: false, notice: null, retryAfterSeconds: null });
    return this.s;
  }

  /** Player typed the code and tapped "Link". The ONLY place `emailProof` is ever sent. */
  async submitCode(code: string): Promise<LinkState> {
    const cur = this.s;
    if (cur.step !== "code_sent" || this.held === null) return this.s;
    const token = code.trim();
    if (!/^[0-9]{6,10}$/.test(token)) {
      this.set({ ...cur, wrongCode: false, notice: "bad_code" });
      return this.s;
    }
    return this.submit({ code: token }, cur);
  }

  cancel(): LinkState {
    this.set({ step: "cancelled" });
    return this.s;
  }

  private async submit(emailProof: { code: string } | null, from?: Extract<LinkState, { step: "code_sent" }>): Promise<LinkState> {
    const held = this.held;
    if (held === null) return this.s;
    const email = from?.email ?? emailFromIdentityToken(held.identityToken);
    this.set({ step: "working" }); // `set` keeps the credential while a proof can still be retried (working / needs_proof / code_sent)
    try {
      const r = await this.deps.api.linkSignInMethod({
        provider: "apple",
        identityToken: held.identityToken,
        authorizationCode: held.authorizationCode,
        nonce: held.nonceRaw,
        ...(emailProof ? { emailProof } : {}),
      });
      this.set({ step: "linked", where: r.linkedTo, methods: r.methods });
    } catch (e) {
      if (e instanceof ApiError && e.kind === "conflict" && e.code === "email_proof_required" && emailProof === null) {
        // The rule fires: stop and wait for the player. Nothing has been sent anywhere.
        this.set({ step: "needs_proof", email, notice: null, retryAfterSeconds: null });
      } else if (e instanceof ApiError && e.code === "email_proof_invalid" && from) {
        const d = attemptsDetailsSchema.safeParse(e.details);
        this.set({ step: "code_sent", email: from.email, attemptsRemaining: d.success ? d.data.attemptsRemaining : null, wrongCode: true, notice: null, retryAfterSeconds: null });
      } else if (e instanceof ApiError && e.kind === "rate_limited" && from) {
        // 5 failed proofs per address per hour: the credential is still unspent, but the lockout is an hour: show it, keep the state.
        this.set({ ...from, wrongCode: false, notice: "rate_limited", retryAfterSeconds: e.retryAfterSeconds });
      } else {
        const f = linkFailureFrom(e);
        this.set({ step: "failed", reason: f.reason, retryAfterSeconds: f.retryAfterSeconds });
      }
    }
    return this.s;
  }
}
