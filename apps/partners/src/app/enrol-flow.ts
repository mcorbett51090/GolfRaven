/**
 * Accepting an invite or an enrolment token (docs/security/partner-auth-design.md 6.1 branch N, 6.4, 6.5; S1.5). DOM-free: the renderer draws
 * `EnrolState`, and this module is the only thing that changes it.
 *
 *   token --requestCode--> code --submitCode--> passkey --createPasskey--> signed-in (panel: the forced first PIN)
 *
 *   1. `accept/start`: the server mails a one-time code to the address ON the invite (the person types no address, so a token holder cannot redirect it).
 *   2. `accept/verify`: the code. The server answers with the create ceremony's options and the binding the next call echoes back.
 *   3. `navigator.credentials.create` (a button press: Safari wants a user gesture, and the options are only good for a few minutes), then
 *      `POST credentials`, which stores the credential and opens the person's FIRST session in one transaction. The token is kept inside the API client.
 *
 * The invite or enrolment token is held in this closure only: it is not in the state, so it is never drawn, and `reset()` / `cancel()` drop it. It is
 * the capability to receive a code for one mailbox, not a session, and it is single-use; it is still treated as a secret.
 *
 * An invite link carries its token in the URL FRAGMENT (`/invite#gr_inv_...`): `main.ts` reads and clears it and calls `start({ token })`. Nothing is
 * sent when a link is merely opened; the person presses "Email me a code".
 */

import type { EnrolmentKind, PartnerApi } from "../api/client";
import { isPartnerApiError } from "../api/errors";
import type { EnrolmentChallenge } from "../api/types";
import { createCredential, type CreateCredentialDeps } from "../webauthn/registration";
import { messageForError } from "./messages";
import type { EnrolState, Host, Notice } from "./state";

export interface EnrolFlow {
  /** Opens the enrolment screen from sign-in. With a token (from a link) the field is skipped; without one the person pastes it. */
  start(opts?: { token?: string }): void;
  /** Back to sign-in; drops the token and the challenge, and aborts a ceremony that is waiting. */
  cancel(): void;
  /** Step 1. `pasted` is used only when no token is held yet; it may be the whole link or just the token. */
  requestCode(pasted?: string): Promise<void>;
  /** Step 2. */
  submitCode(code: string): Promise<void>;
  /** Step 3. */
  createPasskey(): Promise<void>;
  /** Drops every secret this flow holds, without touching the screen (the page is going away, or the controller is resetting). */
  reset(): void;
}

export interface EnrolDeps {
  readonly api: PartnerApi;
  readonly webauthn: CreateCredentialDeps;
  readonly host: Host;
  /** Called once the first session is open: the controller moves to signed-in. Throws are the flow's failure. */
  readonly onSession: (grant: { expiresAt: string; aal: number }, signal: AbortSignal) => Promise<void>;
}

const TOKEN_FIND_RE = /gr_(inv|enr)_[A-Za-z0-9_-]{43}/;
const CODE_RE = /^[0-9]{6,10}$/;
/** Failures that say nothing about the challenge itself (the request may never have arrived): the person may press the button again. */
const RETRYABLE: readonly string[] = ["network", "unavailable", "rate_limited", "server"];

/** The token inside whatever the person pasted (the bare token, or the whole link), and which kind it is; null if there is none. */
export function extractToken(text: string): { token: string; kind: EnrolmentKind } | null {
  const m = TOKEN_FIND_RE.exec(text);
  if (m === null) return null;
  return { token: m[0], kind: m[1] === "inv" ? "invite" : "enrolment" };
}

export function createEnrolFlow(deps: EnrolDeps): EnrolFlow {
  const { api, host } = deps;
  let token: string | null = null;
  let kind: EnrolmentKind | null = null;
  let challenge: EnrolmentChallenge | null = null;
  /** One run of the flow: a late answer from a flow that was cancelled (or restarted) is dropped. */
  let run: AbortController | null = null;

  function current(): EnrolState | null {
    const s = host.getState();
    return s.screen === "enrol" ? s : null;
  }

  function show(patch: Partial<Omit<EnrolState, "screen">>): void {
    const s = current();
    if (s !== null) host.set({ ...s, ...patch });
  }

  function drop(): void {
    token = null;
    kind = null;
    challenge = null;
    run?.abort();
    run = null;
  }

  const error = (e: unknown): Notice => ({ kind: "error", message: messageForError(e, "enrol") });

  /** A flow that was cancelled or replaced while a request was on the wire: its answer is ignored. */
  function mine(r: AbortController): boolean {
    return run === r && current() !== null;
  }

  return {
    start(opts = {}) {
      const s = host.getState();
      if (s.screen !== "signed-out") return;
      drop();
      const found = opts.token === undefined ? null : extractToken(opts.token);
      if (found !== null) {
        token = found.token;
        kind = found.kind;
      }
      run = new AbortController();
      const bad = opts.token !== undefined && found === null;
      host.set({
        screen: "enrol",
        step: "token",
        hasToken: found !== null,
        kind,
        busy: false,
        notice: bad ? { kind: "error", message: { key: "enrol.tokenInvalid" } } : null,
      });
    },

    cancel() {
      if (host.getState().screen !== "enrol") return;
      drop();
      host.set({ screen: "signed-out", notice: null });
    },

    async requestCode(pasted) {
      const s = current();
      if (s === null || s.busy || s.step === "passkey") return;
      if (token === null) {
        const found = extractToken(pasted ?? "");
        if (found === null) {
          show({ notice: { kind: "error", message: { key: "enrol.tokenInvalid" } } });
          return;
        }
        token = found.token;
        kind = found.kind;
      }
      const r = (run ??= new AbortController());
      const k = kind as EnrolmentKind;
      show({ busy: true, notice: null, kind: k, hasToken: true });
      try {
        await api.acceptStart(k, token);
        if (!mine(r)) return;
        show({ step: "code", busy: false, notice: { kind: "enrol-code-sent" } });
      } catch (e) {
        if (!mine(r)) return;
        show({ busy: false, notice: error(e) });
      }
    },

    async submitCode(code) {
      const s = current();
      if (s === null || s.busy || s.step !== "code" || token === null || kind === null) return;
      const clean = code.trim();
      if (!CODE_RE.test(clean)) {
        show({ notice: { kind: "error", message: { key: "enrol.codeInvalid" } } });
        return;
      }
      const r = (run ??= new AbortController());
      const k = kind;
      show({ busy: true, notice: null });
      try {
        challenge = await api.acceptVerify(k, { token, code: clean });
        if (!mine(r)) {
          challenge = null;
          return;
        }
        // the one-time token has done its job: it is not needed again (the challenge carries the rest), and it is not kept
        token = null;
        show({ step: "passkey", busy: false, notice: null });
      } catch (e) {
        if (!mine(r)) return;
        if (isPartnerApiError(e) && e.kind === "conflict" && (e.code === "existing_member_sign_in" || e.code === "recover_required")) {
          drop();
          host.set({ screen: "signed-out", notice: { kind: e.code === "recover_required" ? "enrol-recover-required" : "enrol-existing-member" } });
          return;
        }
        show({ busy: false, notice: error(e) });
      }
    },

    async createPasskey() {
      const s = current();
      if (s === null || s.busy || s.step !== "passkey" || challenge === null) return;
      const r = (run ??= new AbortController());
      const c = challenge;
      show({ busy: true, notice: null });
      let grant: { expiresAt: string; aal: number };
      try {
        const credential = await createCredential(deps.webauthn, c.options, r.signal);
        if (!mine(r)) return;
        // registerFirst holds no token for a flow that was cancelled while it was on the wire (it revokes the session it just opened instead)
        grant = await api.registerFirst({ challenge: c, credential }, { signal: r.signal });
      } catch (e) {
        if (!mine(r)) return;
        // a cancelled prompt, a browser refusal or an unreachable server leaves the challenge usable; any other refusal has consumed or outlived it: start over
        if (challenge !== null && (!isPartnerApiError(e) || RETRYABLE.includes(e.kind))) {
          show({ busy: false, notice: error(e) });
          return;
        }
        const message = error(e);
        challenge = null;
        token = null;
        kind = null;
        show({ step: "token", hasToken: false, kind: null, busy: false, notice: message });
        return;
      }
      challenge = null;
      if (!mine(r)) {
        await dropSession();
        return;
      }
      try {
        await deps.onSession({ expiresAt: grant.expiresAt, aal: grant.aal }, r.signal);
      } catch {
        // the passkey IS saved; only the first session could not be shown. It is not held, and signing in with the new passkey is the way on.
        await dropSession();
        if (mine(r)) {
          drop();
          host.set({ screen: "signed-out", notice: { kind: "enrol-saved" } });
        }
        return;
      }
      drop();
    },

    reset() {
      drop();
    },
  };

  async function dropSession(): Promise<void> {
    if (!api.hasSession()) return;
    try {
      await api.signOut();
    } catch {
      // nothing is held any more; the server's idle timer ends the session if the request could not be sent
    }
  }
}
