import { pbkdf2Sync } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createStepUp, StepUpError, StepUpUnavailable, unavailableStepUp, type PinPrompter, type PinPromptRequest } from "../src/auth/step-up";
import { signInWithPasskey } from "../src/auth/sign-in";
import { fromB64u } from "../../../supabase/functions/_shared/partner/token.ts";
import { jsonResponse } from "./support/stub-fetch";
import { makeWorld, type World } from "./support/world";

afterEach(() => vi.restoreAllMocks());

describe("the fail-closed placeholder (still exported: a screen wired with it cannot send an action without a PIN)", () => {
  it("fails closed for every action class", async () => {
    for (const cls of ["A1", "A2"] as const) await expect(unavailableStepUp.requirePin(cls)).rejects.toBeInstanceOf(StepUpUnavailable);
  });

  it("step-up.ts itself does no crypto, storage or network: it composes pin.ts and the session routes", async () => {
    const src = await import("node:fs").then((fs) => fs.readFileSync(new URL("../src/auth/step-up.ts", import.meta.url), "utf8"));
    const code = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    expect(code).not.toMatch(/PBKDF2|crypto\.subtle|deriveBits|fetch\(|localStorage|sessionStorage|console\./);
  });
});

/** A scripted prompter: answers from the list in order (null cancels) and records what it was asked. */
function scripted(answers: Array<string | null>): PinPrompter & { asked: PinPromptRequest[] } {
  const asked: PinPromptRequest[] = [];
  return {
    asked,
    async ask(req) {
      asked.push(req);
      const next = answers.shift();
      if (next === undefined) throw new Error("the prompter was asked more times than the test scripted");
      return next;
    },
  };
}

async function signedIn(over: Parameters<typeof makeWorld>[0] = {}): Promise<World> {
  const w = makeWorld(over);
  await signInWithPasskey(w.api, { credentials: w.auth.credentials, supported: true });
  return w;
}

const pinPosts = (w: World) => w.server.log.filter((r) => r.method === "POST" && r.path.endsWith("/step-up/pin"));
const PIN = "7391";

describe("requirePin against the real partner-session handler", () => {
  it("happy path: GET pin, derive in the browser, POST { derived } and nothing else; the body is the independent PBKDF2 of the PIN under the server's salt", async () => {
    const w = await signedIn();
    await w.server.seedPin(PIN);
    const record = w.server.pinRecord()!;
    const prompter = scripted([PIN]);
    const grant = await createStepUp({ api: w.api, prompter }).requirePin("A1");

    expect(grant.actionClass).toBe("A1");
    expect(Date.parse(grant.expiresAt)).toBeGreaterThan(Date.now());
    expect(w.server.state.pinGrantsIssued).toBe(1);
    expect(prompter.asked).toHaveLength(1);
    expect(prompter.asked[0]).toMatchObject({ actionClass: "A1", problem: null });

    const posts = pinPosts(w);
    expect(posts).toHaveLength(1);
    const body = JSON.parse(posts[0]!.body) as Record<string, unknown>;
    expect(Object.keys(body)).toEqual(["derived"]);
    const expected = Buffer.from(pbkdf2Sync(PIN, fromB64u(record.salt)!, record.iterations, 32, "sha256")).toString("base64url");
    expect(body["derived"]).toBe(expected);
    expect(body["derived"]).toBe(record.derived);
  });

  it("the PIN's digits appear in NO request: not in a body, not in a URL, not in a header (every request of the whole conversation)", async () => {
    const w = await signedIn();
    await w.server.seedPin(PIN);
    await createStepUp({ api: w.api, prompter: scripted([PIN]) }).requirePin("A2");
    const wire = w.server.log.filter((r) => r.method !== "OPTIONS");
    expect(wire.length).toBeGreaterThanOrEqual(3); // options, verify, session ... pin, step-up/pin
    for (const r of wire) {
      // the PIN is not any field: every JSON body field is either the derived key or part of the sign-in
      const fields = r.body === "" ? [] : Object.values(JSON.parse(r.body) as Record<string, unknown>);
      expect(fields, `${r.method} ${r.path}`).not.toContain(PIN);
      expect(r.path).not.toContain(PIN);
    }
    const stepUpBody = JSON.parse(pinPosts(w)[0]!.body) as Record<string, unknown>;
    expect(stepUpBody["derived"]).not.toBe(PIN);
    expect(String(stepUpBody["derived"])).toHaveLength(43);
  });

  it("a PIN the rules refuse never reaches the derivation or the server (and costs no failure); the next ask names the reason", async () => {
    const w = await signedIn();
    await w.server.seedPin(PIN);
    const derive = vi.spyOn(crypto.subtle, "deriveBits");
    const prompter = scripted(["1234", PIN]);
    await createStepUp({ api: w.api, prompter }).requirePin("A1");
    expect(prompter.asked.map((a) => a.problem)).toEqual([null, { kind: "rejected", reason: "run" }]);
    expect(pinPosts(w)).toHaveLength(1);
    expect(derive).toHaveBeenCalledTimes(1);
    expect(w.server.pinRecord()!.failures).toBe(0);
  });

  it("a wrong PIN asks again with the problem; the server counts it; the right PIN then succeeds and clears the count", async () => {
    const w = await signedIn();
    await w.server.seedPin(PIN);
    const prompter = scripted(["7392", PIN]);
    const grant = await createStepUp({ api: w.api, prompter }).requirePin("A1");
    expect(grant.actionClass).toBe("A1");
    expect(prompter.asked.map((a) => a.problem)).toEqual([null, { kind: "wrong" }]);
    expect(pinPosts(w)).toHaveLength(2);
    expect(w.server.pinRecord()!.failures).toBe(0);
  });

  it("repeated wrong PINs back off (the server's Retry-After reaches the prompt) and then lock: 'locked' ends the call", async () => {
    const w = await signedIn();
    await w.server.seedPin(PIN);
    const prompter = scripted(["7392", "7393", "7394", "7395", null]);
    const e = await createStepUp({ api: w.api, prompter }).requirePin("A1").catch((x: unknown) => x);
    // 3 wrong PINs start a 30 s back-off: the 4th attempt is refused by the server without counting, and the prompt is told how long
    expect(prompter.asked.map((a) => a.problem?.kind ?? null)).toEqual([null, "wrong", "wrong", "wrong", "backoff"]);
    expect(prompter.asked[3]!.retryAfterSeconds).toBeGreaterThan(0);
    const backoff = prompter.asked[4]!.problem;
    expect(backoff).toMatchObject({ kind: "backoff" });
    expect((backoff as { retryAfterSeconds: number | null }).retryAfterSeconds).toBeGreaterThan(0);
    expect(e).toBeInstanceOf(StepUpError);
    expect((e as StepUpError).kind).toBe("cancelled");
    expect(w.server.pinRecord()!.failures).toBe(3);
  });

  it("the fifth consecutive failure locks the PIN: the server answers 'locked' and the call ends with it (the page does not ask again)", async () => {
    const w = await signedIn();
    await w.server.seedPin(PIN, { failures: 4 });
    const prompter = scripted(["7392"]);
    const e = await createStepUp({ api: w.api, prompter }).requirePin("A1").catch((x: unknown) => x);
    expect((e as StepUpError).kind).toBe("locked");
    expect(prompter.asked).toHaveLength(1);
    expect(w.server.pinRecord()!.locked).toBe(true);
    // and a correct PIN is refused afterwards: a lock survives
    const again = scripted([]);
    expect(((await createStepUp({ api: w.api, prompter: again }).requirePin("A1").catch((x: unknown) => x)) as StepUpError).kind).toBe("locked");
    expect(again.asked).toHaveLength(0);
  });

  const cases: Array<[string, (w: World) => Promise<unknown>]> = [
    ["unset", async () => undefined],
    ["must_change", async (w) => w.server.seedPin(PIN, { mustChange: true })],
    ["locked", async (w) => w.server.seedPin(PIN, { locked: true })],
  ];
  it.each(cases)("a PIN that is %s ends the call with that kind, without prompting and without a POST", async (kind, arrange) => {
    const w = await signedIn();
    await arrange(w);
    const prompter = scripted([]);
    const e = await createStepUp({ api: w.api, prompter }).requirePin("A1").catch((x: unknown) => x);
    expect(e).toBeInstanceOf(StepUpError);
    expect((e as StepUpError).kind).toBe(kind);
    expect(prompter.asked).toHaveLength(0);
    expect(pinPosts(w)).toHaveLength(0);
  });

  it("cancelling the prompt ends the call with 'cancelled' and sends nothing", async () => {
    const w = await signedIn();
    await w.server.seedPin(PIN);
    const e = await createStepUp({ api: w.api, prompter: scripted([null]) }).requirePin("A1").catch((x: unknown) => x);
    expect((e as StepUpError).kind).toBe("cancelled");
    expect(pinPosts(w)).toHaveLength(0);
  });

  it("an aborted signal ends the call before it asks", async () => {
    const w = await signedIn();
    await w.server.seedPin(PIN);
    const ctl = new AbortController();
    ctl.abort();
    const prompter = scripted([]);
    const e = await createStepUp({ api: w.api, prompter }).requirePin("A1", ctl.signal).catch((x: unknown) => x);
    expect((e as StepUpError).kind).toBe("cancelled");
    expect(prompter.asked).toHaveLength(0);
  });

  it("a server that asks for a work factor outside the contract is refused: nothing is derived, nothing is sent", async () => {
    const w = await signedIn();
    await w.server.seedPin(PIN);
    const hostile = w.newClient({
      fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input).endsWith("/partner-session/pin") && init?.method === "GET") {
          const real = (await (await w.fetch(input, init)).json()) as { data: { salt: string } };
          return jsonResponse(200, { data: { state: "ok", salt: real.data.salt, iterations: 1000, retryAfterSeconds: 0 } });
        }
        return w.fetch(input, init);
      }) as typeof fetch,
    });
    await signInWithPasskey(hostile, { credentials: w.auth.credentials, supported: true });
    const derive = vi.spyOn(crypto.subtle, "deriveBits");
    const before = pinPosts(w).length;
    const e = await createStepUp({ api: hostile, prompter: scripted([PIN]) }).requirePin("A1").catch((x: unknown) => x);
    expect((e as StepUpError).kind).toBe("bad_params");
    expect(derive).not.toHaveBeenCalled();
    expect(pinPosts(w)).toHaveLength(before);
  });

  it("a dead session is the client's 401 (the token is wiped): the error is the API's, not a PIN failure", async () => {
    const w = await signedIn();
    await w.server.seedPin(PIN);
    w.server.killAllSessions();
    const e = await createStepUp({ api: w.api, prompter: scripted([]) }).requirePin("A1").catch((x: unknown) => x);
    expect(e).toMatchObject({ name: "PartnerApiError", kind: "unauthenticated" });
    expect(w.api.hasSession()).toBe(false);
  });
});
