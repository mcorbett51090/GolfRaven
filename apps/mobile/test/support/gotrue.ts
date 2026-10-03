/** A fake GoTrue (Supabase Auth) for running the REAL `@supabase/supabase-js` in Node: records every request and answers the four endpoints
 * the app uses. `[the wire format here is what supabase-js 2.45.4 sends and parses, observed by running it; whether a real GoTrue answers
 * the same is unverified]` */
export interface GoTrueCall {
  method: string;
  path: string;
  query: Record<string, string>;
  body: Record<string, unknown> | null;
  headers: Record<string, string>;
}

export interface FakeGoTrue {
  fetch: typeof fetch;
  calls: GoTrueCall[];
  /** Per-endpoint overrides: return a Response to replace the default answer, or `null` for the default. */
  override: ((call: GoTrueCall) => Response | null) | null;
  /** Seconds a freshly issued access token lives (default 3600). */
  expiresIn: number;
  issued: number;
}

const json = (status: number, body: unknown): Response => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

export function sessionBody(n: number, provider: string, expiresIn: number): Record<string, unknown> {
  return {
    access_token: `access-${n}`,
    token_type: "bearer",
    expires_in: expiresIn,
    refresh_token: `refresh-${n}`,
    user: {
      id: "11111111-2222-4333-8444-555555555555",
      aud: "authenticated",
      role: "authenticated",
      email: "alice@example.test",
      app_metadata: { provider, providers: [provider] },
      user_metadata: {},
      created_at: "2026-10-01T00:00:00.000Z",
    },
  };
}

export function createFakeGoTrue(): FakeGoTrue {
  const state: FakeGoTrue = {
    calls: [],
    override: null,
    expiresIn: 3600,
    issued: 0,
    fetch: ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const u = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
      const headers: Record<string, string> = {};
      new Headers(init?.headers).forEach((v, k) => (headers[k] = v));
      const call: GoTrueCall = {
        method: init?.method ?? "GET",
        path: u.pathname,
        query: Object.fromEntries(u.searchParams.entries()),
        body: typeof init?.body === "string" ? (JSON.parse(init.body) as Record<string, unknown>) : null,
        headers,
      };
      state.calls.push(call);
      const custom = state.override?.(call);
      if (custom) return Promise.resolve(custom);
      if (call.path.endsWith("/otp")) return Promise.resolve(json(200, {}));
      if (call.path.endsWith("/verify")) {
        state.issued += 1;
        return Promise.resolve(json(200, sessionBody(state.issued, "email", state.expiresIn)));
      }
      if (call.path.endsWith("/token")) {
        state.issued += 1;
        const provider = call.query["grant_type"] === "id_token" ? String(call.body?.["provider"]) : "email";
        return Promise.resolve(json(200, sessionBody(state.issued, provider, state.expiresIn)));
      }
      if (call.path.endsWith("/logout")) return Promise.resolve(new Response(null, { status: 204 }));
      return Promise.resolve(json(404, { msg: "not found" }));
    }) as typeof fetch,
  };
  return state;
}
