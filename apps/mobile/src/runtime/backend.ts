/**
 * Which backend the app runs against, and the guarantee that a release build never runs against a mock.
 *
 * | build     | API + Supabase configured | result                                                                    |
 * |-----------|---------------------------|---------------------------------------------------------------------------|
 * | any       | yes                       | `real`: `createHttpApiClient` + `createSupabaseAuth`                      |
 * | `__DEV__` | no                        | `demo`: the mocks, labelled as such in the UI                             |
 * | release   | no                        | `unconfigured`: network calls fail with `not_configured`; no fake data    |
 *
 * "Configured" means ALL of `EXPO_PUBLIC_API_BASE_URL`, `EXPO_PUBLIC_SUPABASE_URL` and `EXPO_PUBLIC_SUPABASE_ANON_KEY` parsed (`config-values.ts`):
 * half a configuration is no configuration, so a build can never talk to a server it cannot authenticate to.
 */
import { createHttpApiClient, createUnconfiguredApi, type ApiClient, type HttpApiOptions, type HttpFetch } from "../api";
import { AuthError, type AuthService } from "../auth/types";
import { devOnly } from "../dev-guard";
import type { SecureStore } from "../secure";
import type { AppleAdapter, GoogleAdapter } from "../signin/adapters";

export type BackendKind = "real" | "demo" | "unconfigured";

export interface BackendConfig {
  apiBaseUrl: string | null;
  supabaseUrl: string | null;
  supabaseAnonKey: string | null;
}

export function isBackendConfigured(c: BackendConfig): boolean {
  return c.apiBaseUrl !== null && c.supabaseUrl !== null && c.supabaseAnonKey !== null;
}

export function selectBackendKind(input: { isDev: boolean; config: BackendConfig }): BackendKind {
  if (isBackendConfigured(input.config)) return "real";
  return input.isDev ? "demo" : "unconfigured";
}

export interface DevMocks {
  api: ApiClient;
  auth: AuthService;
  /** Stand-ins for the native sign-in modules, so the demo can walk the screens (they return fake tokens that only the mock auth accepts). */
  apple: AppleAdapter;
  google: GoogleAdapter;
  /** Opaque handle the dev panel narrows (it is only ever a `MockApi`). */
  handle: unknown;
}

export interface BackendDeps {
  isDev: boolean;
  config: BackendConfig;
  secure: SecureStore;
  fetch: HttpFetch;
  /** Builds the real auth service (auth-js). Injected so tests need not load it. */
  createAuth: (opts: { url: string; anonKey: string; storage: SecureStore }) => AuthService;
  /** Loads the dev mocks. Called ONLY for `demo`; the app passes a loader that is `null` outside `__DEV__` (`runtime/dev-backend.ts`). */
  loadDevMocks: (() => DevMocks) | null;
  /** Evidence-lane wiring for the real client (the check-in redeemer of `attest/`; the payload write the check-in redemption needs). */
  evidence?: Pick<HttpApiOptions, "redeemer" | "persistEvidencePayload">;
  /** Reward-activation wiring for the real client (the activator of `attest/`, and `Platform.OS` for the plain one). */
  rewards?: Pick<HttpApiOptions, "activator" | "platform">;
}

export interface Backend {
  kind: BackendKind;
  api: ApiClient;
  auth: AuthService;
  /** Set only for `demo`. */
  demoAdapters: { apple: AppleAdapter; google: GoogleAdapter } | null;
  devHandle: unknown;
}

export function createBackend(deps: BackendDeps): Backend {
  const kind = selectBackendKind({ isDev: deps.isDev, config: deps.config });
  if (kind === "real") {
    const { apiBaseUrl, supabaseUrl, supabaseAnonKey } = deps.config;
    const auth = deps.createAuth({ url: supabaseUrl as string, anonKey: supabaseAnonKey as string, storage: deps.secure });
    const api = createHttpApiClient({ baseUrl: apiBaseUrl as string, fetch: deps.fetch, getAccessToken: (o) => auth.getAccessToken(o), ...deps.evidence, ...deps.rewards });
    return { kind, api, auth, demoAdapters: null, devHandle: null };
  }
  if (kind === "demo") {
    devOnly(deps.isDev); // belt and braces: selection already refuses, construction refuses too
    if (!deps.loadDevMocks) throw new Error("demo backend selected but no dev mock loader is present");
    const m = deps.loadDevMocks();
    return { kind, api: m.api, auth: m.auth, demoAdapters: { apple: m.apple, google: m.google }, devHandle: m.handle };
  }
  return { kind, api: createUnconfiguredApi(), auth: createUnconfiguredAuth(), demoAdapters: null, devHandle: null };
}

/** The auth service of a build with no server: never signed in, every sign-in attempt fails as "network". */
export function createUnconfiguredAuth(): AuthService {
  const refuse = (): Promise<never> => Promise.reject(new AuthError("other", { code: "not_configured", message: "this build has no auth server configured" }));
  return {
    restore: () => Promise.resolve(null),
    current: () => null,
    getAccessToken: () => Promise.resolve(null),
    requestEmailCode: refuse,
    verifyEmailCode: refuse,
    signInWithIdToken: refuse,
    signOut: () => Promise.resolve(),
    clearLocalSession: () => Promise.resolve(),
    subscribe: () => () => undefined,
  };
}
