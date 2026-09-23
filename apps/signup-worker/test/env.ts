import type { Env } from "../src/config";
import { FakeD1, FakeKV } from "./fakes";

/**
 * Returns Env typed with the CONCRETE fakes (not the narrow D1Like/KVLike
 * interfaces), so test code can reach in and read `.rows`/`.store` directly
 * without a cast at every call site.
 */
export type TestEnv = Env & { DB: FakeD1; RATE_LIMIT_KV: FakeKV };

export function makeTestEnv(overrides: Partial<Env> = {}): TestEnv {
  return {
    DB: new FakeD1(),
    RATE_LIMIT_KV: new FakeKV(),
    RESEND_API_KEY: "test-resend-key",
    TURNSTILE_SECRET: "test-turnstile-secret",
    TOKEN_PEPPER: "p".repeat(40), // >= the 32-char minimum (config.ts assertRequiredSecretsPresent, gate finding F-N6); built at runtime so no key-shaped literal trips gitleaks
    RESEND_FROM_EMAIL: "GolfRaven <hello@golfraven.example>",
    PUBLIC_BASE_URL: "https://golfraven.example",
    ALLOWED_DEV_ORIGINS: "",
    ...overrides,
  } as TestEnv;
}
