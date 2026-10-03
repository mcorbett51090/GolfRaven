/**
 * The ONLY file that reaches the mocks, and only under `__DEV__` (a `require` inside a `__DEV__ ? … : null` so Metro drops the mock modules
 * from a release bundle, like `DEMO_SNAPSHOT` in `AppProvider.tsx` and the dev panel in the Me screen). `api/index.ts` does not re-export the
 * mock and nothing imports it statically; `test/backend.test.ts` scans the sources to keep it that way.
 */
import type { MockApi } from "../api/mock";
import { devOnly } from "../dev-guard";
import type { AppleAdapter, GoogleAdapter } from "../signin/adapters";
import type { DevMocks } from "./backend";

const demoApple: AppleAdapter = {
  availability: () => Promise.resolve("available"),
  authenticate: () => Promise.resolve({ status: "ok", identityToken: "demo.demo.demo", authorizationCode: "demo-authorization-code" }),
};
const demoGoogle: GoogleAdapter = {
  availability: () => Promise.resolve("available"),
  authenticate: () => Promise.resolve({ status: "ok", idToken: "demo.demo.demo" }),
};

export const loadDevMocks: (() => DevMocks) | null = __DEV__
  ? () => {
      const guard = devOnly(__DEV__);
      const { createMockApi } = require("../api/mock") as typeof import("../api/mock");
      const { createMockAuth } = require("../auth/mock-auth") as typeof import("../auth/mock-auth");
      const api: MockApi = createMockApi(guard, { programmes: {}, plays: [], achievements: [] });
      return { api, auth: createMockAuth(guard), apple: demoApple, google: demoGoogle, handle: api };
    }
  : null;
