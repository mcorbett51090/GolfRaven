/** Wires the real `partner-session` handler (fake ports), a browser-like fetch, a software authenticator and the SPA's API client into one test world. */
import { createPartnerApi, type PartnerApi } from "../../src/api/client";
import { uuidToBytes } from "../../../../supabase/functions/_shared/partner/session-shape.ts";
import { createFakePartnerServer, browserLikeFetch, USER_ID, type FakeServer } from "./fake-partner-server";
import { createSoftAuthenticator, newSoftCredential, type SoftAuthenticator } from "./soft-authenticator";

export const PAGE_ORIGIN = "https://partners.example.test";
export const RP_ID = "partners.example.test";
export const API_BASE = "https://api.example.test/functions/v1";

export interface World {
  readonly server: FakeServer;
  readonly auth: SoftAuthenticator;
  readonly api: PartnerApi;
  readonly fetch: typeof fetch;
  newClient(over?: { fetch?: typeof fetch }): PartnerApi;
}

export function makeWorld(over: { pageOrigin?: string; whoami?: Parameters<typeof createFakePartnerServer>[0]["whoami"] } = {}): World {
  const auth = createSoftAuthenticator({ origin: PAGE_ORIGIN, rpId: RP_ID, credential: newSoftCredential(uuidToBytes(USER_ID)!) });
  const server = createFakePartnerServer({ pageOrigin: PAGE_ORIGIN, rpId: RP_ID, credential: auth.credential, ...(over.whoami === undefined ? {} : { whoami: over.whoami }) });
  const f = browserLikeFetch(server.handler, over.pageOrigin ?? PAGE_ORIGIN, API_BASE);
  const newClient = (o: { fetch?: typeof fetch } = {}) => createPartnerApi({ baseUrl: API_BASE, fetch: o.fetch ?? f });
  return { server, auth, api: newClient(), fetch: f, newClient };
}
