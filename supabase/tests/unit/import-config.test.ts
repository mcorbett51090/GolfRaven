// supabase/tests/unit/import-config.test.ts
import { describe, expect, it } from "vitest";
import { checkArtifactBaseUrl } from "../../functions/_shared/catalog/import-config.js";

describe("checkArtifactBaseUrl", () => {
  it("accepts an https URL whose host is on the allow-list", () => {
    expect(checkArtifactBaseUrl("https://golfraven.example/catalog/v1", ["golfraven.example"]).ok).toBe(true);
  });

  it("rejects http (not https)", () => {
    const r = checkArtifactBaseUrl("http://golfraven.example/catalog/v1", ["golfraven.example"]);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("not_https");
  });

  it("rejects a host not on the allow-list", () => {
    const r = checkArtifactBaseUrl("https://evil.example/catalog/v1", ["golfraven.example"]);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("host_not_allowed");
  });

  it("rejects a subdomain that is not an EXACT allow-list match (no wildcarding)", () => {
    const r = checkArtifactBaseUrl("https://evil.golfraven.example/catalog/v1", ["golfraven.example"]);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("host_not_allowed");
  });

  it("rejects a malformed URL", () => {
    const r = checkArtifactBaseUrl("not a url", ["golfraven.example"]);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("malformed_url");
  });

  // P3e round 2 gate, LOW: reject userinfo, port, query and fragment.
  it.each([
    ["userinfo", "https://user:pw@golfraven.example/catalog/v1"],
    ["userinfo (no password)", "https://golfraven.example@evil.example/catalog/v1"],
    ["port", "https://golfraven.example:8443/catalog/v1"],
    ["query", "https://golfraven.example/catalog/v1?x=1"],
    ["fragment", "https://golfraven.example/catalog/v1#frag"],
    ["empty query marker", "https://golfraven.example/catalog/v1?"],
  ])("rejects a URL with %s", (_label, url) => {
    expect(checkArtifactBaseUrl(url, ["golfraven.example"]).ok).toBe(false);
  });
});
