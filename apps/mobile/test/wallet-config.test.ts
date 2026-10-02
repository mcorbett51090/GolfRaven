import { CONTRACT_VERSION } from "@golfraven/catalog";
import { describe, expect, it } from "vitest";
import { SUPPORTED_CONTRACT_MAJOR, parseCatalogBaseUrl, parseStoreUrl } from "../src/config-values";
import { programmeIsOn, walletTabVisible, walletTrailIds } from "../src/wallet";

describe("Wallet visibility (O17)", () => {
  it("is hidden while no trail's programme is on", () => {
    expect(walletTabVisible({})).toBe(false);
    expect(walletTabVisible({ trl_a: "none", trl_b: "none" })).toBe(false);
  });
  it("is shown when any trail is pilot or live, per trail", () => {
    expect(walletTabVisible({ trl_a: "none", trl_b: "pilot" })).toBe(true);
    expect(walletTabVisible({ trl_a: "live" })).toBe(true);
    expect(walletTrailIds({ trl_b: "pilot", trl_a: "none", trl_c: "live" })).toEqual(["trl_b", "trl_c"]);
    expect(programmeIsOn(undefined)).toBe(false);
  });
});

describe("config", () => {
  it("this build reads the contract MAJOR that @golfraven/catalog currently publishes", () => {
    expect(SUPPORTED_CONTRACT_MAJOR).toBe(CONTRACT_VERSION);
  });

  it("catalog base URL: https only, no credentials or query, trailing slash trimmed", () => {
    expect(parseCatalogBaseUrl("https://golfraven.example/")).toBe("https://golfraven.example");
    expect(parseCatalogBaseUrl("https://cdn.example.com:8443/base/path")).toBe("https://cdn.example.com:8443/base/path");
    expect(parseCatalogBaseUrl("http://golfraven.example")).toBeNull();
    expect(parseCatalogBaseUrl("https://user:pw@golfraven.example")).toBeNull();
    expect(parseCatalogBaseUrl("https://golfraven.example/?x=1")).toBeNull();
    expect(parseCatalogBaseUrl("javascript:alert(1)")).toBeNull();
    expect(parseCatalogBaseUrl("")).toBeNull();
    expect(parseCatalogBaseUrl(undefined)).toBeNull();
  });

  it("plain http is accepted only for local development hosts, and only when allowed", () => {
    expect(parseCatalogBaseUrl("http://localhost:4321", { allowLocalHttp: true })).toBe("http://localhost:4321");
    expect(parseCatalogBaseUrl("http://10.0.2.2:4321", { allowLocalHttp: true })).toBe("http://10.0.2.2:4321");
    expect(parseCatalogBaseUrl("http://localhost:4321")).toBeNull();
    expect(parseCatalogBaseUrl("http://evil.example", { allowLocalHttp: true })).toBeNull();
  });

  it("store url: https only", () => {
    expect(parseStoreUrl("https://apps.apple.com/app/id1")).toBe("https://apps.apple.com/app/id1");
    expect(parseStoreUrl("http://x")).toBeNull();
    expect(parseStoreUrl(undefined)).toBeNull();
  });
});
