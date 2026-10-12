import { describe, expect, it } from "vitest";
import { buildAasa, buildAssetLinks } from "../scripts/gen-applinks.mjs";

describe("gen-applinks (P5 §54)", () => {
  it("AASA is empty until a 10-char Team ID is provided", () => {
    expect(buildAasa(undefined).applinks.details).toEqual([]);
    expect(buildAasa("short").applinks.details).toEqual([]);
    expect(buildAasa("ABCD123456").applinks.details).toEqual([
      {
        appID: "ABCD123456.com.golfraven.app",
        paths: ["/q/m", "/q/m/", "/q/f/*"],
      },
    ]);
  });

  it("assetlinks is empty until a colon-hex SHA-256 fingerprint is provided", () => {
    expect(buildAssetLinks(undefined)).toEqual([]);
    expect(buildAssetLinks("not-a-fingerprint")).toEqual([]);
    const fp = Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, "0")).join(":").toUpperCase();
    expect(buildAssetLinks(fp)).toEqual([
      {
        relation: ["delegate_permission/common.handle_all_urls"],
        target: {
          namespace: "android_app",
          package_name: "com.golfraven.app",
          sha256_cert_fingerprints: [fp],
        },
      },
    ]);
  });
});
