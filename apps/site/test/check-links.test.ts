/**
 * check-links.test.ts — unit coverage for `scripts/check-links.mjs`'s
 * SSRF-hardening functions (Opus gate should-fix, "check-links"). Lives
 * in `apps/site/test/` (imported by relative path) because
 * `scripts/check-links.mjs` is a repo-root ops script with no workspace
 * package of its own — this is still `pnpm -r test` coverage for it,
 * just hosted in the one package whose test runner already exists.
 */
import { describe, expect, it } from "vitest";
import { isPrivateIp, isPrivateV4 } from "../../../scripts/check-links.mjs";

describe("check-links.mjs SSRF hardening: isPrivateV4 / isPrivateIp", () => {
  it.each([
    ["127.0.0.1", true],
    ["10.0.0.5", true],
    ["172.16.0.1", true],
    ["192.168.1.1", true],
    ["169.254.169.254", true], // cloud metadata
    ["100.64.0.1", true], // CGNAT
    ["0.0.0.0", true],
    ["224.0.0.1", true], // multicast
    ["8.8.8.8", false],
    ["1.1.1.1", false],
    ["203.0.113.5", false],
  ])("isPrivateV4(%s) => %s", (ip, expected) => {
    expect(isPrivateV4(ip)).toBe(expected);
  });

  it.each([
    ["::1", true],
    ["fe80::1", true],
    ["fc00::1", true],
    ["fd12:3456::1", true],
    ["::ffff:127.0.0.1", true], // v4-mapped loopback
    ["::ffff:8.8.8.8", false], // v4-mapped public
    ["2001:4860:4860::8888", false], // public v6 (Google DNS)
  ])("isPrivateIp(%s) => %s", (ip, expected) => {
    expect(isPrivateIp(ip)).toBe(expected);
  });

  it("an unparseable IPv4-looking string is treated as UNSAFE (fail closed)", () => {
    expect(isPrivateV4("not-an-ip")).toBe(true);
  });
});
