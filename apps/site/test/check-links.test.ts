/**
 * check-links.test.ts — unit coverage for `scripts/check-links.mjs`'s
 * SSRF-hardening functions (Opus gate should-fix, "check-links"). Lives
 * in `apps/site/test/` (imported by relative path) because
 * `scripts/check-links.mjs` is a repo-root ops script with no workspace
 * package of its own — this is still `pnpm -r test` coverage for it,
 * just hosted in the one package whose test runner already exists.
 */
import { describe, expect, it } from "vitest";
import {
  expandIPv6,
  isPrivateIp,
  isPrivateIpv6,
  isPrivateV4,
} from "../../../scripts/check-links.mjs";

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

describe("check-links.mjs SSRF hardening: isPrivateIpv6 — every range the re-gate named", () => {
  it.each([
    ["::", true, "unspecified"],
    ["::1", true, "loopback"],
    ["fe80::1", true, "link-local fe80::/10"],
    ["fec0::1", true, "site-local fec0::/10 (deprecated)"],
    ["fc00::1", true, "unique-local fc00::/7"],
    ["fd12:3456::1", true, "unique-local fc00::/7 (fd range)"],
    ["ff02::1", true, "multicast ff00::/8"],
    ["ff00::", true, "multicast ff00::/8 (base)"],
    ["64:ff9b::10.0.0.1", true, "NAT64 64:ff9b::/96 wrapping a PRIVATE v4"],
    ["64:ff9b::8.8.8.8", false, "NAT64 64:ff9b::/96 wrapping a PUBLIC v4"],
    [
      "2002:0a00:0001::",
      true,
      "6to4 2002::/16 wrapping a PRIVATE v4 (10.0.0.1)",
    ],
    [
      "2002:0808:0808::",
      false,
      "6to4 2002::/16 wrapping a PUBLIC v4 (8.8.8.8)",
    ],
    ["::0.0.0.0", true, "v4-compatible ::/96 (deprecated) wrapping 0.0.0.0"],
    [
      "::10.0.0.1",
      true,
      "v4-compatible ::/96 (deprecated) wrapping a PRIVATE v4",
    ],
    [
      "::8.8.8.8",
      false,
      "v4-compatible ::/96 (deprecated) wrapping a PUBLIC v4",
    ],
    ["::ffff:127.0.0.1", true, "v4-mapped ::ffff:0:0/96 wrapping loopback"],
    ["::ffff:8.8.8.8", false, "v4-mapped ::ffff:0:0/96 wrapping a PUBLIC v4"],
    [
      "2001:4860:4860::8888",
      false,
      "public v6 (Google DNS) — not in any reserved range",
    ],
  ])("isPrivateIpv6(%s) => %s (%s)", (ip, expected) => {
    expect(isPrivateIpv6(ip)).toBe(expected);
  });

  it("expandIPv6 correctly expands '::'-compressed and embedded-IPv4 forms", () => {
    expect(expandIPv6("::1")).toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
    expect(expandIPv6("::")).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
    expect(expandIPv6("2001:db8::1")).toEqual([
      0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
    ]);
    expect(expandIPv6("::ffff:1.2.3.4")).toEqual([
      0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304,
    ]);
    expect(expandIPv6("64:ff9b::1.2.3.4")).toEqual([
      0x64, 0xff9b, 0, 0, 0, 0, 0x0102, 0x0304,
    ]);
  });

  it("an unparseable IPv6-looking string is treated as UNSAFE (fail closed)", () => {
    expect(expandIPv6("not-an-ipv6")).toBe(null);
    expect(isPrivateIpv6("not-an-ipv6")).toBe(true);
  });

  it("isPrivateIp dispatches IPv4 vs IPv6 correctly (no ':' => v4 path)", () => {
    expect(isPrivateIp("8.8.8.8")).toBe(false);
    expect(isPrivateIp("2001:4860:4860::8888")).toBe(false);
  });
});
