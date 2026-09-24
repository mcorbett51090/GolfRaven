/**
 * Blocking #2 (gate review, post-e9b3ab0): the booking-host allow-list
 * comes only from the committed `config/booking-hosts.json`.
 */
import { describe, expect, it } from "vitest";
import {
  defaultBookingHostsConfigPath,
  loadBookingHostAllowList,
} from "../src/config.js";
import { existsSync } from "node:fs";

describe("loadBookingHostAllowList", () => {
  it("loads the real committed config/booking-hosts.json", async () => {
    expect(existsSync(defaultBookingHostsConfigPath())).toBe(true);
    const hosts = await loadBookingHostAllowList();
    expect(Array.isArray(hosts)).toBe(true);
    expect(hosts).toContain("www.golfnow.com");
  });
});
