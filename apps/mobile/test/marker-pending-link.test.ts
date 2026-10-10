import { afterEach, describe, expect, it } from "vitest";
import { clearCourseQrLink, parkCourseQrLink, peekCourseQrLink, takeCourseQrLink } from "../src/marker/pending-link";

const TOKEN = "aa.bb.cc";
const SIG86 = "A".repeat(86);

afterEach(() => clearCourseQrLink());

describe("parkCourseQrLink (P5 §54)", () => {
  it("parks a rotating link and clears on take", () => {
    const url = `https://golfraven.app/q/m#${TOKEN}`;
    expect(parkCourseQrLink(url)).toBe(true);
    expect(peekCourseQrLink()).toBe(url);
    expect(takeCourseQrLink()).toBe(url);
    expect(peekCourseQrLink()).toBeNull();
  });

  it("parks a printed facility link", () => {
    const url = `https://golfraven.app/q/f/maple-glen#kid1.${SIG86}`;
    expect(parkCourseQrLink(url)).toBe(true);
    expect(takeCourseQrLink()).toBe(url);
  });

  it("ignores malformed input", () => {
    expect(parkCourseQrLink("not-a-url")).toBe(false);
    expect(parkCourseQrLink("https://golfraven.app/q/x#x")).toBe(false);
    expect(peekCourseQrLink()).toBeNull();
  });
});
