// supabase/tests/unit/course-qr-pin-vector.test.ts
//
// The daily course PIN's encoding, pinned by an OUT-OF-DATABASE vector (P5.1a S2a; migration 0046, private.course_pin_derive). The database derives the PIN under a Vault pepper that never
// leaves Postgres; THIS file is the independent implementation (node:crypto HMAC, nothing shared with the SQL) that fixes what the SQL must compute:
//
//   pin = LPAD( (int.from_bytes(HMAC-SHA256(pepper, "golfraven/course-pin/v1" 0x00 facility_id 0x00 YYYY-MM-DD 0x00 pin_epoch as 4 bytes big-endian)[:4], "big") MOD 10000), 4, "0")
//
// The SAME vectors are asserted against the real function in supabase/tests/matrix/24_course_qr_marker_scan.sql, with the pepper that file builds at run time as repeat('p', 40) (no key
// literal lives in either file or in the repository). If the label, the field order, the separators, the epoch's width, the reduction, the hash or the key stops being an input, one
// of the two files fails. S2b's staff-lane wrapper SHOWS this PIN to a staff member: it must come from the same function, so the app's PIN and the staff screen's can never differ.

import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";

const LABEL = "golfraven/course-pin/v1";

/** The reference derivation. `key` is the pepper's UTF-8 bytes. Test-only: production TypeScript never derives a PIN (a unit test scans for the label). */
export function referenceCoursePin(key: Buffer, facilityId: string, localDate: string, pinEpoch: number): { messageHex: string; macHex: string; pin: string } {
  const epoch = Buffer.alloc(4);
  epoch.writeUInt32BE(pinEpoch);
  const message = Buffer.concat([Buffer.from(LABEL, "utf8"), Buffer.from([0]), Buffer.from(facilityId, "utf8"), Buffer.from([0]), Buffer.from(localDate, "utf8"), Buffer.from([0]), epoch]);
  const mac = createHmac("sha256", key).update(message).digest();
  return { messageHex: message.toString("hex"), macHex: mac.toString("hex"), pin: String(mac.readUInt32BE(0) % 10000).padStart(4, "0") };
}

const PEPPER = Buffer.from("p".repeat(40), "utf8");

describe("the course PIN vectors (the same ones 24_course_qr_marker_scan.sql asserts against the database)", () => {
  const cases: Array<[string, string, number, string, string]> = [
    ["fac_s24a", "2030-01-02", 0, "c4891dfab078afafe5ed77308e680adc0a013ed9caa036564e6eb044ea6fc65f", "0442"],
    ["fac_s24a", "2030-01-02", 1, "339f2c210b537c589f39f8e791a73dedcf10b827a98e16304c8cd973a3c737ee", "9537"],
    ["fac_s24a", "2030-01-03", 0, "6479b08045386a0f85468d74cccea792f735d2d6de75aa5d9c3bc73f59c7985b", "6640"],
    ["fac_s24b", "2030-01-02", 0, "26e955eb285d930e46724af8f11b57510046118b1e4ad1768a64cc32f211228c", "6091"],
    ["fac_x", "2030-01-02", 0, "8879e1f05ad69a26f54a71d5a1ec5950ed919d8bfc3a27150cd8083c5a935276", "9072"],
    ["fac_s24a", "2030-01-02", 256, "a2281781e73cbf0f7706c942e7fdce16d5a4c4b5ec67bc153399e4eee9e468c8", "6449"],
  ];
  for (const [fac, date, epoch, mac, pin] of cases) {
    it(`${fac} ${date} epoch ${epoch} -> ${pin}`, () => {
      const r = referenceCoursePin(PEPPER, fac, date, epoch);
      expect(r.macHex).toBe(mac);
      expect(r.pin).toBe(pin);
    });
  }

  it("the message encoding is pinned byte for byte (label, NUL, facility, NUL, date, NUL, 4-byte big-endian epoch)", () => {
    expect(referenceCoursePin(PEPPER, "fac_x", "2030-01-02", 256).messageHex).toBe(
      "676f6c66726176656e2f636f757273652d70696e2f7631" + "00" + "6661635f78" + "00" + "323033302d30312d3032" + "00" + "00000100",
    );
  });

  it("a different pepper gives a different PIN (the pepper really is an input), and so does each other field", () => {
    expect(referenceCoursePin(Buffer.from("q".repeat(40)), "fac_s24a", "2030-01-02", 0).pin).toBe("5962");
    const base = referenceCoursePin(PEPPER, "fac_s24a", "2030-01-02", 0).macHex;
    for (const other of [referenceCoursePin(PEPPER, "fac_s24b", "2030-01-02", 0), referenceCoursePin(PEPPER, "fac_s24a", "2030-01-03", 0), referenceCoursePin(PEPPER, "fac_s24a", "2030-01-02", 1)]) {
      expect(other.macHex).not.toBe(base);
    }
  });

  it("a PIN is four digits and keeps its leading zeros", () => {
    for (let i = 0; i < 300; i++) expect(referenceCoursePin(PEPPER, `fac_${i}`, "2030-01-02", 0).pin).toMatch(/^[0-9]{4}$/);
    expect(cases.some(([, , , , pin]) => pin.startsWith("0"))).toBe(true);
  });

  it("the reduction is nearly uniform: the bias of `uint32 MOD 10000` is far below the guess rate it protects (the counters, not the PIN's entropy, are the control)", () => {
    // 2^32 mod 10000 = 7296: the 7296 lowest PINs are one draw in 429,497 more likely than the rest, ~ 2.3e-10 absolute
    expect(2 ** 32 % 10000).toBe(7296);
    expect((Math.floor(2 ** 32 / 10000) + 1) / Math.floor(2 ** 32 / 10000) - 1).toBeLessThan(3e-6);
  });
});
