// supabase/tests/unit/pem-shared.test.ts
//
// ONE PKCS#8 PEM parser (`_shared/pem.ts`) for the Sign in with Apple key, the DeviceCheck key and the Google service-account key. Before it, the
// Sign in with Apple parser accepted a one-line PEM with literal backslash-n and the DeviceCheck / Play Integrity one did not.

import { beforeAll, describe, expect, it } from "vitest";
import { pkcs8PemToDer as shared } from "../../functions/_shared/pem.js";
import { pkcs8PemToDer as viaSignin } from "../../functions/_shared/signin/apple-client-secret.js";
import { pemToDer as viaRewards } from "../../functions/_shared/rewards/vendor-http.js";
import { toB64 } from "./rewards-test-crypto.js";

// The fences are assembled at run time so no source line carries a literal PEM header (gitleaks' private-key rule reads one, correctly in
// general and wrongly here: nothing in this file is a key).
const FENCE = "-".repeat(5);
const block = (label: string, body: string) => `${FENCE}BEGIN ${label}${FENCE}\n${body}\n${FENCE}END ${label}${FENCE}`;

let pem: string;
let der: Uint8Array;
beforeAll(async () => {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  pem = block("PRIVATE KEY", toB64(der).replace(/(.{64})/g, "$1\n"));
}, 30_000);

describe("the shared PKCS#8 PEM parser", () => {
  it("is ONE implementation: the sign-in and rewards entry points are the shared function", () => {
    expect(viaSignin).toBe(shared);
    expect(viaRewards(pem)).toEqual(shared(pem));
  });

  it("accepts real LF newlines, CRLF, a one-line literal backslash-n form, and surrounding whitespace, all to the same DER", () => {
    const forms = [pem, pem.replace(/\n/g, "\r\n"), pem.replace(/\n/g, "\\n"), `\n\t ${pem} \n\n`, `  ${pem.replace(/\n/g, "\\n")}  `];
    for (const f of forms) {
      for (const parse of [shared, viaSignin, viaRewards]) expect(Array.from(parse(f)!), f.slice(0, 30)).toEqual(Array.from(der));
    }
  });

  it("rejects everything else with null and never throws: empty, wrong label, bad base64, truncated, two blocks, trailing junk, a bare escaped newline", () => {
    const bad = [
      "",
      "   ",
      "nope",
      block("PUBLIC KEY", "AAAA"),
      block("EC PRIVATE KEY", "AAAA"),
      block("PRIVATE KEY", "!!!"),
      block("PRIVATE KEY", ""),
      `${FENCE}BEGIN PRIVATE KEY${FENCE}\nAAAA`,
      `${FENCE}BEGIN PRIVATE KEY${FENCE}\\nAAAA`,
      `${pem}\n${pem}`,
      `${pem}\ntrailing`,
      `prefix\n${pem}`,
      "\\n",
      "\\n\\n\\n",
    ];
    for (const b of bad) {
      for (const parse of [shared, viaSignin, viaRewards]) expect(parse(b), JSON.stringify(b).slice(0, 40)).toBeNull();
    }
  });
});
