// supabase/tests/unit/mint-siwa-client-secret.test.ts
//
// tools/apple/mint-siwa-client-secret.mjs, the operator tool that mints the long-lived Sign in with Apple client secret for Supabase Auth's Apple
// provider. It is run as a real child process (a CLI's contract is its argv, stdin, stdout, stderr and exit code). Every key here is generated at
// run time; nothing is a fixture. The properties that matter: the key is never accepted from argv, nothing is written to disk (proved at run time with
// Node's permission model, which denies every write), the lifetime is capped, only the JWT reaches stdout, and no key material reaches any output.

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fromBase64UrlStrict } from "../../functions/_shared/rewards/binding.js";
import { toB64 } from "./rewards-test-crypto.js";

const TOOL = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "tools", "apple", "mint-siwa-client-secret.mjs");
const IDS = ["--team-id", "TEAMX", "--key-id", "KEYX", "--client-id", "com.example.app"];

// Fences assembled at run time: no source line carries a literal PEM header (gitleaks' private-key rule would read one; nothing here is a key).
const FENCE = "-".repeat(5);
const block = (body: string) => `${FENCE}BEGIN PRIVATE KEY${FENCE}\n${body}\n${FENCE}END PRIVATE KEY${FENCE}\n`;

// A preload that WRAPS every write-capable `fs` / `fs/promises` function and prints `WRITE-ATTEMPT <name>` to stderr before calling the original.
// The permission model denies a write, but a tool could swallow that error in a try/catch; this spy sees the ATTEMPT either way. Read-only opens pass.
const SPY = `
import fs from "node:fs";
import fsp from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
const readOnly = (flags) => flags === undefined || flags === null || flags === "r" || flags === "rs" || (typeof flags === "number" && (flags & 3) === 0 && (flags & (64 | 512 | 1024)) === 0);
const ALWAYS = ["writeFileSync","writeFile","appendFileSync","appendFile","createWriteStream","mkdirSync","mkdir","mkdtempSync","mkdtemp","rmSync","rm","unlinkSync","unlink","renameSync","rename","copyFileSync","copyFile","truncateSync","truncate","writeSync","write","symlinkSync","symlink","utimesSync","chmodSync","chmod","cpSync","cp"];
const OPEN = ["openSync","open"];
for (const [mod, name] of [[fs, "fs"], [fsp, "fsp"]]) {
  for (const fn of ALWAYS) if (typeof mod[fn] === "function") { const o = mod[fn]; mod[fn] = function (...a) { process.stderr.write("WRITE-ATTEMPT " + name + "." + fn + "\\n"); return o.apply(this, a); }; }
  for (const fn of OPEN) if (typeof mod[fn] === "function") { const o = mod[fn]; mod[fn] = function (...a) { if (!readOnly(a[1])) process.stderr.write("WRITE-ATTEMPT " + name + "." + fn + "\\n"); return o.apply(this, a); }; }
}
syncBuiltinESMExports();
`;

let dir: string;
let pem: string;
let publicKey: CryptoKey;
let keyFile: string;
let spyFile: string;
beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "apple-mint-test-"));
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  publicKey = kp.publicKey;
  pem = block(toB64(new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey))).replace(/(.{64})/g, "$1\n"));
  keyFile = join(dir, "AuthKey_TEST.p8");
  writeFileSync(keyFile, pem);
  spyFile = join(dir, "write-spy.mjs");
  writeFileSync(spyFile, SPY);
}, 30_000);
afterAll(() => rmSync(dir, { recursive: true, force: true }));

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
}
// Run under Node's permission model: read anywhere, WRITE NOWHERE. If the tool tried to write a file, spawn a process or open a worker, it would be denied.
function run(args: string[], input?: string, nodeArgs: string[] = []): Run {
  const r = spawnSync(process.execPath, ["--permission", "--allow-fs-read=*", ...nodeArgs, TOOL, ...args], { input, encoding: "utf8", cwd: dir, env: { ...process.env, TMPDIR: dir } });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

const decode = (jwt: string) => {
  const [h, c, s] = jwt.split(".");
  const j = (x: string) => JSON.parse(new TextDecoder().decode(fromBase64UrlStrict(x)!));
  return { header: j(h!), claims: j(c!), signingInput: `${h}.${c}`, sig: fromBase64UrlStrict(s!)! };
};
const verifies = async (jwt: string) => {
  const d = decode(jwt);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, d.sig.slice().buffer, new TextEncoder().encode(d.signingInput));
};
/** True if any 24-character window of the key's base64 body appears in `out` (a leak of key material, even partial). */
const leaksKey = (out: string) => {
  const body = pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
  for (let i = 0; i + 24 <= body.length; i += 8) if (out.includes(body.slice(i, i + 24))) return true;
  return false;
};

describe("minting", () => {
  it("reads the key from a FILE, prints exactly one JWT line on stdout, and the JWT is the server's own client-secret shape, verifiable with the public key", async () => {
    const r = run([...IDS, "--key-file", keyFile, "--lifetime-days", "30"]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+\n$/);
    const jwt = r.stdout.trim();
    const d = decode(jwt);
    expect(d.header).toEqual({ alg: "ES256", kid: "KEYX" });
    expect(d.claims).toMatchObject({ iss: "TEAMX", sub: "com.example.app", aud: "https://appleid.apple.com" });
    expect(d.claims.exp - d.claims.iat).toBe(30 * 86_400);
    expect(Math.abs(d.claims.iat - Date.now() / 1000)).toBeLessThan(60);
    expect(await verifies(jwt)).toBe(true);
  });

  it("reads the key from STDIN with `--key-file -`", async () => {
    const r = run([...IDS, "--key-file", "-"], pem);
    expect(r.status).toBe(0);
    expect(await verifies(r.stdout.trim())).toBe(true);
    expect(decode(r.stdout.trim()).claims.exp - decode(r.stdout.trim()).claims.iat).toBe(150 * 86_400); // the default
  });

  it("accepts a one-line key with literal backslash-n, CRLF and a leading BOM (the shared parser's forms)", async () => {
    for (const form of [pem.trim().replace(/\n/g, "\\n"), pem.replace(/\n/g, "\r\n"), `\ufeff${pem}`]) {
      const r = run([...IDS, "--key-file", "-"], form);
      expect(r.status).toBe(0);
      expect(await verifies(r.stdout.trim())).toBe(true);
    }
  });

  it("never lets key material or the JWT reach stderr, and writes NOTHING to disk (the permission model would have denied it, and the directory stays as it was)", () => {
    const before = readdirSync(dir).sort();
    const r = run([...IDS, "--key-file", keyFile]);
    expect(r.status).toBe(0);
    expect(leaksKey(r.stderr)).toBe(false);
    expect(r.stderr).not.toContain(r.stdout.trim());
    expect(r.stderr).not.toMatch(/ERR_ACCESS_DENIED/);
    expect(readdirSync(dir).sort()).toEqual(before);
    // and the source names no file-writing API at all
    const src = readFileSync(TOOL, "utf8").replace(/\/\/.*$/gm, "");
    expect(src).not.toMatch(/writeFile|appendFile|createWriteStream|copyFile|rename|mkdtemp|mkdir|openSync|truncate|unlink|\bcp\b|child_process|execSync|spawn/);
  });
});

describe("no write is even ATTEMPTED (a swallowed denied write would not show in the exit code)", () => {
  const spied = (args: string[], input?: string) => run(args, input, ["--import", spyFile]);

  it("the spy itself works: a write wrapped in a swallowing try/catch is still reported (control)", () => {
    const script = join(dir, "swallow.mjs");
    writeFileSync(script, 'import fs from "node:fs"; try { fs.writeFileSync("x.txt", "y"); } catch {}\nimport fsp from "node:fs/promises"; try { await fsp.open("y.txt", "w"); } catch {}\n');
    const r = spawnSync(process.execPath, ["--permission", "--allow-fs-read=*", "--import", spyFile, script], { encoding: "utf8", cwd: dir });
    expect(r.status).toBe(0); // the denied writes were swallowed
    expect(r.stderr).toContain("WRITE-ATTEMPT fs.writeFileSync");
    expect(r.stderr).toContain("WRITE-ATTEMPT fsp.open");
  });

  it("minting from a file, from stdin, and every failure path attempts no write", () => {
    const runs = [
      spied([...IDS, "--key-file", keyFile]),
      spied([...IDS, "--key-file", "-"], pem),
      spied([...IDS, "--key-file", "-"], "garbage"),
      spied([...IDS, "--key-file", join(dir, "nope.p8")]),
      spied([...IDS, "--key-file", keyFile, "--lifetime-days", "999"]),
      spied([...IDS, "--key", "x"]),
    ];
    expect(runs.map((r) => r.status)).toEqual([0, 0, 1, 2, 2, 2]);
    for (const r of runs) expect(r.stderr).not.toContain("WRITE-ATTEMPT");
  });

  it("the only fs import is `readFileSync` (no fs/promises, no require, no other node:fs name)", () => {
    const src = readFileSync(TOOL, "utf8").replace(/\/\/.*$/gm, "");
    expect([...src.matchAll(/^import .* from "([^"]+)";/gm)].map((m) => m[1])).toEqual(["node:fs"]);
    expect(src).toContain('import { readFileSync } from "node:fs";');
    expect(src).not.toMatch(/fs\/promises|require\(|process\.binding|\bfs\.|node:(?!fs")/);
  });
});

describe("the lifetime cap", () => {
  it("accepts up to 180 days and REFUSES more (exit 2, nothing minted), not clamping it", () => {
    expect(run([...IDS, "--key-file", keyFile, "--lifetime-days", "180"]).status).toBe(0);
    for (const bad of ["181", "365", "1e9", "Infinity"]) {
      const r = run([...IDS, "--key-file", keyFile, "--lifetime-days", bad]);
      expect([bad, r.status, r.stdout]).toEqual([bad, 2, ""]);
    }
  });

  it("refuses a non-positive or non-numeric lifetime", () => {
    for (const bad of ["0", "-5", "abc", "NaN"]) {
      const r = run([...IDS, "--key-file", keyFile, "--lifetime-days", bad]);
      expect([bad, r.status, r.stdout]).toEqual([bad, 2, ""]);
    }
  });
});

describe("the key never travels on the command line", () => {
  it("refuses an argument that looks like a private key, without echoing it", () => {
    const r = run([...IDS, "--key-file", pem]);
    expect(r.status).toBe(2);
    expect(r.stdout).toBe("");
    expect(leaksKey(r.stderr)).toBe(false);
    expect(r.stderr).toMatch(/command line/);
  });

  it("has no option that takes the key's text (--private-key, --key, --key-pem are unknown options), and a literal-looking value is refused", () => {
    for (const opt of ["--private-key", "--key", "--key-pem", "--p8"]) {
      const r = run([...IDS, opt, "abc"]);
      expect([opt, r.status, r.stdout]).toEqual([opt, 2, ""]);
      expect(r.stderr, opt).toContain(`unknown option ${opt}`);
      // the same option with the key file supplied still fails: it is unknown, not merely redundant
      expect(run([...IDS, "--key-file", keyFile, opt, "abc"]).status, `${opt} with a key file`).toBe(2);
      expect(run([...IDS, "--key-file", keyFile, `${opt}=abc`]).stderr, `${opt}=`).toContain(`unknown option ${opt}`);
    }
  });
});

describe("bad usage and bad keys fail closed", () => {
  it("each required option is required (exit 2)", () => {
    for (const drop of ["--team-id", "--key-id", "--client-id"]) {
      const i = IDS.indexOf(drop);
      const args = [...IDS.slice(0, i), ...IDS.slice(i + 2), "--key-file", keyFile];
      expect([drop, run(args).status]).toEqual([drop, 2]);
    }
    expect(run(IDS).status).toBe(2);
  });

  it("ids with whitespace, an empty stdin and an unreadable path are refused (exit 2)", () => {
    expect(run(["--team-id", "TEA MX", "--key-id", "KEYX", "--client-id", "c", "--key-file", keyFile]).status).toBe(2);
    expect(run([...IDS, "--key-file", "-"], "").status).toBe(2);
    expect(run([...IDS, "--key-file", join(dir, "does-not-exist.p8")]).status).toBe(2);
  });

  it("a key that is not a PKCS#8 P-256 private key mints nothing (exit 1), and its text never reaches an output", async () => {
    const rsa = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const rsaPem = block(toB64(new Uint8Array(await crypto.subtle.exportKey("pkcs8", rsa.privateKey))).replace(/(.{64})/g, "$1\n"));
    for (const bad of ["garbage not a key", rsaPem, pem.replace("END PRIVATE", "END PUBLIC"), `${pem}${pem}`]) {
      const r = run([...IDS, "--key-file", "-"], bad);
      expect([r.status, r.stdout]).toEqual([1, ""]);
      const probe = bad.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "").slice(0, 24);
      expect(probe.length).toBeGreaterThan(10);
      expect(r.stderr).not.toContain(probe);
    }
  });
});
