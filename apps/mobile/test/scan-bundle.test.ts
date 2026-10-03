/**
 * MEDIUM-2 (PR #38 gate): Metro's transform cache ignores `EXPO_PUBLIC_*` values, so a secret inlined into an earlier export can ship again after the
 * variable is unset. `scripts/scan-bundle.mjs` scans the export OUTPUT for a non-anon JWT and an `sb_secret_` key; `scripts/export-and-scan.mjs`
 * runs it after `expo export` over the same directory. Run here as real child processes on temp directories.
 */
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { b64url } from "./support/fakes";

const SCAN = fileURLToPath(new URL("../scripts/scan-bundle.mjs", import.meta.url));
const EXPORT = fileURLToPath(new URL("../scripts/export-and-scan.mjs", import.meta.url));
const jwt = (role: unknown) => `${b64url('{"alg":"HS256","typ":"JWT"}')}.${b64url(JSON.stringify({ iss: "supabase", ref: "abcdefgh", role }))}.${b64url("signature-signature")}`;
const SB_SECRET = `sb_secret_${"abcdefghijklmnopqrstuvwxyz0123456789"}`;

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), "gr-scan-"));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

/** A fake export directory: `files` maps a relative path to its text; the scan is run over it. */
function scan(files: Record<string, string | Buffer>) {
  const dir = tmp();
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(join(dir, name, ".."), { recursive: true });
    writeFileSync(join(dir, name), content);
  }
  const r = spawnSync(process.execPath, [SCAN, dir], { encoding: "utf8" });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
}
const BUNDLE = (inlined: string) => `var a=1;var b={url:"https://x.supabase.co",key:"${inlined}"};console.log(a.b.c,b);`;

describe("scripts/scan-bundle.mjs", () => {
  it("a clean export passes and says ok", () => {
    const r = scan({ "_expo/static/js/ios/index.js": BUNDLE("sb_publishable_abcdefghijklmnopqrstuvwxyz"), "assets/logo.png": Buffer.from([0, 1, 2, 255]) });
    expect(r.code).toBe(0);
    expect(r.out).toContain("scan-bundle: ok");
  });

  it("an anon JWT passes (the anon key is meant to ship)", () => {
    expect(scan({ "index.js": BUNDLE(jwt("anon")) }).code).toBe(0);
  });

  it("ANY occurrence of `sb_secret_` is a finding (no length threshold): the bare prefix, a short body, a body of any characters, anywhere in a text or a Hermes-style packed binary", () => {
    for (const text of [`if(v.startsWith("sb_secret_"))return null;`, "sb_secret_", "sb_secret_x", "xx sb_secret_ yy", `{"k":"sb_secret_shaped"}`, "SB_SECRET_NOT"]) {
      const r = scan({ "index.js": text });
      expect(r.code, text).toBe(text === "SB_SECRET_NOT" ? 0 : 1); // case-sensitive: only the real prefix
      if (r.code === 1) {
        expect(r.out).toContain("index.js: sb_secret_key");
        expect(r.out).not.toContain("sb_secret_x");
      }
    }
    const packed = scan({ "index.android.bundle.hbc": Buffer.from("Missing default exportsb_secret_shapedThe 'responseT", "latin1") });
    expect(packed.code).toBe(1);
    expect(packed.out).toContain("sb_secret_key");
  });

  it("the app's own sources build the prefix from parts, so a clean export has no occurrence: no code line of src/ or app/ contains the literal", () => {
    const strip = (t: string): string => t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
    const offenders: string[] = [];
    const walk = (dir: string): void => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, e.name);
        if (e.isDirectory()) walk(p);
        else if (/\.(ts|tsx|js|jsx)$/.test(e.name) && strip(readFileSync(p, "utf8")).includes("sb_secret_")) offenders.push(p);
      }
    };
    walk(fileURLToPath(new URL("../src", import.meta.url)));
    walk(fileURLToPath(new URL("../app", import.meta.url)));
    expect(offenders).toEqual([]);
  });

  it("a JWT with no role claim, or a payload that is not JSON, passes (not a Supabase key)", () => {
    expect(scan({ "index.js": BUNDLE(`${b64url('{"alg":"none"}')}.${b64url('{"sub":"x"}')}.${b64url("s")}`) }).code).toBe(0);
    expect(scan({ "index.js": BUNDLE(`eyJhbGciOiJIUzI1NiJ9.${b64url("not json at all")}.c2ln`) }).code).toBe(0);
  });

  it("a service_role JWT fails, naming the file and the kind but NEVER the value", () => {
    const secret = jwt("service_role");
    const r = scan({ "_expo/static/js/android/index.hbc": BUNDLE(secret) });
    expect(r.code).toBe(1);
    expect(r.out).toContain("_expo/static/js/android/index.hbc");
    expect(r.out).toContain("jwt_non_anon_role");
    expect(r.out).not.toContain(secret);
    expect(r.out).not.toContain(secret.slice(0, 24));
    expect(r.out).not.toContain(secret.split(".")[1]!);
  });

  it("any other non-anon role fails too (authenticated)", () => {
    expect(scan({ "index.js": BUNDLE(jwt("authenticated")) }).code).toBe(1);
  });

  it("an sb_secret_ key fails, by kind only", () => {
    const r = scan({ "index.js": BUNDLE(SB_SECRET) });
    expect(r.code).toBe(1);
    expect(r.out).toContain("sb_secret_key");
    expect(r.out).not.toContain(SB_SECRET);
    expect(r.out).not.toContain("abcdefghijklmnop");
  });

  it("finds a secret inside a binary file (Hermes bytecode keeps its strings as plain bytes) and in a nested directory", () => {
    const bin = Buffer.concat([Buffer.from([0xc0, 0x1f, 0xbc, 0x03, 0x00, 0xff]), Buffer.from(SB_SECRET, "latin1"), Buffer.from([0x00, 0xfe])]);
    const r = scan({ "a/b/c/index.android.bundle.hbc": bin });
    expect(r.code).toBe(1);
    expect(r.out).toContain("a/b/c/index.android.bundle.hbc");
  });

  it("a secret next to a clean file still fails; one line per file and kind however often it repeats", () => {
    const r = scan({ "ok.js": "var x=1;", "bad.js": `${BUNDLE(SB_SECRET)}${BUNDLE(SB_SECRET)}` });
    expect(r.code).toBe(1);
    expect(r.out.match(/bad\.js: sb_secret_key/g)).toHaveLength(1);
    expect(r.out).not.toContain("ok.js:");
  });

  it("exits 2 (not clean) when the directory is missing or holds no files: an unscanned export is not a clean one", () => {
    const missing = spawnSync(process.execPath, [SCAN, join(tmp(), "nope")], { encoding: "utf8" });
    expect(missing.status).toBe(2);
    expect(missing.stderr).toMatch(/could not run/);
    expect(scan({}).code).toBe(2);
  });
});

describe("scripts/export-and-scan.mjs (a stub `expo` on PATH)", () => {
  /** A project dir whose `expo` stub records its arguments and writes `payload` to <output-dir>/index.js, exiting `exitCode`. */
  function runExport(args: string[], payload: string, exitCode = 0) {
    const cwd = tmp();
    const bin = join(cwd, "bin");
    mkdirSync(bin);
    writeFileSync(
      join(bin, "expo"),
      `#!${process.execPath}
const fs = require("node:fs"); const path = require("node:path");
const a = process.argv.slice(2); fs.writeFileSync(path.join(${JSON.stringify(cwd)}, "expo-args.json"), JSON.stringify(a));
let out = "dist"; for (let i = 0; i < a.length; i++) { if (a[i] === "--output-dir" || a[i] === "-o") out = a[i + 1]; else if (a[i].startsWith("--output-dir=")) out = a[i].slice(13); }
fs.mkdirSync(path.resolve(out), { recursive: true }); fs.writeFileSync(path.join(path.resolve(out), "index.js"), ${JSON.stringify(payload)});
process.exit(${exitCode});
`,
    );
    chmodSync(join(bin, "expo"), 0o755);
    const r = spawnSync(process.execPath, [EXPORT, ...args], { cwd, encoding: "utf8", env: { PATH: `${bin}:${process.env.PATH ?? ""}` } as unknown as NodeJS.ProcessEnv });
    return { code: r.status, out: `${r.stdout}${r.stderr}`, cwd, expoArgs: JSON.parse(readFileSync(join(cwd, "expo-args.json"), "utf8")) as string[] };
  }

  it("forwards its arguments to `expo export` and scans the default output directory (dist)", () => {
    const r = runExport(["--clear", "--platform", "ios"], BUNDLE(jwt("anon")));
    expect(r.expoArgs).toEqual(["export", "--clear", "--platform", "ios"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("scan-bundle: ok");
  });

  it("scans the directory the caller chose, in both spellings `expo export` has, not just `dist`", () => {
    for (const flags of [["--output-dir", "out1"], ["--output-dir=out2"]]) {
      const r = runExport(["--clear", "--platform", "android", ...flags], BUNDLE(SB_SECRET));
      expect(r.code, flags.join(" ")).toBe(1);
      expect(r.out).toContain("index.js: sb_secret_key");
    }
  });

  it("`-o` is not a flag of `expo export` (its help lists only --output-dir), so it no longer redirects the scan", async () => {
    const { outputDirOf } = (await import(EXPORT)) as { outputDirOf: (argv: string[]) => string };
    expect(outputDirOf(["--output-dir", "a"])).toBe("a");
    expect(outputDirOf(["--output-dir=b"])).toBe("b");
    expect(outputDirOf(["-o", "c"])).toBe("dist");
    expect(readFileSync(EXPORT, "utf8")).not.toMatch(/"-o"/);
  });

  it("no `expo` on PATH (ENOENT): says so, names the cause, exits 2 (could not run) and scans nothing", () => {
    const cwd = tmp();
    const r = spawnSync(process.execPath, [EXPORT, "--platform", "ios"], { cwd, encoding: "utf8", env: { PATH: join(cwd, "empty-bin") } as unknown as NodeJS.ProcessEnv });
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/could not run `expo export`/);
    expect(r.stderr).toMatch(/ENOENT/);
    expect(r.stdout + r.stderr).not.toContain("scan-bundle");
  });

  it("a failed export keeps expo's exit code and does not scan", () => {
    const r = runExport(["--platform", "ios"], BUNDLE(SB_SECRET), 7);
    expect(r.code).toBe(7);
    expect(r.out).not.toContain("scan-bundle");
  });
});

describe("package.json wires the scan after the export, with --clear", () => {
  const scripts = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { scripts: Record<string, string> }).scripts;
  it.each(["ios", "android"])("export:%s clears Metro's cache and runs the scan wrapper", (p) => {
    expect(scripts[`export:${p}`]).toContain("--clear");
    expect(scripts[`export:${p}`]).toContain(`export-and-scan.mjs --clear --platform ${p}`);
  });
  it("the wrapper runs `expo export` then scan-bundle.mjs, in that order", () => {
    const src = readFileSync(EXPORT, "utf8");
    expect(src).toMatch(/spawnSync\("expo", \["export", \.\.\.args\]/);
    expect(src.indexOf('spawnSync("expo"')).toBeLessThan(src.indexOf('join(here, "scan-bundle.mjs")'));
  });
});
