// @ts-check
/**
 * What went INTO the bundle, from esbuild's own metafile (not from a regex over the source): every input must be a file of this package's `src/`
 * (or one of the exact SHARED_FILES below, or, for the Playwright build only, the e2e harness), and nothing may come from `node_modules`. A regex over `import ... from` cannot see a
 * side-effect `import "pkg"`, a dynamic `import("pkg")`, a `require("pkg")` or a re-export; the bundler's list of inputs sees all of them,
 * because it had to resolve and read every one to build the output.
 *
 * `scripts/build.mjs` runs this on every build (a finding fails the build); `test/source-scan.test.ts` runs it on a real build and on temp-dir
 * fixtures that import a package each of those ways.
 */

/** Paths (relative to the package root, `/` separated) an input may live under. */
export const SOURCE_ROOTS = ["src/"];
/**
 * The only files OUTSIDE `src/` a build may bundle: the S1.3 browser-derivation contract and the base64url helpers it imports (design 19.4: "import by
 * relative path, or reproduce exactly"). They are Web Crypto only, shared with the Edge and the database tests, and importing them (rather than copying) is
 * what keeps the browser's derivation byte-identical to the server's. An exact-path list, not a directory: a new shared file is a deliberate edit here.
 */
export const SHARED_FILES = [
  "../../supabase/functions/_shared/partner/pin-contract.ts",
  "../../supabase/functions/_shared/partner/pin-deny-list.ts",
  "../../supabase/functions/_shared/partner/token.ts",
];
/** The Playwright build also bundles its harness page. */
export const HARNESS_ROOTS = ["test/e2e/harness/"];

/**
 * @param {{ inputs: Record<string, unknown> }} metafile esbuild's `metafile`
 * @param {{ harness?: boolean }} [opts]
 * @returns {string[]} one line per offending input; empty when clean
 */
export function checkBundleInputs(metafile, opts = {}) {
  const roots = opts.harness ? [...SOURCE_ROOTS, ...HARNESS_ROOTS] : SOURCE_ROOTS;
  const names = Object.keys(metafile.inputs);
  /** @type {string[]} */
  const findings = [];
  if (names.length === 0) findings.push("the bundle has no inputs (the check would pass vacuously)");
  for (const raw of names) {
    const name = raw.split("\\").join("/").replace(/^(?:\.\/)+/, "");
    if (name.split("/").includes("node_modules")) findings.push(`${raw}: comes from node_modules`);
    else if (!roots.some((r) => name.startsWith(r)) && !SHARED_FILES.includes(name)) findings.push(`${raw}: is outside ${roots.join(", ")}`);
  }
  return findings;
}
