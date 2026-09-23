#!/usr/bin/env node
// Minimal smoke test for the landing page. No test framework — this is a
// static, dependency-free page, so a small script that greps the built
// HTML is enough to catch the two failure modes that matter most:
//   1. a third-party script/stylesheet sneaking in (the page promises none)
//   2. the "no endpoint configured" default silently changing
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = join(here, "..", "src");
// dist/ is what actually ships (scripts/build.mjs copies src/ -> dist/
// verbatim); check the built output, not just the source, so a stale or
// hand-edited dist/ can't drift from src/ unnoticed (gate review N6).
const distDir = join(here, "..", "dist");

let failures = 0;

function fail(message) {
  failures += 1;
  console.error(`FAIL: ${message}`);
}

function ok(message) {
  console.log(`ok: ${message}`);
}

const html = await readFile(join(distDir, "index.html"), "utf8");
const config = await readFile(join(distDir, "config.js"), "utf8");

// No third-party origins referenced from any src/href — including
// protocol-relative references ("//host/...") which the previous
// https?:// -only pattern missed (gate review N6).
const externalRefs = [
  ...html.matchAll(/(?:src|href)="((?:https?:)?\/\/[^"]+)"/g),
].map((m) => m[1]);
if (externalRefs.length > 0) {
  fail(`found external script/link references: ${externalRefs.join(", ")}`);
} else {
  ok("no external script/link references in index.html");
}

// Local scripts referenced are exactly config.js and main.js (plus the
// local stylesheet) — nothing else is loaded.
const localScripts = [...html.matchAll(/<script src="([^"]+)"/g)].map((m) => m[1]);
const expectedScripts = ["config.js", "main.js"];
if (
  localScripts.length !== expectedScripts.length ||
  !expectedScripts.every((s) => localScripts.includes(s))
) {
  fail(`expected scripts ${expectedScripts.join(", ")}, found ${localScripts.join(", ")}`);
} else {
  ok("only the expected local scripts are loaded");
}

// SIGNUP_ENDPOINT defaults to empty, so "signups open soon" is the
// out-of-the-box behaviour until an endpoint is wired up.
if (!/window\.SIGNUP_ENDPOINT\s*=\s*("|')("|')\s*;/.test(config)) {
  fail("config.js does not default SIGNUP_ENDPOINT to an empty string");
} else {
  ok("SIGNUP_ENDPOINT defaults to empty (signups closed by default)");
}

// The required copy elements are present.
const requiredStrings = [
  "Tennessee Golf Trail",
  "Vancouver Island Golf Trail",
  "finisher's marker",
  "confirmation email",
  "16 years of age or older",
  "Unsubscribe any time",
];
for (const needle of requiredStrings) {
  if (!html.includes(needle)) {
    fail(`index.html is missing required copy: "${needle}"`);
  }
}
if (requiredStrings.every((needle) => html.includes(needle))) {
  ok("all required copy present (trails, finisher's marker, double opt-in, 16+, unsubscribe)");
}

// Deploy guard (gate review S5): the page must not ship with the
// [OPERATING ENTITY NAME — TBD] / [CONTACT EMAIL — TBD] placeholders once
// a real deploy is attempted. This only fails the build when DEPLOY=1 is
// set, so local/dev/CI builds of the still-placeholder page stay green
// until the owner fills these in and actually deploys (see README.md
// "Before this page goes live").
const placeholderPattern = /\[\s*(OPERAT\w*|CONTACT)[^\]]*\]/i;
const hasPlaceholder = placeholderPattern.test(html);
if (process.env.DEPLOY === "1") {
  if (hasPlaceholder) {
    fail(
      "index.html still contains an [OPERATING ENTITY NAME…]/[CONTACT EMAIL…] placeholder and DEPLOY=1 is set — fill these in before deploying (see README.md \"Before this page goes live\")",
    );
  } else {
    ok("no [OPERATING ENTITY NAME…]/[CONTACT EMAIL…] placeholders found (DEPLOY=1 checked)");
  }
} else if (hasPlaceholder) {
  ok("placeholders present but DEPLOY=1 is not set — not blocking a non-deploy build");
}

if (failures > 0) {
  console.error(`\n${failures} check(s) failed.`);
  process.exit(1);
}

console.log("\nAll landing page smoke checks passed.");
