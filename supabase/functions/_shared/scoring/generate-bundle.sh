#!/usr/bin/env bash
# supabase/functions/_shared/scoring/generate-bundle.sh
#
# Regenerates the `vendor/` tree: verbatim copies of the small slice of
# `packages/rules/dist` (+ the `packages/catalog/dist` functions it
# depends on) that `scorePlay`/`parseScorePlayInput`/`parseEvidence`
# actually need, with ONLY their bare-specifier imports rewritten —
# `packages/rules/src` (via `packages/rules/dist`, its own build output)
# stays the single source of truth; nothing here is hand-authored logic.
#
# WHY VENDORED COPIES, NOT A BUNDLE (round 2 of this design — see git
# history/PR discussion for the first, abandoned approach): an esbuild
# bundle that INLINES a third-party dependency's source (zod, @noble/
# hashes, tz-lookup) turns their code into a FILE ON DISK under
# supabase/functions — and tools/service-role-lint's global-reference /
# dynamic-code-execution checks (banned-global-reference,
# globalthis-access, dynamic-code-execution) scan every such file's full
# AST CONTENT, independent of how its code got there. zod v4's own
# environment-detection internals (`typeof process`, `globalThis`,
# `.constructor`/`Object.getPrototypeOf` structural-clone helpers) tripped
# dozens of findings once inlined — confirmed this session
# (`node tools/service-role-lint/dist/cli.js supabase/functions`).
#
# A NORMAL import through the reviewed `supabase/functions/deno.json`
# import map, by contrast, is lint-INVISIBLE for exactly this concern:
# the lint only walks FILES ON DISK under supabase/functions — a
# dependency resolved to a pinned CDN URL is fetched by Deno at runtime
# and never exists as a local file for the lint to scan at all. That is
# the mechanism this script uses: every genuinely third-party dependency
# (zod, @noble/hashes, tz-lookup) is left as an ordinary bare-specifier
# import, resolved through deno.json's import map to an EXACT, pinned
# target on tools/service-role-lint/pinned-import-targets.json — the
# reviewed-dependency mechanism the lint's own model
# (tools/service-role-lint/src/config.ts) is built around. Only OUR OWN
# first-party logic (score-play.js, parse-evidence.js, internal/
# classify.js, and the two catalog functions parse-evidence.js calls)
# is copied in as local files — confirmed clean of every one of those
# same checks (grepped for process/globalThis/self/.constructor/
# getPrototypeOf/Reflect./eval/new Function — zero matches).
#
# What gets rewritten, and how:
#   - Cross-file imports among the vendored files themselves stay
#     RELATIVE and are kept relative (they already resolve inside this
#     vendor/ tree once copied together with the same layout).
#   - `import ... from "@golfraven/catalog"` (parse-evidence.js) is
#     rewritten to a RELATIVE import of the small `catalog/index.js` this
#     script also writes (re-exporting exactly `canonicalizeTimeZone`/
#     `isValidIanaTimeZoneName` from the two vendored catalog files) —
#     this is OUR OWN code being redirected to OUR OWN vendored copy, not
#     a third-party dependency, so no import-map entry is needed for it.
#   - `import ... from "zod"` / `"@noble/hashes/utils.js"` /
#     `"@noble/hashes/sha2.js"` (score-play.js, parse-evidence.js) and
#     `import tzlookup from "tz-lookup"` (catalog/geo.js) are LEFT AS
#     BARE SPECIFIERS — resolved via supabase/functions/deno.json's
#     import map, which this script does NOT touch (a pinned import-map
#     entry is a reviewed, one-time addition to that file + pinned-
#     import-targets.json, not something to regenerate).
#
# Run this after any change to packages/rules/src or packages/catalog/src
# (after `pnpm -r build`, so packages/*/dist is fresh) and commit the
# regenerated vendor/ tree alongside it.
# supabase/tests/unit/rules-vendor-freshness.test.ts fails CI if it drifts
# from a fresh copy.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
VENDOR_DIR="${SCRIPT_DIR}/vendor"

if [ ! -f "${REPO_ROOT}/pnpm-workspace.yaml" ]; then
  echo "generate-bundle.sh: could not locate repo root (expected pnpm-workspace.yaml at ${REPO_ROOT})" >&2
  exit 1
fi
for pkg in packages/rules packages/catalog; do
  if [ ! -d "${REPO_ROOT}/${pkg}/dist" ]; then
    echo "generate-bundle.sh: ${pkg}/dist is missing — run 'pnpm -r build' first" >&2
    exit 1
  fi
done

rm -rf "${VENDOR_DIR}"
mkdir -p "${VENDOR_DIR}/internal" "${VENDOR_DIR}/catalog"

RULES_DIST="${REPO_ROOT}/packages/rules/dist"
CATALOG_DIST="${REPO_ROOT}/packages/catalog/dist"

cp "${RULES_DIST}/score-play.js" "${VENDOR_DIR}/score-play.js"
cp "${RULES_DIST}/parse-evidence.js" "${VENDOR_DIR}/parse-evidence.js"
cp "${RULES_DIST}/internal/classify.js" "${VENDOR_DIR}/internal/classify.js"
cp "${CATALOG_DIST}/geo.js" "${VENDOR_DIR}/catalog/geo.js"
cp "${CATALOG_DIST}/common.js" "${VENDOR_DIR}/catalog/common.js"
cp "${CATALOG_DIST}/tzdb-backward-links.json" "${VENDOR_DIR}/catalog/tzdb-backward-links.json"
cp "${CATALOG_DIST}/region-codes.json" "${VENDOR_DIR}/catalog/region-codes.json"

# The one rewrite: parse-evidence.js's package-name import of
# "@golfraven/catalog" -> a relative import of the small index this
# script writes below. Confirmed unique (grep) before rewriting, so a
# future second import of the same specifier doesn't go unnoticed.
if [ "$(grep -c 'from "@golfraven/catalog"' "${VENDOR_DIR}/parse-evidence.js")" != "1" ]; then
  echo 'generate-bundle.sh: expected exactly one `from "@golfraven/catalog"` import in parse-evidence.js — packages/rules/src/parse-evidence.ts may have changed; update this script.' >&2
  exit 1
fi
sed -i.bak 's#from "@golfraven/catalog"#from "./catalog/index.js"#' "${VENDOR_DIR}/parse-evidence.js"
rm -f "${VENDOR_DIR}/parse-evidence.js.bak"

cat > "${VENDOR_DIR}/catalog/index.js" <<'EOF'
// GENERATED FILE — DO NOT EDIT BY HAND. See generate-bundle.sh.
// Narrow re-export of exactly the two packages/catalog functions
// parse-evidence.js imports at runtime (NOT the full @golfraven/catalog
// barrel, which pulls in Node-only fs/crypto modules this scoring slice
// never touches).
export { canonicalizeTimeZone } from "./geo.js";
export { isValidIanaTimeZoneName } from "./common.js";
EOF

BANNER='// GENERATED FILE — DO NOT EDIT BY HAND.
// Copied verbatim from packages/rules/dist or packages/catalog/dist (built
// from packages/rules/src / packages/catalog/src — the single source of
// truth) by supabase/functions/_shared/scoring/generate-bundle.sh, which
// also rewrote its "@golfraven/catalog" import to a relative one. Every
// other import (zod, @noble/hashes/*, tz-lookup) is untouched, resolved
// through supabase/functions/deno.json'"'"'s pinned import map. Re-run that
// script after `pnpm -r build` and commit the result.
// supabase/tests/unit/rules-vendor-freshness.test.ts fails CI on drift.
'
for f in "${VENDOR_DIR}/score-play.js" "${VENDOR_DIR}/parse-evidence.js" "${VENDOR_DIR}/internal/classify.js" "${VENDOR_DIR}/catalog/geo.js" "${VENDOR_DIR}/catalog/common.js"; do
  printf '%s' "${BANNER}" | cat - "${f}" > "${f}.tmp" && mv "${f}.tmp" "${f}"
done

echo "vendor tree written: ${VENDOR_DIR}"
