# GolfRaven

GolfRaven tracks a golfer's rounds against a trail's official course
roster and confirms completion — with a finisher's marker to show for it.
Its pilot slate is the Tennessee Golf Trail, the Vancouver Island Golf Trail and
the Robert Trent Jones Golf Trail (Oklahoma Golf Trail in reserve), and it expands
from there. The full build plan lives in the RavenGolf repo:
[`docs/golf-trails/02-build-plan.md`](https://github.com/mcorbett51090/RavenGolf/blob/main/docs/golf-trails/02-build-plan.md) (architecture §3, this repo's
layout §3.1, Phase 0 §10). Every `docs/golf-trails/…` path cited in this repo refers
to that RavenGolf plan set.

This is the **P0 monorepo skeleton**: workspace plumbing, placeholder
packages/apps, and the P0 deliverables (the K2 landing page, the Android
Health Connect reader for check X1). Almost nothing here is the real
product yet — each package/app README says what phase actually builds it.

## Provenance

This repo was staged under `golfraven/` in the RavenGolf repo on 2026-09-23 while it
did not yet exist, then moved here with its history intact via
`git subtree split --prefix=golfraven`. The staging copy in RavenGolf was removed after
the move.

## Layout

```
golfraven/
├── apps/
│   ├── site/       Public site (Astro 5 static). Placeholder — P2 ports
│   │                southern-wine-country here (build plan §5).
│   ├── mobile/      Expo/React Native app. P0 scope: only the Android
│   │                Health Connect reader for check X1 (build plan §10).
│   ├── partners/    Staff/operator/admin portal PWA. Placeholder — P5.
│   ├── ciq/         Garmin Connect IQ "Trail Check-in". Placeholder,
│   │                gated on P0-K4b's feasibility verdict.
│   └── landing/     The K2 landing page (build plan §10 P0, check K2).
├── packages/
│   ├── catalog/     @golfraven/catalog — the catalog schema SSOT: the
│   │                full §4.1 Zod schema (P1a) plus the ID ledger.
│   │                AchievementDef/OfferTerms and loadCatalog() are not
│   │                yet implemented (part B / a later P1 step).
│   ├── matching/    @golfraven/matching — course matching from a route.
│   │                Placeholder — real logic lands from P1/§7.4.
│   └── rules/       @golfraven/rules — scoring/eligibility rules.
│                    Placeholder — real logic lands from P1/§8 (part B).
├── tools/
│   ├── p0/          P0 kill-experiment check tools (build plan §10 P0).
│   └── catalog/     @golfraven/catalog-tools — verify-catalog +
│                    verify-contract (build plan §10 P1 AT(1)/(5)/(7)/(8),
│                    §3.5, §15).
├── supabase/        Player plane (Postgres + RLS + Auth + Edge
│                    Functions). Placeholder — migrations arrive P3.
├── data/            Catalog content (git, PR-reviewed). id-ledger.json
│                    exists in its real format (P1a, empty); real
│                    facility/trail content arrives P1.1+.
├── contract/        contract/catalog.schema.json — generated from
│                    packages/catalog's Zod schema; verify-contract fails
│                    the build on any drift (§3.5).
├── config/          booking-hosts.json — the booking-host allow-list
│                    verify-catalog reads (synthetic/test hosts only,
│                    P1a; real contents wait on X4/X6).
├── .gitleaks.toml   gitleaks config, at the repo root (not under
│                    .github/), consumed by .github/workflows/ci.yml.
└── .github/         CODEOWNERS, PR template, CI workflow (ci.yml).
```

Each package/app has its own `README.md` explaining what phase actually
builds it — most of this skeleton is intentionally placeholder.

## How to build

Requires **pnpm 10.33.0** (pinned via `packageManager` in `package.json`;
`corepack enable` picks it up automatically) and **Node ≥ 24** (`.nvmrc`).

```shell
pnpm install --frozen-lockfile
pnpm -r build
pnpm -r typecheck
pnpm -r test
```

If your local Node is older than 24 (engines is enforced via
`engine-strict=true` in `.npmrc`), you can still run these commands
locally with `pnpm --config.engine-strict=false <command>` — CI always
runs on Node 24 and enforces the real engines constraint, so this is a
local-only workaround, never something to weaken in CI.

## CI

`.github/workflows/ci.yml` (workflow name "golfraven CI") runs on every PR
and every push to `main`, with **no `paths:` filter** — it always
evaluates, so a consumer of this workflow never sees a check stuck
pending. It installs with a frozen lockfile, then runs **Build before
Typecheck** (`pnpm -r build`, then `pnpm -r typecheck`), `pnpm -r test`
(which already includes `verify-contract`'s committed-file check,
`tools/catalog/test/contract-freshness.test.ts`), an explicit
`verify-contract` CLI step for a clearer dedicated failure message, and a
gitleaks secret scan, all pinned to full commit SHAs (see the workflow
file for the exact SHA → version mapping).

**Why Build before Typecheck (gate-review fix, post-e9b3ab0, blocking #1).**
`tools/catalog` resolves `@golfraven/catalog` through its compiled `dist/`
output, so typechecking it on a clean runner before anything is built
failed with `TS2307` (cannot find module). Fixed two ways, deliberately
redundant: (1) `tools/catalog/tsconfig.json` and `tsconfig.build.json` now
declare a TypeScript project reference to `packages/catalog/tsconfig.build.json`
and run via `tsc -b`, so `tsc` builds the dependency's `dist/` automatically
whenever it's missing — typechecking `tools/catalog` alone, from a clean
checkout with **no `dist/` anywhere**, now works with no ordering
requirement at all; (2) CI still runs Build first anyway, as a second,
independent safeguard. See `tools/catalog/README.md`'s "Build ordering"
section.
