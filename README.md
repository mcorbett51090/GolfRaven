# GolfRaven

GolfRaven tracks a golfer's rounds against a trail's official course
roster and confirms completion — with a finisher's marker to show for it.
It launches with two pilot trails, the Tennessee Golf Trail and the
Vancouver Island Golf Trail, and expands from there. See the full plan at
[`../docs/golf-trails/02-build-plan.md`](../docs/golf-trails/02-build-plan.md)
(architecture in §3, this repo's layout at §3.1). **This link points into
the `RavenGolf` repo** (the plan lives there, not here) and will break
once `golfraven/` is extracted to its own repo — see "Staging note" below.

This is the **P0 monorepo skeleton**: workspace plumbing, placeholder
packages/apps, and the P0 deliverables (the K2 landing page, the Android
Health Connect reader for check X1). Almost nothing here is the real
product yet — each package/app README says what phase actually builds it.

## Staging note

**This directory is staged inside the `RavenGolf` repo, not yet its own
repo.** The build plan (§3.1) calls for a dedicated `golfraven` repo, but
that repo could not be created yet, so this monorepo lives at
`RavenGolf/golfraven/` for now. It is written to need **no changes** when
it moves:

- Every path inside `golfraven/` (workspace globs, CODEOWNERS, config
  files) is relative to `golfraven/` itself, never to the `RavenGolf`
  repo root.
- The one exception is CI: a GitHub Actions workflow only runs from
  `.github/workflows/` at whatever the repo root is, so the **live**
  workflow currently sits at `RavenGolf/.github/workflows/golfraven-ci.yml`
  (repo root) and scopes itself into `golfraven/` via
  `defaults.run.working-directory: golfraven`. A post-extraction copy —
  equivalent apart from working-directory, cache path and comments (the
  jobs themselves are the same) — already lives at
  `golfraven/.github/workflows/ci.yml`, so extraction needs no CI edit,
  just moving that file up to `.github/workflows/`.
- Extraction itself is `git subtree split --prefix=golfraven` from the
  `RavenGolf` repo, pushed to the new `golfraven` repo as its initial
  history.

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
│   ├── catalog/     @golfraven/catalog — the catalog schema SSOT.
│   │                Placeholder — P1 defines the real schema (§4.1).
│   ├── matching/    @golfraven/matching — course matching from a route.
│   │                Placeholder — real logic lands from P1/§7.4.
│   └── rules/       @golfraven/rules — scoring/eligibility rules.
│                    Placeholder — real logic lands from P1/§8.
├── supabase/        Player plane (Postgres + RLS + Auth + Edge
│                    Functions). Placeholder — migrations arrive P3.
├── data/            Catalog content (git, PR-reviewed). Placeholder —
│                    seeded data arrives P1.
├── .gitleaks.toml   gitleaks config (at the golfraven/ root, not under
│                    .github/ — used by both the live workflow and the
│                    post-extraction copy below).
└── .github/         CODEOWNERS, PR template, the post-extraction CI copy.
```

Each package/app has its own `README.md` explaining what phase actually
builds it — most of this skeleton is intentionally placeholder.

## How to build

Requires **pnpm 10.33.0** (pinned via `packageManager` in `package.json`;
`corepack enable` picks it up automatically) and **Node ≥ 24** (`.nvmrc`).

```shell
cd golfraven
pnpm install --frozen-lockfile
pnpm -r typecheck
pnpm -r build
pnpm -r test
```

If your local Node is older than 24 (engines is enforced via
`engine-strict=true` in `.npmrc`), you can still run these commands
locally with `pnpm --config.engine-strict=false <command>` — CI always
runs on Node 24 and enforces the real engines constraint, so this is a
local-only workaround, never something to weaken in CI.

## CI

`golfraven-ci.yml` (see "Staging note" above) runs on every PR and every
push to `main`, with **no `paths:` filter** — it always evaluates, so a
consumer of this workflow never sees a check stuck pending. It installs
with a frozen lockfile, then runs `pnpm -r typecheck`, `pnpm -r build`,
`pnpm -r test`, and a gitleaks secret scan, all pinned to full commit
SHAs (see the workflow file for the exact SHA → version mapping).
