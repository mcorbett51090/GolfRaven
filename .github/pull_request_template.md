## What

<!-- What does this PR change, and why? -->

## Phase / build-plan reference

<!-- Which build-plan phase/section does this belong to? e.g. "P1 §4.1" -->

## Checklist

- [ ] `pnpm -r typecheck` passes
- [ ] `pnpm -r build` passes
- [ ] `pnpm -r test` passes
- [ ] No secrets in this diff (gitleaks runs in CI, but check before pushing)
- [ ] If this changes a facility's `url`, `phone` or any `booking[].url` host: the `contact-reviewed` label is applied and its out-of-band checklist is done (build plan §6.3)
- [ ] If this changes geometry (centroid moved > 150 m or area changed > 25%): the `geometry-reviewed` label is applied (build plan §15)

## Security overlay (build plan §10)

- [ ] Secrets only in platform stores, never in code or CI logs
- [ ] No new outbound host without an allow-list entry
