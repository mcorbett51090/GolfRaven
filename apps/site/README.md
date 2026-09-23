# @golfraven/site

Placeholder. The public site is Astro 5, static, deployed to Cloudflare Pages
(build plan §3.1 row C). It is ported from `southern-wine-country` @ `572ff7e`
in **P2** — see the full file mapping in the build plan §5.1.

Astro is deliberately **not** installed yet: pulling it in during the P0
skeleton would slow `pnpm install` for a phase that only needs the workspace
to exist and build. `pnpm build` currently just writes a trivial static
`dist/index.html` so the workspace has a working build target.
