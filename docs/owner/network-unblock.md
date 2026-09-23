# Network unblock — hosts needed for the P0 desk checks

Observed this session (2026-09-23): the container's network egress proxy returns `403` on CONNECT to the
hosts below, and `WebFetch` is also blocked for them. This blocks checks **X2, X4, X5, X6** (and touches the
account-setup steps for X7 / the domain / Cloudflare). Grant these in the environment's **Network access**
settings, then an agent can run the blocked checks directly — see each check's memo in `docs/p0/` for the
exact queries/URLs once unblocked.

## Hosts, grouped by what they unblock

### X2 — pilot-slate roster/rules direct-fetch (`docs/p0/X2.md`)

| Host | Why |
|---|---|
| `rtjgolf.com` | Robert Trent Jones Golf Trail's own site — roster + rules |
| `tngolftrail.net` | Confirmed blocked this session; not the host cited in `research/us-trails.md` (which uses `tnstateparks.com`) — allow both until the canonical TN host is confirmed |
| `tnstateparks.com` | Tennessee State Parks — the TN Golf Trail host per `research/us-trails.md` (confirmed blocked this session, 2026-09-23: proxy CONNECT `403`) |
| `golfvancouverisland.ca` | Vancouver Island Golf Trail's own site — roster + rules + Trail Pass terms |
| `tn.gov` | Tennessee state government domain family, relevant if the trail's rules live under a `.tn.gov` subdomain |

### X4 — GolfNow facility-page coverage (`docs/p0/X4.md`)

| Host | Why |
|---|---|
| `golfnow.com` | Facility pages (`www.golfnow.com/tee-times/facility/<id>-<slug>/search`) for the pilot-slate courses |

### X5 — Overpass OSM coverage (`docs/p0/X5.md`)

| Host | Why |
|---|---|
| `overpass-api.de` | The public Overpass API endpoint used for the `leisure=golf_course` count and `golf=hole` coverage queries |

### X6 — GolfNow ToS + partner-API docs (`docs/p0/X6.md`)

| Host | Why |
|---|---|
| `golfnow.com` | Terms of Use (`golfnow.com/support/about-us/terms`) and the Business Partnership page |
| `affiliate.gnsvc.com` | GolfNow's Affiliate & Partner API docs (confirmed blocked this session, 2026-09-23: proxy CONNECT `403`) |

### Account-setup steps that also hit blocked hosts this session (not a gating check, but worth unblocking together)

| Host | Why | Relevant checklist |
|---|---|---|
| `supabase.com` | Creating/managing the Supabase project (X7's prerequisite) | `docs/owner/accounts-and-domain-checklist.md` §9, `docs/p0/X7.md` |
| `developers.cloudflare.com` | Cloudflare Pages docs, relevant to §5.2 build-budget items X5 also records | `docs/owner/accounts-and-domain-checklist.md` §10 |
| `rdap.verisign.com` | RDAP/WHOIS lookups for domain availability (`golfraven.com`/`.golf`/`.ca`, O1/A82) | `docs/owner/accounts-and-domain-checklist.md` §1 |

## Confirmed this session (evidence, not inference)

`CONNECT` to `rtjgolf.com`, `tngolftrail.net`, `golfvancouverisland.ca`, `tn.gov`, `golfnow.com`,
`overpass-api.de`, `developers.cloudflare.com`, `supabase.com`, `rdap.verisign.com`,
`affiliate.gnsvc.com` and `tnstateparks.com` all returned proxy `403` this session (2026-09-23; the last
two probed and confirmed as part of the P0 gate review; see `docs/p0/X6.md` and `docs/p0/X2.md`); `WebFetch`
was also blocked for the same hosts.

## After unblocking

Once a host is allowed, re-open the corresponding `docs/p0/<ID>.md` memo and change its STATUS line from
`BLOCKED — network policy (...)` to reflect the run; do not change any other memo's STATUS speculatively —
each host group above maps to specific checks, not all of them at once.
