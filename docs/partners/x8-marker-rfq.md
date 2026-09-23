# X8 — Ball-marker vendor RFQ pack

Draft for Matt to send from his own accounts/email. Nothing here has been sent. Sourced against
`docs/golf-trails/02-build-plan.md` §9.6 ("Special-marker stock distribution and logistics"), §9.3 (code
cards, `programme_marker` only), §10 P0 ("X8 marker vendor quotes … gates only `programme_marker`
procurement in P5 … the quotes also record the special-marker MOQ, unit cost and lead time, which each
trail uses for its own order"). Vendor candidates were found via WebSearch this session; **WebFetch is
blocked by the network proxy**, so no vendor page was directly fetched — every MOQ/price figure below is
a `[snippet-only]` marketing-page claim, not a confirmed quote. That is exactly what this RFQ is for.

## What GolfRaven needs quoted (two distinct products, per §9.1/§9.6)

1. **Course markers** — per-course logo, only relevant if a trail opts into `programme_marker` mode
   (§9.1 table); the default mode (`any_purchase`) needs none, since any marker already sold at a pro
   shop counts.
2. **Trail special marker** — a numbered, collectible finisher's marker, one design per trail, ordered
   and paid for by the trail (or its sponsor) directly with the vendor — GolfRaven never holds or ships
   stock (O9/O10, §9.6). This is the marker every RFQ must cover regardless of trail mode.

## RFQ email template

```
Subject: Quote request — golf ball markers (course + special/commemorative), US + Canada

Hello,

I'm working with a set of golf trails (a multi-course collection marketed and tracked together) on a
marker programme, and I'd like a quote covering two products:

1. Course markers — a small, flat ball marker (standard ~25mm size, similar to a typical logo ball
   marker) with a single-color or full-color course logo. Per-course, low volume.
2. A trail special/commemorative marker — a distinct, numbered-edition marker design (open to a coin-
   style marker with a magnetic ball-marker insert, or a simple stamped/enameled marker — happy to see
   options), one design per trail, higher volume than an individual course marker.

For each product, could you quote:
- Minimum order quantity (MOQ)
- Unit cost at 100 / 250 / 500 / 1,000 units
- Lead time from art approval to delivery, at each quantity tier
- Available finishes (soft enamel, hard enamel, offset print, epoxy dome, stamped metal, etc.) and any
  price difference between them
- Numbering/sequential-serial capability for the special marker (e.g. "0001 of 500"), and any added cost
- Shipping cost and lead time to multiple pro-shop addresses in the continental US and in Canada
  (British Columbia specifically) — we'd need delivery split across roughly [N] separate shop addresses
  per order, not one bulk delivery
- Sample cost and turnaround, before a production order is placed
- Any tooling/setup fee, and whether it's reusable for reorders of the same design

Rough initial order size to plan around: [100–500] units per trail per season, split across [8–26] pro
shops. We'd want a recurring relationship (reorders each season), not a one-time buy.

Happy to send artwork specs once we have a sense of your pricing tiers.

Thanks,
Matt [Last Name]
[Entity name — TBD]
[Phone] / [Email]
```

## Candidate vendors (≥ 5 found via WebSearch; none fetched directly — all `[snippet-only]`)

| # | Vendor | URL | Why included |
|---|---|---|---|
| 1 | Vivipins | https://vivipins.com/custom-golf-ball-markers/ | Advertises no minimum order and wholesale pricing with free design/revisions — a candidate for a small first trial batch before committing to a full trail run. `[snippet-only]` |
| 2 | Aceballmarkers.com | https://aceballmarkers.com/ | Advertises no minimum order with per-unit pricing as low as $0.68 at volume — useful as a low-end pricing anchor for course markers specifically. `[snippet-only]` |
| 3 | GS-JJ | https://www.gs-jj.com/ball-markers/custom-golf-coins | Positions itself around challenge-coin-style commemorative markers with free shipping — a fit for the trail special marker (numbered edition) rather than the everyday course marker. `[snippet-only]` |
| 4 | Jin Sheu | https://www.jinsheu.com/en/category/Golf-Coin-with-Ball-Marker.html | Taiwan-based manufacturer advertising flexible MOQ for corporate/large-volume orders — worth quoting for a larger trail (e.g. RTJ's 11 sites) where volume could bring unit cost down meaningfully. `[snippet-only]` |
| 5 | Matchstick Golf | https://matchstickgolf.com/pages/custom-golf-ball-markers | A US-facing wholesale custom-marker seller — worth checking for domestic US production/shipping, which could beat overseas lead times and avoid cross-border customs for US pro shops. `[snippet-only]` |
| 6 | Signature Coins | https://signaturecoins.com/custom-golf-ball-marker/ | Advertises free shipping and a quality guarantee on custom metal ball markers — another candidate for the special/commemorative marker specifically. `[snippet-only]` |

**Note on figures already seen in search results** (do not treat as confirmed): per-unit prices as low
as $0.39–$0.68 at high volume, and MOQs ranging from "no minimum" to 50–100 units, appeared across
multiple vendor marketing pages. `research/mobile-stack-and-data.md` independently estimated "marker
MOQs 50–250, low single-digit $" and flagged it `[unverified]` — the RFQ responses are what settle this
for real, per the build plan's own framing of X8.

## Quote comparison table (empty — fill in as quotes come back)

| Vendor | Product | MOQ | Unit cost @100 | Unit cost @250 | Unit cost @500 | Unit cost @1000 | Lead time | Finishes offered | US shipping | Canada shipping | Sample cost | Numbering available? | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| | Course marker | | | | | | | | | | | | |
| | Special/trail marker | | | | | | | | | | | | |
