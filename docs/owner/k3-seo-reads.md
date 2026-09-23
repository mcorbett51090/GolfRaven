# K3 — SEO reads runbook (SWC Search Console + Keyword Planner)

Covers plan §10 P0 check **K3**. Thresholds quoted verbatim in `docs/p0/K3.md` — this file is the how-to.
M = 1,000 monthly organic clicks (90-day median) on SWC, **and** golf-keyword volume ≥ 5,000/month combined,
both fixed before the data is read (O7 DECIDED 2026-09-23: kept as written).

## Part A — southern-wine-country Search Console export (≈15 min, Matt)

1. Sign in to [Google Search Console](https://search.google.com/search-console) with the account that owns
   the `southern-wine-country` property. Record the property's exact property id in `docs/p0/K3.md` ("SWC
   Search Console property") before opening the report (decision 0001, Addendum D, R4).
2. Select the SWC property → **Performance** → **Search results**.
3. Set **search type = Web**, **all countries**, **all devices** (decision 0001, Addendum D, R4 — set this
   before reading any number, not in Part B).
4. Set a **custom date range** of **July 1, 2026 – September 30, 2026** — the three months are fixed
   (decision 0001, Addendum D, R4), not "the three most recent complete calendar months before the read
   date."
5. In the results table, switch the metric view to show **Clicks** by date (the chart above the table, or
   export the full date-by-date breakdown).
6. **Export**: use the "Export" button (top right of the Performance report) → **Google Sheets** or **CSV**,
   to get the daily clicks series for the fixed Jul–Sep 2026 range.
7. Group the daily clicks series by calendar month (July, August, September 2026).
   **Pinned method (decision 0001, Addendum A):** sum organic clicks for each of the three fixed months, and
   use the **median of those three monthly totals**.
8. Record the computed **median monthly organic clicks** figure. **The first complete read performed is the
   recorded result — there are no re-reads** (decision 0001, Addendum D, R4).
9. Compare to **M = 1,000**.

## Part B — Google Ads account with no spend → Keyword Planner (≈30 min, Matt)

1. Create (or sign in to) a [Google Ads](https://ads.google.com) account under Matt's own Google identity.
   **Do not enable billing or launch any campaign** — the check is explicitly run with **no active spend**
   (O23).
2. Navigate to **Tools & Settings → Planning → Keyword Planner → Get search volume and forecasts** (not
   "Discover new keywords" — that tool returns Google's own suggested/related terms, not a volume for a fixed
   list, and is not used for this check).
3. Enter **exactly** this closed keyword list — no additions, no substitutions (fixed in decision 0001,
   Addendum B, before any data is read):
   - `golf trail`
   - `golf trails`
   - `robert trent jones golf trail`
   - `tennessee golf trail`
   - `vancouver island golf trail`
   - `oklahoma golf trail`
4. Set location targeting to **United States and Canada**, **language: English only** (no French terms —
   Addendum B), and **date range: September 2025 – August 2026** (decision 0001, Addendum D, R5 — not the
   Planner's default trailing-12-month average).
5. Read the **Avg. monthly searches** column for each term. Without ad spend, Google Ads Keyword Planner
   typically shows a **range** (e.g. "1K–10K") rather than an exact number
   `[unverified — training knowledge; A79]`.
6. **Use the range's lower bound** for every term (per the plan's explicit instruction), not the midpoint or
   upper bound.
7. **Sum the lower bounds across the six terms** to get the combined golf-keyword volume figure. **If two of
   the six terms return the identical range, count that range once** (decision 0001, Addendum D, R5 — this
   replaces Addendum B's "exact-match only" wording, since the Planner may report one combined volume for
   close variants). Do not add any other term after any number has been read.
8. Compare to **≥ 5,000/month combined**.

## Recording the result

Fill in `docs/p0/K3.md`:

- MEASURED VALUE: the SWC 90-day median monthly clicks figure, and the combined keyword-volume lower-bound
  sum, with the date the data was read and the three calendar months used.
- VERDICT: `pass` if both thresholds are met; per the kill consequence, `kill`/`adjust` reasoning if both
  miss (directory scoped as partner-facing asset) or if they disagree (growth engine on probation, re-read 6
  months after M1).
- Log entry with the date and the account/property used.
