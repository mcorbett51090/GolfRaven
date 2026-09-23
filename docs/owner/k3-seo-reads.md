# K3 — SEO reads runbook (SWC Search Console + Keyword Planner)

Covers plan §10 P0 check **K3**. Thresholds quoted verbatim in `docs/p0/K3.md` — this file is the how-to.
M = 1,000 monthly organic clicks (90-day median) on SWC, **and** golf-keyword volume ≥ 5,000/month combined,
both fixed before the data is read (O7 DECIDED 2026-09-23: kept as written).

## Part A — southern-wine-country Search Console 90-day export (≈15 min, Matt)

1. Sign in to [Google Search Console](https://search.google.com/search-console) with the account that owns
   the `southern-wine-country` property.
2. Select the SWC property → **Performance** → **Search results**.
3. Set a **custom date range** covering the three most recent complete calendar months (not "compare"; see step 5).
4. In the results table, switch the metric view to show **Clicks** by date (the chart above the table, or
   export the full date-by-date breakdown).
5. **Export**: use the "Export" button (top right of the Performance report) → **Google Sheets** or **CSV**,
   to get the daily clicks series. **Set the date range to a custom range covering the three most recent
   complete calendar months** (a plain "Last 3 months" window read early in a month contains only two complete
   months).
6. Group the daily clicks series by calendar month.
   **Pinned method (decision 0001 addendum, fixed 2026-09-23 before any data is read):** take the **three most
   recent complete calendar months** before the read date, sum organic clicks for each month, and use the
   **median of those three monthly totals**. Partial months are excluded. Do not substitute a rolling-window
   method; the choice was fixed in advance so it cannot be picked after seeing the numbers.
7. Record the computed **median monthly organic clicks** figure.
8. Compare to **M = 1,000**.

## Part B — Google Ads account with no spend → Keyword Planner (≈30 min, Matt)

1. Create (or sign in to) a [Google Ads](https://ads.google.com) account under Matt's own Google identity.
   **Do not enable billing or launch any campaign** — the check is explicitly run with **no active spend**
   (O23).
2. Navigate to **Tools & Settings → Planning → Keyword Planner → Discover new keywords**.
3. Enter the keyword list:
   - `golf trail`
   - Each pilot-candidate trail name from the research files:
     - Tennessee Golf Trail
     - Vancouver Island Golf Trail
     - Robert Trent Jones Golf Trail
     - Oklahoma Golf Trail (reserve, O4)
     - Optionally any other trail names from `docs/golf-trails/research/us-trails.md` and
       `docs/golf-trails/research/canada-trails.md` worth checking for later-slate context
4. Set location targeting to **US + CA** and language to English (and French for Québec-relevant terms, if
   material).
5. Read the **Avg. monthly searches** column for each term. Without ad spend, Google Ads Keyword Planner
   typically shows a **range** (e.g. "1K–10K") rather than an exact number
   `[unverified — training knowledge; A79]`.
6. **Use the range's lower bound** for every term (per the plan's explicit instruction), not the midpoint or
   upper bound.
7. **Sum the lower bounds across all terms** to get the combined golf-keyword volume figure.
8. Compare to **≥ 5,000/month combined**.

## Recording the result

Fill in `docs/p0/K3.md`:

- MEASURED VALUE: the SWC 90-day median monthly clicks figure, and the combined keyword-volume lower-bound
  sum, with the date the data was read and the three calendar months used.
- VERDICT: `pass` if both thresholds are met; per the kill consequence, `kill`/`adjust` reasoning if both
  miss (directory scoped as partner-facing asset) or if they disagree (growth engine on probation, re-read 6
  months after M1).
- Log entry with the date and the account/property used.
