# P0 application tracker

Required by build plan §10 P0 acceptance test (2): "Every application has a dated receipt." Sourced
against `docs/golf-trails/02-build-plan.md` §10 P0 ("Applications, each with a dated receipt: GolfNow T1 +
business form, Lightspeed, GHIN GPA, Arccos, Garmin waitlist + Golf API BD email, Supreme Golf. The
applicant is the P0 legal entity") and O20 ("Matt's existing operating entity is applicant and merchant of
record"). Application URLs found via WebSearch this session; WebFetch is blocked, so nothing was
confirmed by opening the page directly — treat every URL as `[snippet-only]` until Matt opens it.

## Tracker

| Programme | What we ask for | Where to apply | Status | Submitted date | Response |
|---|---|---|---|---|---|
| GolfNow T1 partner/affiliate + business form | Deep-link/booking distribution partnership; eventually API-level tee-time search (Tier 1 per `research/golfnow-integration.md`) | https://www.golfnow.com/business-partnership/form (partnership interest form); API access requested at https://affiliate.gnsvc.com/getting-started after signing in `[snippet-only]` | Not started | | |
| Lightspeed (Chronogolf) Partner API | Read tee-sheet/pricing data for participating courses; no self-service portal | No public application form — credentials requested by emailing **golf.api@lightspeedhq.com**; docs at https://partner-api.docs.chronogolf.com/ `[snippet-only]` | Not started | | |
| USGA GHIN Golfer Product Access (GPA) | Vendor access to GHIN handicap-posting data (course + date + score) via a negotiated GPA + API agreement | Programme overview: https://www.usga.org/content/usga/home-page/handicapping/world-handicap-system/GPA-Program-Overview.html — **exact application form/contact not found this session**; `[unknown — find on day 1, likely requires contacting USGA directly]` | Not started | | |
| Arccos | Partner access to the On-Course Data API (rounds, stats, course catalog) | No public application form found; partners page: https://www.arccosgolf.com/pages/partners; general support-request form: https://support.arccosgolf.com/hc/en-us/requests/new `[snippet-only]` | Not started | | |
| Garmin Connect Developer waitlist + Golf API BD email | New Connect Developer Program access (Health/Activity/Training/Courses APIs) is reported **paused since spring 2026, still paused as of 2026-09-23**, with no waitlist and no reopening date (`research/golf-app-sync.md`); this is a monitoring + BD outreach ask, not a normal application | Portal to monitor: developer.garmin.com (per Garmin's own forum guidance, check directly rather than wait for a notification — no waitlist exists `[snippet-only]`); direct BD email for the Golf Premium API **not found this session** — `[unknown — find on day 1]` | Not started (blocked pending Garmin reopening; see note below) | | |
| Supreme Golf | Demand-side inventory/distribution partnership (pulling their aggregated tee-time feed as a partner site, not the course-side sign-up) | Course-side sign-up only was found (`courses.supremegolf.com/course-sign-up/`); **no demand-side/partner application path was confirmed** (`research/golfnow-integration.md` open question 8 — "the sign-up page found is course-side (supply) only"); `[unknown — find on day 1, likely requires direct outreach]` | Not started | | |

**Applicant for every row:** Matt's existing operating entity — **[Entity name — TBD]**, US + CA merchant
of record (O20). A D-U-N-S number is applied for in P0 if the entity does not already hold one (§10 P0
external prerequisites).

**Garmin — plain statement for the file (per task instruction):** New Garmin Connect Developer Program
applications, which cover the Golf Premium API's sibling programs, were reported paused industry-wide as
of mid-September 2026 with no reopening timeline (`research/golf-app-sync.md` — "Garmin has paused all new
Connect Developer Program applications … reported mid-September 2026, no reopening date given"). There is
no confirmed waitlist. This row is therefore a **watch-and-BD-outreach** item, not a normal application:
check developer.garmin.com periodically, and send the BD note below to whatever Garmin Golf partnerships
contact can be found, rather than expecting a standard approval process.

---

## Ready-to-paste application / pitch text (per programme)

### GolfNow T1 (business partnership form)

```
Organization: [Entity name — TBD], operating GolfRaven

What GolfRaven is: A mobile app and companion website that lets golfers track which courses they've
played on a branded golf trail (e.g. a state or regional multi-course trail), see completion progress,
and earn a collectible finisher's marker for completing a trail, collected in person at a member pro
shop.

Integration we want: Deep-link/booking distribution — sending golfers from trail/course pages in our app
to GolfNow to book a tee time at that course. Longer term, we're interested in the Affiliate & Partner API
for live tee-time search on our own trail pages, if GolfNow's team sees a fit.

Data use: We would not request or store any GolfNow booking data beyond what a standard deep link
requires (a URL click). If API access is granted, any booking-confirmation data received would be used
only to support the golfer's own trail-completion record inside our app — never resold, and never shown
to any user other than the golfer who made the booking.

Applicant: [Entity name — TBD], the operating entity behind GolfRaven (US + Canada).
Contact: Matt [Last Name], [phone], [email].
```

### Lightspeed (Chronogolf) Partner API

```
To: golf.api@lightspeedhq.com
Subject: Partner API credentials request — GolfRaven

Hello,

I'm building GolfRaven, an app that tracks golfer progress on branded multi-course golf trails and
verifies course visits. Several pilot trail courses may run on Lightspeed Golf (Chronogolf), and I'd like
to request staging credentials for the Partner API v2 to evaluate a read-only integration (tee sheet /
course identity, not booking automation, at this stage).

What GolfRaven is: a completion tracker and collectible-marker programme for golf trails, built with the
participating course's/operator's agreement, at no cost or POS change to the course.

Integration we want: read access to confirm course identity and, if useful, booking/round records tied
to a specific course and date, to help verify trail-course completions.

Data use: any data received would be used only to support the golfer's own trail-completion record;
never resold or shown to other users.

Applicant: [Entity name — TBD] (US + Canada operating entity).

Thanks,
Matt [Last Name]
[phone] / [email]
```

### USGA GHIN Golfer Product Access (GPA)

```
Subject: GPA program inquiry — GolfRaven

Hello,

I'm building GolfRaven, an app that tracks golfer progress on branded golf trails, verifies course
visits, and rewards trail completion. I'm interested in exploring Golfer Product Access (GPA) to use GHIN
handicap-posting records (course + date, and score where posted) as one verification signal for a
golfer's played rounds, alongside our own device-based and in-app verification.

What GolfRaven is: a trail-completion tracker and collectible-marker programme, built with each trail
operator's agreement.

Data use: GHIN data would only be used to help confirm a golfer's own recorded rounds against trail
courses; never resold, never shown to any user other than the golfer, and deletable on request per our
own privacy policy.

Applicant: [Entity name — TBD] (US + Canada operating entity).

Could you point me to the GPA application process and any requirements (cost, volume, agreement terms)?

Thanks,
Matt [Last Name]
[phone] / [email]
```

### Arccos

```
Subject: On-Course Data API partner inquiry — GolfRaven

Hello,

I'm building GolfRaven, a golf-trail completion tracker. I'd like to explore partner access to the
On-Course Data API (rounds, course catalog) as an additional signal for verifying a golfer's played
rounds on trail courses, for golfers who already use Arccos hardware/software.

What GolfRaven is: a completion tracker and collectible-marker programme for branded golf trails, built
with each trail operator's agreement, at no cost to the course.

Data use: Arccos round data received would be used only to support the golfer's own trail-completion
record; never resold or shown to other users; deletable on the golfer's request.

Applicant: [Entity name — TBD] (US + Canada operating entity).

Thanks,
Matt [Last Name]
[phone] / [email]
```

### Garmin Connect Developer Program (waitlist / BD)

```
Subject: Golf trail app — interested in Garmin Golf/Connect Developer access once reopened

Hello,

I understand new Connect Developer Program applications (and the Golf Premium API) may currently be
paused. I wanted to register interest ahead of any reopening: I'm building GolfRaven, an app that tracks
golfer progress on branded golf trails, including verifying course visits via device data where a golfer
opts in.

What GolfRaven is: a completion tracker and collectible-marker programme for golf trails.

Integration we want: read access to a golfer's own golf activity/round data (course, date, and ideally
GPS route) to help verify trail-course completions, with explicit golfer opt-in.

Data use: used only to support that golfer's own trail-completion record; never resold; never shown to
other users; deletable on request.

Is there a waitlist, or a business-development contact I should reach out to directly once the program
reopens?

Applicant: [Entity name — TBD] (US + Canada operating entity).

Thanks,
Matt [Last Name]
[phone] / [email]
```

### Supreme Golf

```
Subject: Partnership inquiry — golf-trail completion app

Hello,

I'm building GolfRaven, an app that tracks golfer progress on branded multi-course golf trails and
verifies course visits, with links out to book tee times. I'd like to explore a demand-side partnership —
pulling Supreme Golf's aggregated tee-time feed to show live availability and booking links on our trail
and course pages, similar to your existing partner sites (Barstool Golf Time, GolfDigest, etc.).

What GolfRaven is: a completion tracker and collectible-marker programme for golf trails, built with each
trail operator's agreement.

Data use: booking-related data would be used only to support the golfer's own trail-completion record
and to send them to book; never resold.

Applicant: [Entity name — TBD] (US + Canada operating entity).

Could you point me to the right contact or process for a partner site (not a course) integration?

Thanks,
Matt [Last Name]
[phone] / [email]
```
