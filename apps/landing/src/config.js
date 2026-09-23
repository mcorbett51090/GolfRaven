// GolfRaven landing page config.
//
// Set SIGNUP_ENDPOINT to the URL that accepts
// POST { email, trail, ageConfirmed, consentVersion, turnstileToken, source? }
// as JSON and triggers the double-opt-in confirmation email — see
// apps/signup-worker (the backend that implements this) and this repo's
// README.md "How signups work". Left blank until that endpoint exists —
// main.js checks this and shows "Signups open soon" instead of a form
// that can't submit anywhere. Same-origin deploys (golfraven.<tld>/api/*)
// can set this to the path alone, e.g. "/api/signup".
window.SIGNUP_ENDPOINT = "";

// Cloudflare Turnstile site key (public — safe to ship to the client).
// TODO(owner): set once apps/signup-worker is deployed and a Turnstile
// widget is created for this domain. Required for signups to work: the
// form is rendered but the Turnstile widget (and therefore submission)
// stays disabled without it — see main.js. Must be paired with the
// TURNSTILE_SECRET the worker verifies against (never put the secret
// here — this is the PUBLIC site key only).
window.TURNSTILE_SITE_KEY = "";
