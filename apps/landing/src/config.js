// GolfRaven landing page config.
//
// Set SIGNUP_ENDPOINT to the URL that accepts POST { email, trail } as
// JSON and triggers the double-opt-in confirmation email (see README.md
// "How signups work" for the backend requirement: custom SMTP with
// SPF/DKIM/DMARC, owned by the operator). Left blank until that endpoint
// exists — main.js checks this and shows "Signups open soon" instead of a
// form that can't submit anywhere.
window.SIGNUP_ENDPOINT = "";
