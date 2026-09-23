// GolfRaven landing page: signup form wiring.
//
// No third-party scripts, no trackers. If SIGNUP_ENDPOINT (config.js) is
// unset, the form never renders and the page shows "Signups open soon"
// instead — it must never attempt to submit with nowhere to send to.
(function () {
  "use strict";

  // Bump this whenever the privacy notice / consent copy in index.html
  // changes materially, so stored signups can be matched back to the
  // wording they actually agreed to (see the privacy section's "What we
  // store" bullet).
  var CONSENT_VERSION = "2026-09-23";

  var yearEl = document.getElementById("year");
  if (yearEl) {
    yearEl.textContent = String(new Date().getFullYear());
  }

  var endpoint =
    typeof window.SIGNUP_ENDPOINT === "string" ? window.SIGNUP_ENDPOINT.trim() : "";
  var turnstileSiteKey =
    typeof window.TURNSTILE_SITE_KEY === "string" ? window.TURNSTILE_SITE_KEY.trim() : "";

  var form = document.getElementById("signup-form");
  var closedNotice = document.getElementById("signups-closed");

  // Both a real endpoint AND a Turnstile site key are required for a
  // signup to ever succeed (apps/signup-worker requires turnstileToken on
  // every POST /api/signup) — so a form the visitor can submit but that
  // can never pass server-side verification would be worse than showing
  // the honest "not open yet" notice. Same rule as the endpoint-only
  // check this replaces: never show a form that can't work.
  if (!endpoint || !turnstileSiteKey) {
    if (closedNotice) {
      closedNotice.hidden = false;
    }
    return;
  }

  if (!form) {
    return;
  }

  // The ONE allowed third-party origin (see README.md and _headers): the
  // Turnstile widget script and its challenge iframe. Injected here,
  // dynamically, rather than a static <script src> in index.html, so a
  // signups-closed page (the branch above) never references it at all.
  var turnstileContainer = document.getElementById("turnstile-container");
  if (turnstileContainer) {
    turnstileContainer.classList.add("cf-turnstile");
    turnstileContainer.setAttribute("data-sitekey", turnstileSiteKey);
  }
  var turnstileScript = document.createElement("script");
  turnstileScript.src = "https://challenges.cloudflare.com/turnstile/v0/api.js";
  turnstileScript.async = true;
  turnstileScript.defer = true;
  document.head.appendChild(turnstileScript);

  form.hidden = false;
  if (closedNotice) {
    closedNotice.hidden = true;
  }

  var statusEl = document.getElementById("form-status");
  var submitButton = form.querySelector('button[type="submit"]');

  function setStatus(message) {
    if (statusEl) {
      statusEl.textContent = message;
    }
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();

    if (typeof form.reportValidity === "function" && !form.reportValidity()) {
      return;
    }

    var emailInput = document.getElementById("email");
    var trailInput = form.querySelector('input[name="trail"]:checked');
    var ageConfirmInput = document.getElementById("age-confirm");
    var email = emailInput ? emailInput.value.trim() : "";
    var trail = trailInput ? trailInput.value : "either";
    var ageConfirmed = !!(ageConfirmInput && ageConfirmInput.checked);

    if (!email) {
      setStatus("Please enter your email address.");
      return;
    }

    // Turnstile's implicit rendering creates a hidden input named
    // "cf-turnstile-response" inside the widget container once a visitor
    // completes the challenge. [unverified — Cloudflare Turnstile's
    // documented client behavior, not exercised against a live challenge
    // in this environment; see apps/signup-worker/README.md.]
    var turnstileInput = form.querySelector('[name="cf-turnstile-response"]');
    var turnstileToken = turnstileInput ? turnstileInput.value : "";
    if (!turnstileToken) {
      setStatus("Please complete the verification challenge, then try again.");
      return;
    }

    if (submitButton) {
      submitButton.disabled = true;
    }
    setStatus("Sending…");

    // ageConfirmed and consentVersion are sent so the backend can store the
    // 16+ attestation and which wording of the privacy notice the signup
    // agreed to (see the privacy section above and README.md "How signups
    // work") -- there is otherwise no durable consent/age record at all.
    // turnstileToken lets the backend verify the challenge server-side
    // (apps/signup-worker/src/turnstile.ts) before ever sending an email.
    fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: email,
        trail: trail,
        ageConfirmed: ageConfirmed,
        consentVersion: CONSENT_VERSION,
        turnstileToken: turnstileToken,
        source: trail,
      }),
    })
      .then(function (response) {
        if (!response.ok) {
          throw new Error("Request failed with status " + response.status);
        }
        setStatus(
          "Check your inbox — we've sent a confirmation email. Click the link there to finish signing up.",
        );
        form.reset();
      })
      .catch(function () {
        setStatus(
          "Something went wrong sending that. Please try again in a moment.",
        );
      })
      .finally(function () {
        if (submitButton) {
          submitButton.disabled = false;
        }
      });
  });
})();
