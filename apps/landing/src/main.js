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

  var form = document.getElementById("signup-form");
  var closedNotice = document.getElementById("signups-closed");

  if (!endpoint) {
    // No endpoint configured: signups are not open yet. Keep the form
    // hidden and show the static notice only.
    if (closedNotice) {
      closedNotice.hidden = false;
    }
    return;
  }

  if (!form) {
    return;
  }

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

    if (submitButton) {
      submitButton.disabled = true;
    }
    setStatus("Sending…");

    // ageConfirmed and consentVersion are sent so the backend can store the
    // 16+ attestation and which wording of the privacy notice the signup
    // agreed to (see the privacy section above and README.md "How signups
    // work") -- there is otherwise no durable consent/age record at all.
    fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: email,
        trail: trail,
        ageConfirmed: ageConfirmed,
        consentVersion: CONSENT_VERSION,
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
