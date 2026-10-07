// @ts-nocheck
// A TEST-ONLY page served by the Playwright suite under the SAME generated headers as the bundle. It fetches a list of URLs on the API origin (given as
// ?api=<origin>&root=<functions root path>) the way the client does (cors, credentials omit, JSON) and records, per URL, whether the CSP let the request
// leave the page: "blocked" (a TypeError AND a connect-src violation event) or the HTTP status the server answered (so CSP allowed it).
const params = new URLSearchParams(location.search);
const api = params.get("api");
const root = params.get("root");
const violations = [];
document.addEventListener("securitypolicyviolation", (ev) => violations.push({ directive: ev.violatedDirective, blockedURI: ev.blockedURI }));
const targets = {
  "partner-session/options (POST, what the client sends)": [`${api}${root}/partner-session/options`, "POST"],
  "partner-session/session (GET)": [`${api}${root}/partner-session/session`, "GET"],
  "partner-session/reauth/options (POST)": [`${api}${root}/partner-session/reauth/options`, "POST"],
  "partner-session (bare name, no trailing slash)": [`${api}${root}/partner-session`, "GET"],
  "other-fn": [`${api}${root}/other-fn/x`, "GET"],
  "partner-sessionx (shares the prefix string)": [`${api}${root}/partner-sessionx/x`, "GET"],
  "rest/v1 (PostgREST)": [`${api}/rest/v1/orgs`, "GET"],
  "rest/v1 root": [`${api}/rest/v1/`, "GET"],
  "origin root": [`${api}/`, "GET"],
  "dot segments out of the function": [`${api}${root}/partner-session/../other-fn/x`, "GET"],
};
const result = {};
for (const [name, [url, method]] of Object.entries(targets)) {
  const before = violations.length;
  try {
    const res = await fetch(url, { method, mode: "cors", credentials: "omit", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer", headers: { "Content-Type": "application/json" }, ...(method === "POST" ? { body: "{}" } : {}) });
    result[name] = `status ${res.status}`;
  } catch (e) {
    await new Promise((r) => setTimeout(r, 30));
    result[name] = violations.length > before && violations.at(-1).directive.startsWith("connect-src") ? "blocked by CSP" : `failed without a CSP violation (${e && e.name})`;
  }
}
document.getElementById("out").textContent = JSON.stringify(result);
