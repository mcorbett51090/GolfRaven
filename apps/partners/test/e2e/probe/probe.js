// @ts-nocheck
// A TEST-ONLY page served by the Playwright suite's static server under the SAME generated CSP header as the bundle (never part of any build). It is a real
// same-origin external script (allowed by script-src 'self'), and from inside the page it attempts everything the policy forbids, recording what happened.
// This is what turns "zero CSP violations" in the other tests from a statement about a permissive page into a statement about an enforcing one.
const violations = [];
document.addEventListener("securitypolicyviolation", (ev) => violations.push(ev.violatedDirective));
const result = {};
async function attempt(name, fn) {
  try {
    await fn();
    result[name] = "ALLOWED";
  } catch (e) {
    result[name] = e && e.name ? e.name : "error";
  }
}
await attempt("eval", () => eval("1+1"));
await attempt("newFunction", () => new Function("return 1")());
await attempt("setTimeoutString", () => setTimeout("window.__ran = 1", 0));
await attempt("innerHTML", () => {
  document.body.innerHTML = "<b>x</b>";
});
await attempt("scriptText", () => {
  const s = document.createElement("script");
  s.textContent = "window.__ran = 1";
  document.head.append(s);
});
await attempt("dataScript", () => {
  const s = document.createElement("script");
  s.src = "data:text/javascript,window.__ran2=1";
  document.head.append(s);
});
await attempt("foreignFetch", () => fetch("http://localhost:1/x", { mode: "no-cors" }));
await attempt("createPolicy", () => trustedTypes.createPolicy("x", {}));
await attempt("inlineStyleAttr", () => {
  const p = document.createElement("p");
  p.setAttribute("style", "color:red");
  document.body.append(p);
  return getComputedStyle(p).color === "rgb(255, 0, 0)" ? Promise.resolve() : Promise.reject(new Error("blocked"));
});
await new Promise((r) => setTimeout(r, 200));
result.ran = String(window.__ran ?? window.__ran2 ?? "no");
result.violations = violations;
document.getElementById("out").textContent = JSON.stringify(result);
