/**
 * The signed-in panels (docs/security/partner-auth-design.md 6.3, 6.4): the PIN prompt, set / change PIN, the email proof and the second factor.
 * Plain DOM, text only. Every form reads its fields on submit and empties them at once (forms.ts), and the controller never keeps the digits.
 */

import type { AppController } from "../app/controller";
import type { EmailProofPanel, PinPromptPanel, PinSetupPanel, TotpPanel } from "../app/state";
import { translate, type Locale, type MessageKey } from "../i18n";
import { h } from "./dom";
import { field, form } from "./forms";
import { noticeElement } from "./notice";

type T = (k: MessageKey, p?: Record<string, string | number>) => string;
type Panel = PinPromptPanel | PinSetupPanel | EmailProofPanel | TotpPanel;

const wrap = (titleKey: MessageKey, t: T, screen: string, busy: boolean, ...children: Array<Node | null>): HTMLElement =>
  h("main", { "aria-busy": busy ? "true" : "false", "data-screen": screen }, h("h1", { tabindex: "-1", "data-testid": "heading" }, t(titleKey)), ...children);

const cancel = (t: T, busy: boolean, onclick: () => void) => h("button", { type: "button", disabled: busy, "data-testid": "panel-cancel", onclick }, t("common.cancel"));
const busyLine = (t: T, key: MessageKey) => h("p", { role: "status", "data-testid": "busy" }, t(key));

/** What the last attempt of a prompt got, as a notice. */
function promptProblem(p: PinPromptPanel, locale: Locale): HTMLElement | null {
  const problem = p.problem;
  if (problem === null) return p.retryAfterSeconds > 0 ? noticeElement({ kind: "error", message: { key: "pin.backoff.wait", params: { seconds: p.retryAfterSeconds } } }, locale) : null;
  if (problem.kind === "wrong") return noticeElement({ kind: "error", message: { key: "pin.wrong" } }, locale);
  if (problem.kind === "rejected") return noticeElement({ kind: "error", message: { key: `pin.rejected.${problem.reason}` } }, locale);
  return noticeElement({ kind: "error", message: problem.retryAfterSeconds === null ? { key: "pin.backoff" } : { key: "pin.backoff.wait", params: { seconds: problem.retryAfterSeconds } } }, locale);
}

function pinPrompt(p: PinPromptPanel, c: AppController, t: T, locale: Locale): HTMLElement {
  const pin = field({ id: "pin", label: t("pin.field.label"), kind: "pin", autofocus: true, disabled: p.busy });
  return wrap(
    "pin.prompt.title",
    t,
    "pin-prompt",
    p.busy,
    promptProblem(p, locale),
    h("p", {}, t(p.actionClass === "A2" ? "pin.prompt.lead.A2" : "pin.prompt.lead")),
    form(
      () => c.submitPin(pin.take()),
      "pin-form",
      pin.row,
      h("div", { class: "actions" }, h("button", { type: "submit", class: "primary", disabled: p.busy, "data-testid": "pin-submit" }, t("pin.prompt.submit")), cancel(t, p.busy, () => c.cancelPin())),
    ),
    p.busy ? busyLine(t, "pin.prompt.busy") : null,
  );
}

function pinSetup(p: PinSetupPanel, c: AppController, t: T, locale: Locale): HTMLElement {
  const current = p.mode === "change" ? field({ id: "pin-current", label: t("pin.setup.current"), kind: "pin", autofocus: true, disabled: p.busy }) : null;
  const next = field({ id: "pin-new", label: t("pin.setup.new"), kind: "pin", autofocus: current === null, disabled: p.busy });
  const confirm = field({ id: "pin-confirm", label: t("pin.setup.confirm"), kind: "pin", disabled: p.busy });
  return wrap(
    p.mode === "set" ? "pin.setup.title.set" : "pin.setup.title.change",
    t,
    "pin-setup",
    p.busy,
    noticeElement(p.notice, locale),
    p.mode === "set" ? h("p", {}, t(p.forced ? "pin.setup.lead.forced" : "pin.setup.lead")) : null,
    form(
      () => void c.submitPinSetup({ current: current?.take() ?? "", pin: next.take(), confirm: confirm.take() }),
      "pin-setup-form",
      current?.row ?? null,
      next.row,
      confirm.row,
      h(
        "div",
        { class: "actions" },
        h("button", { type: "submit", class: "primary", disabled: p.busy, "data-testid": "pin-save" }, t("pin.setup.submit")),
        p.forced && !p.canSkip ? null : cancel(t, p.busy, () => c.closePanel()),
        p.forced && p.canSkip ? h("button", { type: "button", "data-testid": "pin-skip", onclick: () => c.closePanel() }, t("pin.setup.skip")) : null,
      ),
    ),
    p.busy ? busyLine(t, "pin.setup.busy") : null,
  );
}

function emailProof(p: EmailProofPanel, c: AppController, t: T, locale: Locale): HTMLElement {
  if (p.step === "send") {
    return wrap(
      "proof.title",
      t,
      "email-proof",
      p.busy,
      noticeElement(p.notice, locale),
      h("p", {}, t("proof.send.lead")),
      h(
        "div",
        { class: "actions" },
        h("button", { type: "button", class: "primary", disabled: p.busy, "data-autofocus": true, "data-testid": "proof-send", onclick: () => void c.startEmailProof() }, t("proof.send.button")),
        cancel(t, p.busy, () => c.closePanel()),
      ),
    );
  }
  const code = field({ id: "proof-code", label: t("proof.code.label"), kind: "code", autofocus: true, disabled: p.busy });
  return wrap(
    "proof.title",
    t,
    "email-proof",
    p.busy,
    noticeElement(p.notice, locale),
    h("p", {}, t("proof.code.lead")),
    form(
      () => void c.submitEmailProof(code.take()),
      "proof-form",
      code.row,
      h("div", { class: "actions" }, h("button", { type: "submit", class: "primary", disabled: p.busy, "data-testid": "proof-submit" }, t("proof.code.button")), cancel(t, p.busy, () => c.closePanel())),
    ),
  );
}

function totp(p: TotpPanel, c: AppController, t: T, locale: Locale): HTMLElement {
  if (p.step === "enrol-start") {
    return wrap(
      "totp.enrol.title",
      t,
      "totp",
      p.busy,
      noticeElement(p.notice, locale),
      h("p", {}, t("totp.enrol.start.lead")),
      h(
        "div",
        { class: "actions" },
        h("button", { type: "button", class: "primary", disabled: p.busy, "data-autofocus": true, "data-testid": "totp-show-seed", onclick: () => void c.startTotpEnrol() }, t("totp.enrol.start.button")),
        cancel(t, p.busy, () => c.closePanel()),
      ),
    );
  }
  const code = field({ id: "totp-code", label: t("totp.code.label"), kind: "totp", autofocus: true, disabled: p.busy });
  const confirming = p.step === "enrol-confirm";
  return wrap(
    confirming ? "totp.enrol.title" : "totp.verify.title",
    t,
    "totp",
    p.busy,
    noticeElement(p.notice, locale),
    h("p", {}, t(confirming ? "totp.enrol.confirm.lead" : "totp.verify.lead")),
    p.enrolment === null
      ? null
      : h(
          "dl",
          { class: "fields", "data-testid": "totp-seed" },
          h("dt", {}, t("totp.seed.label")),
          h("dd", { class: "mono" }, p.enrolment.seed),
          h("dt", {}, t("totp.uri.label")),
          h("dd", { class: "mono" }, p.enrolment.otpauthUrl),
        ),
    form(
      () => void c.submitTotp(code.take()),
      "totp-form",
      code.row,
      h("div", { class: "actions" }, h("button", { type: "submit", class: "primary", disabled: p.busy, "data-testid": "totp-submit" }, t(confirming ? "totp.confirm.button" : "totp.verify.button")), cancel(t, p.busy, () => c.closePanel())),
    ),
  );
}

export function panelView(panel: Panel, controller: AppController, locale: Locale): HTMLElement {
  const t: T = (k, p) => translate(locale, k, p);
  switch (panel.kind) {
    case "pin-prompt":
      return pinPrompt(panel, controller, t, locale);
    case "pin-setup":
      return pinSetup(panel, controller, t, locale);
    case "email-proof":
      return emailProof(panel, controller, t, locale);
    default:
      return totp(panel, controller, t, locale);
  }
}
