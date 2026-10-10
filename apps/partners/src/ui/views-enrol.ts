/** The invite and enrolment screen (docs/security/partner-auth-design.md 6.1): token, emailed code, passkey. Plain DOM, text only. */

import type { AppController } from "../app/controller";
import type { EnrolState } from "../app/state";
import { translate, type Locale, type MessageKey } from "../i18n";
import { h } from "./dom";
import { field, form } from "./forms";
import { noticeElement } from "./notice";

export function enrolView(state: EnrolState, controller: AppController, locale: Locale): HTMLElement {
  const t = (k: MessageKey, p?: Record<string, string | number>) => translate(locale, k, p);
  const heading = h("h1", { tabindex: "-1", "data-testid": "heading" }, t("enrol.title"));
  const busy = state.busy;
  const back = h("button", { type: "button", disabled: busy, "data-testid": "enrol-back", onclick: () => controller.cancelEnrol() }, t("enrol.back"));
  const status = busy ? h("p", { role: "status", "data-testid": "busy" }, t("enrol.busy")) : null;

  let body: Array<Node | null>;
  if (state.step === "token") {
    const token = state.hasToken ? null : field({ id: "enrol-token", label: t("enrol.token.label"), kind: "token", autofocus: true, disabled: busy });
    const send = () => void controller.requestEnrolCode(token?.take());
    body = [
      h("p", {}, t(state.hasToken ? "enrol.lead.link" : "enrol.lead.token")),
      form(
        send,
        "enrol-token-form",
        token?.row ?? null,
        h("div", { class: "actions" }, h("button", { type: "submit", class: "primary", disabled: busy, "data-autofocus": state.hasToken, "data-testid": "enrol-send-code" }, t("enrol.sendCode"))),
      ),
    ];
  } else if (state.step === "code") {
    const code = field({ id: "enrol-code", label: t("enrol.code.label"), kind: "code", autofocus: true, disabled: busy });
    body = [
      h("p", {}, t("enrol.code.lead")),
      form(
        () => void controller.submitEnrolCode(code.take()),
        "enrol-code-form",
        code.row,
        h(
          "div",
          { class: "actions" },
          h("button", { type: "submit", class: "primary", disabled: busy, "data-testid": "enrol-submit-code" }, t("enrol.code.button")),
          h("button", { type: "button", disabled: busy, "data-testid": "enrol-resend", onclick: () => void controller.requestEnrolCode() }, t("enrol.code.resend")),
        ),
      ),
    ];
  } else {
    body = [
      h("p", {}, t("enrol.passkey.lead")),
      h("div", { class: "actions" }, h("button", { type: "button", class: "primary", disabled: busy, "data-autofocus": true, "data-testid": "enrol-create-passkey", onclick: () => void controller.createPasskey() }, t("enrol.passkey.button"))),
    ];
  }
  return h("main", { "aria-busy": busy ? "true" : "false", "data-screen": "enrol", "data-step": state.step }, heading, noticeElement(state.notice, locale), ...body, status, h("div", { class: "actions" }, back));
}
