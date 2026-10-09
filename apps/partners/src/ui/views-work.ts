/**
 * Draws the S7b work screens (attest and course-QR). Plain DOM, `textContent` only. Forms collect values on submit and hand them to the controller; nothing secret is kept in the tree.
 */

import type { AppController } from "../app/controller";
import type { SignedInState } from "../app/state";
import { facilityChoices } from "../app/work";
import { translate, type Locale, type MessageKey } from "../i18n";
import { h } from "./dom";
import { noticeElement } from "./notice";

function facilitySelect(state: SignedInState, controller: AppController, locale: Locale): HTMLElement {
  const t = (k: MessageKey) => translate(locale, k);
  const choices = facilityChoices(state.session);
  const current = state.work?.facilityId ?? choices[0] ?? "";
  const select = h(
    "select",
    {
      "data-testid": "work-facility",
      "aria-label": t("work.facility"),
      disabled: state.busy !== null || choices.length === 0,
      onchange: (e: Event) => controller.setWorkFacility((e.target as HTMLSelectElement).value),
    },
    ...choices.map((id) => h("option", { value: id, selected: id === current }, id)),
  );
  return h("label", { class: "field" }, h("span", {}, t("work.facility")), select);
}

export function workView(state: SignedInState, controller: AppController, locale: Locale): HTMLElement {
  const t = (k: MessageKey, p?: Record<string, string | number>) => translate(locale, k, p);
  const work = state.work!;
  const busy = state.busy !== null || work.busy;
  const back = h("button", { type: "button", disabled: busy, "data-testid": "work-back", onclick: () => controller.closeWork() }, t("work.back"));

  if (work.kind === "attest") {
    const online = work.mode === "online";
    const form = online
      ? h(
          "form",
          {
            "data-testid": "attest-online",
            onsubmit: (e: SubmitEvent) => {
              e.preventDefault();
              const fd = new FormData(e.target as HTMLFormElement);
              void controller.submitOnlineAttest(String(fd.get("token") ?? ""));
            },
          },
          h("label", { class: "field" }, h("span", {}, t("attest.token.label")), h("input", { name: "token", type: "text", autocomplete: "off", spellcheck: "false", required: true, "data-autofocus": true, "data-testid": "attest-token", disabled: busy })),
          h("p", { class: "muted" }, t("attest.token.hint")),
          h("div", { class: "actions" }, h("button", { type: "submit", class: "primary", disabled: busy, "data-testid": "attest-online-submit" }, t("attest.token.submit"))),
        )
      : h(
          "form",
          {
            "data-testid": "attest-offline",
            onsubmit: (e: SubmitEvent) => {
              e.preventDefault();
              const fd = new FormData(e.target as HTMLFormElement);
              void controller.submitOfflineAttest(String(fd.get("handle") ?? ""), String(fd.get("code") ?? ""));
            },
          },
          h("label", { class: "field" }, h("span", {}, t("attest.handle.label")), h("input", { name: "handle", type: "text", autocomplete: "off", spellcheck: "false", required: true, "data-autofocus": true, "data-testid": "attest-handle", disabled: busy })),
          h("label", { class: "field" }, h("span", {}, t("attest.code.label")), h("input", { name: "code", type: "text", inputmode: "numeric", autocomplete: "one-time-code", maxlength: 6, required: true, "data-testid": "attest-code", disabled: busy })),
          h("div", { class: "actions" }, h("button", { type: "submit", class: "primary", disabled: busy, "data-testid": "attest-offline-submit" }, t("attest.offline.submit"))),
        );

    return h(
      "main",
      { "aria-busy": busy ? "true" : "false", "data-screen": "attest" },
      h("h1", { tabindex: "-1", "data-testid": "heading" }, t("attest.title")),
      noticeElement(state.notice, locale),
      facilitySelect(state, controller, locale),
      h(
        "div",
        { class: "actions" },
        h("button", { type: "button", ...(online ? { class: "primary" } : {}), disabled: busy, "data-testid": "attest-mode-online", onclick: () => controller.setAttestMode("online") }, t("attest.mode.online")),
        h("button", { type: "button", ...(!online ? { class: "primary" } : {}), disabled: busy, "data-testid": "attest-mode-offline", onclick: () => controller.setAttestMode("offline") }, t("attest.mode.offline")),
      ),
      h(
        "label",
        { class: "field" },
        h("span", {}, t("attest.kind")),
        h(
          "select",
          {
            "data-testid": "attest-kind",
            disabled: busy,
            onchange: (e: Event) => controller.setAttestKind((e.target as HTMLSelectElement).value === "marker_purchase" ? "marker_purchase" : "presence"),
          },
          h("option", { value: "presence", selected: work.attestKind === "presence" }, t("attest.kind.presence")),
          h("option", { value: "marker_purchase", selected: work.attestKind === "marker_purchase" }, t("attest.kind.marker_purchase")),
        ),
      ),
      form,
      work.lastResult !== null
        ? h("p", { role: "status", "data-testid": "attest-result" }, t("attest.result", { held: work.lastResult.held ? t("common.yes") : t("common.no") }))
        : null,
      h(
        "div",
        { class: "actions" },
        h("button", { type: "button", disabled: busy, "data-testid": "attest-shift-log", onclick: () => void controller.loadShiftLog() }, t("attest.shiftLog")),
        h("button", { type: "button", disabled: busy, "data-testid": "attest-staff-activity", onclick: () => void controller.loadStaffActivity(7) }, t("attest.staffActivity")),
        back,
      ),
      work.shiftLog !== null
        ? h("ul", { "data-testid": "shift-log" }, ...work.shiftLog.map((e) => h("li", {}, `${e.createdAt} · ${e.kind} · ${e.playerHandle} · ${e.staffHandle}`)))
        : null,
      work.staffActivity !== null
        ? h("ul", { "data-testid": "staff-activity" }, ...work.staffActivity.map((r) => h("li", {}, `${r.day} · ${r.attests} · ${r.activations} · ${r.anomalies}`)))
        : null,
      busy ? h("p", { class: "muted", role: "status" }, t("work.busy")) : null,
    );
  }

  return h(
    "main",
    { "aria-busy": busy ? "true" : "false", "data-screen": "course-qr" },
    h("h1", { tabindex: "-1", "data-testid": "heading" }, t("courseQr.title")),
    noticeElement(state.notice, locale),
    facilitySelect(state, controller, locale),
    h(
      "section",
      {},
      h("h2", {}, t("courseQr.pin.title")),
      work.pin !== null ? h("p", { "data-testid": "course-pin" }, t("courseQr.pin.value", { pin: work.pin.pin, until: work.pin.validUntil, epoch: work.pin.pinEpoch })) : null,
      h(
        "div",
        { class: "actions" },
        h("button", { type: "button", disabled: busy, "data-testid": "course-pin-load", onclick: () => void controller.loadCoursePin() }, t("courseQr.pin.load")),
        h("button", { type: "button", disabled: busy, "data-testid": "course-pin-rotate", onclick: () => void controller.rotatePin() }, t("courseQr.pin.rotate")),
      ),
    ),
    h(
      "section",
      {},
      h("h2", {}, t("courseQr.sale.title")),
      work.sale !== null
        ? h(
            "div",
            { "data-testid": "course-sale" },
            h("p", {}, `${t("courseQr.sale.token")}: ${work.sale.token}`),
            work.sale.link !== null ? h("p", {}, `${t("courseQr.sale.link")}: ${work.sale.link}`) : null,
            work.refreshLeft !== null ? h("p", {}, t("courseQr.sale.left", { seconds: work.refreshLeft })) : null,
          )
        : null,
      h(
        "div",
        { class: "actions" },
        h("button", { type: "button", class: "primary", disabled: busy, "data-testid": "course-mint", onclick: () => void controller.mintToken() }, t("courseQr.sale.mint")),
        h("button", { type: "button", disabled: busy || work.sale === null, "data-testid": "course-refresh", onclick: () => void controller.refreshSale() }, t("courseQr.sale.refresh")),
      ),
    ),
    h(
      "section",
      {},
      h("h2", {}, t("courseQr.print.title")),
      work.printed !== null ? h("p", { "data-testid": "course-printed" }, t("courseQr.print.meta", { kid: work.printed.qrKid, at: work.printed.printedAt })) : null,
      h(
        "div",
        { class: "actions" },
        h("button", { type: "button", disabled: busy, "data-testid": "course-print-load", onclick: () => void controller.loadPrintedQr() }, t("courseQr.print.load")),
        h("button", { type: "button", disabled: busy, "data-testid": "course-print-write", onclick: () => void controller.printQr() }, t("courseQr.print.write")),
        back,
      ),
    ),
    busy ? h("p", { class: "muted", role: "status" }, t("work.busy")) : null,
  );
}
