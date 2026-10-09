/**
 * Draws the S7b/S7c work screens (attest, course-QR, stock, hand-over). Plain DOM, `textContent` only. Forms collect values on submit and hand them to the controller; nothing secret is kept in the tree.
 */

import type { AppController } from "../app/controller";
import type { SignedInState } from "../app/state";
import { facilityChoices } from "../app/work";
import { STOCK_MOVE_KINDS, type StockMoveKind } from "../api/work-routes";
import { translate, type Locale, type MessageKey } from "../i18n";
import { h } from "./dom";
import { noticeElement } from "./notice";
import { adminView } from "./views-admin";

function facilitySelect(state: SignedInState, controller: AppController, locale: Locale): HTMLElement {
  const t = (k: MessageKey) => translate(locale, k);
  const choices = facilityChoices(state.session);
  const work = state.work;
  const current = work !== null && "facilityId" in work ? work.facilityId : choices[0] ?? "";
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
  const work = state.work!;
  if (
    work.kind === "programme" || work.kind === "offers" || work.kind === "sponsorships" ||
    work.kind === "review" || work.kind === "rollups"
  ) {
    return adminView(state, controller, locale);
  }

  const t = (k: MessageKey, p?: Record<string, string | number>) => translate(locale, k, p);
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

  if (work.kind === "course-qr") {
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

  if (work.kind === "stock") {
    return h(
      "main",
      { "aria-busy": busy ? "true" : "false", "data-screen": "stock" },
      h("h1", { tabindex: "-1", "data-testid": "heading" }, t("stock.title")),
      noticeElement(state.notice, locale),
      facilitySelect(state, controller, locale),
      h("p", { class: "muted" }, t("stock.hint")),
      work.lastOnHand !== null ? h("p", { role: "status", "data-testid": "stock-last" }, t("stock.lastOnHand", { onHand: work.lastOnHand })) : null,
      work.rows !== null
        ? h(
            "ul",
            { "data-testid": "stock-rows" },
            ...work.rows.map((r) => h("li", {}, t("stock.row", { trail: r.trailId, onHand: r.onHand, status: r.status }))),
          )
        : null,
      h(
        "form",
        {
          "data-testid": "stock-move",
          onsubmit: (e: SubmitEvent) => {
            e.preventDefault();
            const fd = new FormData(e.target as HTMLFormElement);
            const kind = String(fd.get("kind") ?? "") as StockMoveKind;
            const qty = Number(fd.get("qty"));
            const noteRaw = String(fd.get("note") ?? "").trim();
            void controller.submitStockMove(String(fd.get("trailId") ?? ""), kind, qty, noteRaw.length > 0 ? noteRaw : null);
          },
        },
        h("label", { class: "field" }, h("span", {}, t("stock.trail")), h("input", { name: "trailId", type: "text", autocomplete: "off", spellcheck: "false", required: true, "data-testid": "stock-trail", disabled: busy })),
        h(
          "label",
          { class: "field" },
          h("span", {}, t("stock.kind")),
          h(
            "select",
            { name: "kind", "data-testid": "stock-kind", disabled: busy },
            ...STOCK_MOVE_KINDS.map((k) => h("option", { value: k }, t(`stock.kind.${k}` as MessageKey))),
          ),
        ),
        h("label", { class: "field" }, h("span", {}, t("stock.qty")), h("input", { name: "qty", type: "number", required: true, "data-testid": "stock-qty", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("stock.note")), h("input", { name: "note", type: "text", autocomplete: "off", "data-testid": "stock-note", disabled: busy })),
        h("div", { class: "actions" }, h("button", { type: "submit", class: "primary", disabled: busy, "data-testid": "stock-move-submit" }, t("stock.move"))),
      ),
      h(
        "div",
        { class: "actions" },
        h("button", { type: "button", disabled: busy, "data-testid": "stock-load", onclick: () => void controller.loadStock() }, t("stock.load")),
        back,
      ),
      busy ? h("p", { class: "muted", role: "status" }, t("work.busy")) : null,
    );
  }

  // handover
  const scan = work.redeemMethod === "staff_scan";
  return h(
    "main",
    { "aria-busy": busy ? "true" : "false", "data-screen": "handover" },
    h("h1", { tabindex: "-1", "data-testid": "heading" }, t("handover.title")),
    noticeElement(state.notice, locale),
    facilitySelect(state, controller, locale),
    h("p", { class: "muted" }, t("handover.hint")),
    work.minted !== null
      ? h(
          "div",
          { role: "status", "data-testid": "handover-minted" },
          h("p", {}, t("handover.minted.lead")),
          h("p", { "data-testid": "handover-token" }, work.minted.token),
          h("p", { class: "muted" }, t("handover.minted.until", { until: work.minted.expiresAt })),
          h("button", { type: "button", disabled: busy, "data-testid": "handover-mint-dismiss", onclick: () => controller.dismissHandoverMint() }, t("handover.minted.dismiss")),
        )
      : null,
    work.queue !== null
      ? h(
          "ul",
          { "data-testid": "handover-queue" },
          ...work.queue.map((r) =>
            h(
              "li",
              {},
              h("span", {}, t("handover.queue.row", { handle: r.playerHandle, trail: r.trailId, state: r.state })),
              h(
                "div",
                { class: "actions" },
                h("button", { type: "button", disabled: busy, "data-testid": `handover-mint-${r.entitlementId}`, onclick: () => void controller.mintHandover(r.entitlementId) }, t("handover.mint")),
                h("button", { type: "button", disabled: busy, "data-testid": `handover-voucher-${r.entitlementId}`, onclick: () => void controller.submitVoucher(r.entitlementId) }, t("handover.voucher")),
              ),
            ),
          ),
        )
      : null,
    h(
      "div",
      { class: "actions" },
      h("button", { type: "button", ...(scan ? { class: "primary" } : {}), disabled: busy, "data-testid": "handover-method-scan", onclick: () => controller.setRedeemMethod("staff_scan") }, t("handover.method.scan")),
      h("button", { type: "button", ...(!scan ? { class: "primary" } : {}), disabled: busy, "data-testid": "handover-method-token", onclick: () => controller.setRedeemMethod("hand_over_token") }, t("handover.method.token")),
    ),
    h(
      "form",
      {
        "data-testid": "handover-redeem",
        onsubmit: (e: SubmitEvent) => {
          e.preventDefault();
          const fd = new FormData(e.target as HTMLFormElement);
          void controller.submitRedeem(String(fd.get("entitlementId") ?? ""), String(fd.get("credential") ?? ""));
        },
      },
      h("label", { class: "field" }, h("span", {}, t("handover.entitlement")), h("input", { name: "entitlementId", type: "text", autocomplete: "off", spellcheck: "false", required: true, "data-testid": "handover-entitlement", disabled: busy })),
      h(
        "label",
        { class: "field" },
        h("span", {}, scan ? t("handover.credential.scan") : t("handover.credential.token")),
        h("input", { name: "credential", type: "text", autocomplete: "off", spellcheck: "false", required: true, "data-autofocus": true, "data-testid": "handover-credential", disabled: busy }),
      ),
      h("div", { class: "actions" }, h("button", { type: "submit", class: "primary", disabled: busy, "data-testid": "handover-redeem-submit" }, t("handover.redeem"))),
    ),
    work.lastRedeem !== null
      ? h("p", { role: "status", "data-testid": "handover-redeem-result" }, t("handover.redeem.result", { movement: work.lastRedeem.movement }))
      : null,
    h(
      "div",
      { class: "actions" },
      h("button", { type: "button", disabled: busy, "data-testid": "handover-load", onclick: () => void controller.loadCollectQueue() }, t("handover.load")),
      back,
    ),
    busy ? h("p", { class: "muted", role: "status" }, t("work.busy")) : null,
  );
}
