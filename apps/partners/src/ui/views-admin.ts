/**
 * Draws the S7d manager/operator/admin screens. Plain DOM, `textContent` only. Forms collect values on
 * submit and hand them to the controller; nothing secret is kept in the tree.
 */

import type { AppController } from "../app/controller";
import { trailChoices } from "../app/admin";
import type { SignedInState } from "../app/state";
import { translate, type Locale, type MessageKey } from "../i18n";
import { h } from "./dom";
import { noticeElement } from "./notice";

function trailField(state: SignedInState, controller: AppController, locale: Locale): HTMLElement {
  const t = (k: MessageKey) => translate(locale, k);
  const work = state.work;
  const current = work !== null && "trailId" in work ? work.trailId : "";
  const choices = trailChoices(state.session);
  const busy = state.busy !== null;
  if (choices.length > 0) {
    return h(
      "label",
      { class: "field" },
      h("span", {}, t("admin.trail")),
      h(
        "select",
        {
          "data-testid": "admin-trail",
          "aria-label": t("admin.trail"),
          disabled: busy,
          onchange: (e: Event) => controller.setAdminTrail((e.target as HTMLSelectElement).value),
        },
        ...choices.map((id) => h("option", { value: id, selected: id === current }, id)),
      ),
    );
  }
  return h(
    "label",
    { class: "field" },
    h("span", {}, t("admin.trail")),
    h("input", {
      type: "text",
      value: current,
      autocomplete: "off",
      spellcheck: "false",
      "data-testid": "admin-trail",
      disabled: busy,
      onchange: (e: Event) => controller.setAdminTrail((e.target as HTMLInputElement).value),
    }),
  );
}

function back(controller: AppController, locale: Locale, busy: boolean): HTMLElement {
  return h("button", { type: "button", disabled: busy, "data-testid": "work-back", onclick: () => controller.closeWork() }, translate(locale, "work.back"));
}

function optionalText(v: FormDataEntryValue | null): string | null {
  const s = String(v ?? "").trim();
  return s.length > 0 ? s : null;
}

function optionalNum(v: FormDataEntryValue | null): number | null {
  const s = String(v ?? "").trim();
  if (s.length === 0) return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

export function adminView(state: SignedInState, controller: AppController, locale: Locale): HTMLElement {
  const t = (k: MessageKey, p?: Record<string, string | number>) => translate(locale, k, p);
  const work = state.work!;
  const busy = state.busy !== null || work.busy;

  if (work.kind === "programme") {
    return h(
      "main",
      { "aria-busy": busy ? "true" : "false", "data-screen": "programme" },
      h("h1", { tabindex: "-1", "data-testid": "heading" }, t("programme.title")),
      noticeElement(state.notice, locale),
      trailField(state, controller, locale),
      h("p", { class: "muted" }, t("programme.hint")),
      work.trail !== null
        ? h(
            "p",
            { "data-testid": "programme-trail" },
            t("programme.trail.summary", { status: work.trail.status, source: work.trail.markerSource }),
          )
        : null,
      work.facilities !== null
        ? h(
            "ul",
            { "data-testid": "programme-facilities" },
            ...work.facilities.map((f) => h("li", {}, t("programme.facility.row", { facility: f.facilityId, participation: f.participation, qr: f.qrMode }))),
          )
        : null,
      h(
        "form",
        {
          "data-testid": "programme-trail-form",
          onsubmit: (e: SubmitEvent) => {
            e.preventDefault();
            const fd = new FormData(e.target as HTMLFormElement);
            void controller.saveTrailProgramme({
              trailId: work.trailId,
              status: String(fd.get("status") ?? "off"),
              markerSource: String(fd.get("markerSource") ?? "any_purchase"),
              markerRequiresCompletion: fd.get("markerRequiresCompletion") === "on",
              specialMarkerFundedBy: optionalText(fd.get("specialMarkerFundedBy")),
              specialMarkerLowThreshold: Number(fd.get("specialMarkerLowThreshold") ?? 0),
              webPlayerFlow: fd.get("webPlayerFlow") === "on",
              specialMarkerSku: optionalText(fd.get("specialMarkerSku")),
              specialMarkerSponsorshipId: optionalText(fd.get("specialMarkerSponsorshipId")),
              feeModel: optionalText(fd.get("feeModel")),
              feeAmount: optionalNum(fd.get("feeAmount")),
              startsOn: optionalText(fd.get("startsOn")),
              endsOn: optionalText(fd.get("endsOn")),
            });
          },
        },
        h("h2", {}, t("programme.trail.form")),
        h("label", { class: "field" }, h("span", {}, t("programme.status")), h("select", { name: "status", "data-testid": "programme-status", disabled: busy }, h("option", { value: "off" }, "off"), h("option", { value: "pilot", selected: true }, "pilot"), h("option", { value: "live" }, "live"))),
        h("label", { class: "field" }, h("span", {}, t("programme.markerSource")), h("select", { name: "markerSource", "data-testid": "programme-marker-source", disabled: busy }, h("option", { value: "any_purchase", selected: true }, "any_purchase"), h("option", { value: "programme_marker" }, "programme_marker"))),
        h("label", { class: "field" }, h("span", {}, t("programme.lowThreshold")), h("input", { name: "specialMarkerLowThreshold", type: "number", value: "3", "data-testid": "programme-low", disabled: busy })),
        h("label", { class: "field" }, h("input", { name: "markerRequiresCompletion", type: "checkbox", "data-testid": "programme-requires", disabled: busy }), " ", h("span", {}, t("programme.requiresCompletion"))),
        h("label", { class: "field" }, h("input", { name: "webPlayerFlow", type: "checkbox", "data-testid": "programme-web", disabled: busy }), " ", h("span", {}, t("programme.webPlayer"))),
        h("label", { class: "field" }, h("span", {}, t("programme.fundedBy")), h("input", { name: "specialMarkerFundedBy", type: "text", "data-testid": "programme-funded", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("programme.sku")), h("input", { name: "specialMarkerSku", type: "text", "data-testid": "programme-sku", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("programme.sponsorshipId")), h("input", { name: "specialMarkerSponsorshipId", type: "text", "data-testid": "programme-sponsorship", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("programme.feeModel")), h("input", { name: "feeModel", type: "text", "data-testid": "programme-fee-model", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("programme.feeAmount")), h("input", { name: "feeAmount", type: "number", "data-testid": "programme-fee-amount", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("programme.startsOn")), h("input", { name: "startsOn", type: "text", "data-testid": "programme-starts", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("programme.endsOn")), h("input", { name: "endsOn", type: "text", "data-testid": "programme-ends", disabled: busy })),
        h("div", { class: "actions" }, h("button", { type: "submit", class: "primary", disabled: busy, "data-testid": "programme-trail-save" }, t("programme.trail.save"))),
      ),
      h(
        "form",
        {
          "data-testid": "programme-facility-form",
          onsubmit: (e: SubmitEvent) => {
            e.preventDefault();
            const fd = new FormData(e.target as HTMLFormElement);
            const stocks = String(fd.get("stocksMarkers") ?? "");
            const holds = String(fd.get("holdsSpecialMarker") ?? "");
            const staff = String(fd.get("staffNetwork") ?? "");
            void controller.saveFacilityProgramme({
              trailId: work.trailId,
              facilityId: String(fd.get("facilityId") ?? ""),
              participation: String(fd.get("participation") ?? "invited"),
              stocksMarkers: stocks === "" ? null : stocks === "true",
              holdsSpecialMarker: holds === "" ? null : holds === "true",
              connectivity: optionalText(fd.get("connectivity")),
              staffNetwork: staff === "" ? null : staff === "true",
              wifiNote: optionalText(fd.get("wifiNote")),
              qrMode: String(fd.get("qrMode") ?? "rotating"),
            });
          },
        },
        h("h2", {}, t("programme.facility.form")),
        h("label", { class: "field" }, h("span", {}, t("programme.facilityId")), h("input", { name: "facilityId", type: "text", required: true, "data-testid": "programme-facility-id", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("programme.participation")), h("select", { name: "participation", "data-testid": "programme-participation", disabled: busy }, h("option", { value: "invited", selected: true }, "invited"), h("option", { value: "accepted" }, "accepted"), h("option", { value: "declined" }, "declined"), h("option", { value: "left" }, "left"))),
        h("label", { class: "field" }, h("span", {}, t("programme.qrMode")), h("select", { name: "qrMode", "data-testid": "programme-qr-mode", disabled: busy }, h("option", { value: "rotating", selected: true }, "rotating"), h("option", { value: "static_pin" }, "static_pin"), h("option", { value: "both" }, "both"))),
        h("label", { class: "field" }, h("span", {}, t("programme.stocksMarkers")), h("input", { name: "stocksMarkers", type: "text", "data-testid": "programme-stocks", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("programme.holdsMarker")), h("input", { name: "holdsSpecialMarker", type: "text", "data-testid": "programme-holds", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("programme.connectivity")), h("input", { name: "connectivity", type: "text", "data-testid": "programme-connectivity", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("programme.staffNetwork")), h("input", { name: "staffNetwork", type: "text", "data-testid": "programme-staff-net", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("programme.wifiNote")), h("input", { name: "wifiNote", type: "text", "data-testid": "programme-wifi", disabled: busy })),
        h("div", { class: "actions" }, h("button", { type: "submit", class: "primary", disabled: busy, "data-testid": "programme-facility-save" }, t("programme.facility.save"))),
      ),
      h(
        "div",
        { class: "actions" },
        h("button", { type: "button", disabled: busy, "data-testid": "programme-load", onclick: () => void controller.loadProgramme() }, t("programme.load")),
        back(controller, locale, busy),
      ),
      busy ? h("p", { class: "muted", role: "status" }, t("work.busy")) : null,
    );
  }

  if (work.kind === "offers") {
    return h(
      "main",
      { "aria-busy": busy ? "true" : "false", "data-screen": "offers" },
      h("h1", { tabindex: "-1", "data-testid": "heading" }, t("offers.title")),
      noticeElement(state.notice, locale),
      trailField(state, controller, locale),
      h("p", { class: "muted" }, t("offers.hint")),
      work.lastId !== null ? h("p", { role: "status", "data-testid": "offers-last-id" }, t("offers.lastId", { id: work.lastId })) : null,
      work.offers !== null
        ? h(
            "ul",
            { "data-testid": "offers-list" },
            ...work.offers.map((o) =>
              h(
                "li",
                {},
                h("span", {}, t("offers.row", { id: o.id, status: o.status, funder: o.funder, cap: o.budgetCap, used: o.budgetUsed, face: o.faceValue })),
                h(
                  "div",
                  { class: "actions" },
                  h("button", { type: "button", disabled: busy || o.status !== "draft", "data-testid": `offers-approve-${o.id}`, onclick: () => void controller.approveOffer(o.id) }, t("offers.approve")),
                  h("button", { type: "button", disabled: busy || o.status !== "live", "data-testid": `offers-end-${o.id}`, onclick: () => void controller.endOffer(o.id) }, t("offers.end")),
                ),
              ),
            ),
          )
        : null,
      h(
        "form",
        {
          "data-testid": "offers-form",
          onsubmit: (e: SubmitEvent) => {
            e.preventDefault();
            const fd = new FormData(e.target as HTMLFormElement);
            let eligibility: unknown = {};
            try {
              eligibility = JSON.parse(String(fd.get("eligibility") ?? "{}"));
            } catch {
              eligibility = null;
            }
            if (eligibility === null || typeof eligibility !== "object") {
              return;
            }
            void controller.saveOffer({
              id: optionalText(fd.get("id")),
              trailId: work.trailId,
              facilityId: String(fd.get("facilityId") ?? ""),
              eligibility,
              funder: String(fd.get("funder") ?? "course"),
              sponsorshipId: optionalText(fd.get("sponsorshipId")),
              budgetCap: Number(fd.get("budgetCap") ?? 0),
              maxRedemptions: optionalNum(fd.get("maxRedemptions")),
              faceValue: Number(fd.get("faceValue") ?? 0),
              validFrom: String(fd.get("validFrom") ?? ""),
              validTo: String(fd.get("validTo") ?? ""),
            });
          },
        },
        h("h2", {}, t("offers.form")),
        h("label", { class: "field" }, h("span", {}, t("offers.id")), h("input", { name: "id", type: "text", "data-testid": "offers-id", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("offers.facility")), h("input", { name: "facilityId", type: "text", required: true, "data-testid": "offers-facility", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("offers.funder")), h("select", { name: "funder", "data-testid": "offers-funder", disabled: busy }, h("option", { value: "course", selected: true }, "course"), h("option", { value: "operator" }, "operator"), h("option", { value: "sponsor" }, "sponsor"))),
        h("label", { class: "field" }, h("span", {}, t("offers.sponsorshipId")), h("input", { name: "sponsorshipId", type: "text", "data-testid": "offers-sponsorship", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("offers.budgetCap")), h("input", { name: "budgetCap", type: "number", required: true, value: "100", "data-testid": "offers-budget", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("offers.maxRedemptions")), h("input", { name: "maxRedemptions", type: "number", "data-testid": "offers-max", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("offers.faceValue")), h("input", { name: "faceValue", type: "number", required: true, value: "10", "data-testid": "offers-face", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("offers.validFrom")), h("input", { name: "validFrom", type: "text", required: true, value: "2026-01-01", "data-testid": "offers-from", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("offers.validTo")), h("input", { name: "validTo", type: "text", required: true, value: "2026-12-31", "data-testid": "offers-to", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("offers.eligibility")), h("input", { name: "eligibility", type: "text", value: '{"all":true}', "data-testid": "offers-eligibility", disabled: busy })),
        h("div", { class: "actions" }, h("button", { type: "submit", class: "primary", disabled: busy, "data-testid": "offers-save" }, t("offers.save"))),
      ),
      h(
        "div",
        { class: "actions" },
        h("button", { type: "button", disabled: busy, "data-testid": "offers-load", onclick: () => void controller.loadOffers() }, t("offers.load")),
        back(controller, locale, busy),
      ),
      busy ? h("p", { class: "muted", role: "status" }, t("work.busy")) : null,
    );
  }

  if (work.kind === "sponsorships") {
    return h(
      "main",
      { "aria-busy": busy ? "true" : "false", "data-screen": "sponsorships" },
      h("h1", { tabindex: "-1", "data-testid": "heading" }, t("sponsorships.title")),
      noticeElement(state.notice, locale),
      trailField(state, controller, locale),
      h("p", { class: "muted" }, t("sponsorships.hint")),
      work.lastId !== null ? h("p", { role: "status", "data-testid": "sponsorships-last-id" }, t("sponsorships.lastId", { id: work.lastId })) : null,
      work.sponsorships !== null
        ? h(
            "ul",
            { "data-testid": "sponsorships-list" },
            ...work.sponsorships.map((s) =>
              h(
                "li",
                {},
                h("span", {}, t("sponsorships.row", { id: s.id, status: s.status, name: s.attributionName, category: s.category })),
                h(
                  "div",
                  { class: "actions" },
                  h("button", { type: "button", disabled: busy || s.status !== "draft", "data-testid": `sponsorships-approve-${s.id}`, onclick: () => void controller.approveSponsorship(s.id) }, t("sponsorships.approve")),
                ),
              ),
            ),
          )
        : null,
      h(
        "form",
        {
          "data-testid": "sponsorships-form",
          onsubmit: (e: SubmitEvent) => {
            e.preventDefault();
            const fd = new FormData(e.target as HTMLFormElement);
            void controller.saveSponsorship({
              id: optionalText(fd.get("id")),
              sponsorOrgId: String(fd.get("sponsorOrgId") ?? ""),
              trailId: work.trailId,
              category: String(fd.get("category") ?? "equipment"),
              scope: String(fd.get("scope") ?? "offers"),
              attributionName: String(fd.get("attributionName") ?? ""),
              attributionAsset: optionalText(fd.get("attributionAsset")),
              placementFee: optionalNum(fd.get("placementFee")),
              startsOn: optionalText(fd.get("startsOn")),
              endsOn: optionalText(fd.get("endsOn")),
            });
          },
        },
        h("h2", {}, t("sponsorships.form")),
        h("label", { class: "field" }, h("span", {}, t("sponsorships.id")), h("input", { name: "id", type: "text", "data-testid": "sponsorships-id", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("sponsorships.sponsorOrg")), h("input", { name: "sponsorOrgId", type: "text", required: true, "data-testid": "sponsorships-org", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("sponsorships.category")), h("select", { name: "category", "data-testid": "sponsorships-category", disabled: busy }, h("option", { value: "equipment", selected: true }, "equipment"), h("option", { value: "apparel" }, "apparel"), h("option", { value: "tourism" }, "tourism"), h("option", { value: "other" }, "other"))),
        h("label", { class: "field" }, h("span", {}, t("sponsorships.scope")), h("select", { name: "scope", "data-testid": "sponsorships-scope", disabled: busy }, h("option", { value: "special_marker" }, "special_marker"), h("option", { value: "offers", selected: true }, "offers"), h("option", { value: "both" }, "both"))),
        h("label", { class: "field" }, h("span", {}, t("sponsorships.name")), h("input", { name: "attributionName", type: "text", required: true, "data-testid": "sponsorships-name", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("sponsorships.asset")), h("input", { name: "attributionAsset", type: "text", "data-testid": "sponsorships-asset", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("sponsorships.fee")), h("input", { name: "placementFee", type: "number", "data-testid": "sponsorships-fee", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("sponsorships.startsOn")), h("input", { name: "startsOn", type: "text", "data-testid": "sponsorships-starts", disabled: busy })),
        h("label", { class: "field" }, h("span", {}, t("sponsorships.endsOn")), h("input", { name: "endsOn", type: "text", "data-testid": "sponsorships-ends", disabled: busy })),
        h("div", { class: "actions" }, h("button", { type: "submit", class: "primary", disabled: busy, "data-testid": "sponsorships-save" }, t("sponsorships.save"))),
      ),
      h(
        "div",
        { class: "actions" },
        h("button", { type: "button", disabled: busy, "data-testid": "sponsorships-load", onclick: () => void controller.loadSponsorships() }, t("sponsorships.load")),
        back(controller, locale, busy),
      ),
      busy ? h("p", { class: "muted", role: "status" }, t("work.busy")) : null,
    );
  }

  if (work.kind === "review") {
    return h(
      "main",
      { "aria-busy": busy ? "true" : "false", "data-screen": "review" },
      h("h1", { tabindex: "-1", "data-testid": "heading" }, t("review.title")),
      noticeElement(state.notice, locale),
      h("p", { class: "muted" }, t("review.hint")),
      work.sla !== null
        ? h(
            "p",
            { "data-testid": "review-sla" },
            t("review.sla", {
              codes: work.sla.heldOfferCodes,
              ents: work.sla.heldEntitlements,
              open: work.sla.openReviewItems,
              breachR: work.sla.slaBreachedRewards,
              breachI: work.sla.slaBreachedReviewItems,
              hours: work.sla.slaHours,
            }),
          )
        : null,
      work.lastState !== null ? h("p", { role: "status", "data-testid": "review-last-state" }, t("review.lastState", { state: work.lastState })) : null,
      work.items !== null
        ? h(
            "ul",
            { "data-testid": "review-queue" },
            ...work.items.map((item) =>
              h(
                "li",
                {},
                h("span", {}, t("review.row", { kind: item.kind, handle: item.handle, breached: item.slaBreached ? t("common.yes") : t("common.no") })),
                h(
                  "div",
                  { class: "actions" },
                  item.kind === "offer_code" || item.subjectTable === "offer_codes"
                    ? h("button", { type: "button", disabled: busy, "data-testid": `review-approve-code-${item.id}`, onclick: () => void controller.resolveOfferCode(item.id, true) }, t("review.approve"))
                    : h("button", { type: "button", disabled: busy, "data-testid": `review-approve-ent-${item.id}`, onclick: () => void controller.resolveEntitlement(item.id, true) }, t("review.approve")),
                  item.kind === "offer_code" || item.subjectTable === "offer_codes"
                    ? h("button", { type: "button", disabled: busy, "data-testid": `review-reject-code-${item.id}`, onclick: () => void controller.resolveOfferCode(item.id, false) }, t("review.reject"))
                    : h("button", { type: "button", disabled: busy, "data-testid": `review-reject-ent-${item.id}`, onclick: () => void controller.resolveEntitlement(item.id, false) }, t("review.reject")),
                ),
              ),
            ),
          )
        : null,
      h(
        "div",
        { class: "actions" },
        h("button", { type: "button", disabled: busy, "data-testid": "review-load", onclick: () => void controller.loadReview() }, t("review.load")),
        back(controller, locale, busy),
      ),
      busy ? h("p", { class: "muted", role: "status" }, t("work.busy")) : null,
    );
  }

  if (work.kind !== "rollups") {
    return h("main", { "data-screen": "admin" }, h("h1", { tabindex: "-1", "data-testid": "heading" }, t("home.admin.title")), back(controller, locale, busy));
  }

  return h(
    "main",
    { "aria-busy": busy ? "true" : "false", "data-screen": "rollups" },
    h("h1", { tabindex: "-1", "data-testid": "heading" }, t("rollups.title")),
    noticeElement(state.notice, locale),
    trailField(state, controller, locale),
    h("p", { class: "muted" }, t("rollups.hint")),
    work.operator !== null
      ? h(
          "ul",
          { "data-testid": "rollups-operator" },
          ...work.operator.map((r) => h("li", {}, t("rollups.row", { month: r.month, metric: r.metric, value: r.value, cohort: r.cohortN }))),
        )
      : null,
    h(
      "label",
      { class: "field" },
      h("span", {}, t("rollups.sponsorshipId")),
      h("input", {
        type: "text",
        value: work.sponsorshipId,
        autocomplete: "off",
        "data-testid": "rollups-sponsorship",
        disabled: busy,
        onchange: (e: Event) => controller.setAdminSponsorshipId((e.target as HTMLInputElement).value),
      }),
    ),
    work.sponsor !== null
      ? h(
          "ul",
          { "data-testid": "rollups-sponsor" },
          ...work.sponsor.map((r) => h("li", {}, t("rollups.row", { month: r.month, metric: r.metric, value: r.value, cohort: r.cohortN }))),
        )
      : null,
    h(
      "div",
      { class: "actions" },
      h("button", { type: "button", disabled: busy, "data-testid": "rollups-operator-load", onclick: () => void controller.loadOperatorRollups() }, t("rollups.loadOperator")),
      h("button", { type: "button", disabled: busy, "data-testid": "rollups-sponsor-load", onclick: () => void controller.loadSponsorRollups() }, t("rollups.loadSponsor")),
      back(controller, locale, busy),
    ),
    busy ? h("p", { class: "muted", role: "status" }, t("work.busy")) : null,
  );
}
