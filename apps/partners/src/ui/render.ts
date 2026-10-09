/**
 * Draws an `AppState`. Plain DOM, `textContent` only (see dom.ts). The whole tree is rebuilt on every state change: it is a few dozen nodes, and a
 * rebuild means no stale node can keep showing data from a session that has ended. After the rebuild the heading takes focus, so a screen-reader
 * user lands on the new screen.
 */

import type { WhoAmI } from "../api/types";
import { canOpenAdminOps, canOpenReview, trailChoices } from "../app/admin";
import type { AppState, AppController } from "../app/controller";
import { translate, plural, type Locale, type MessageKey } from "../i18n";
import { h } from "./dom";
import { noticeElement } from "./notice";
import { enrolView } from "./views-enrol";
import { panelView } from "./views-panels";
import { workView } from "./views-work";

export interface RenderEnv {
  readonly locale: Locale;
  readonly setLocale: (l: Locale) => void;
}

function formatTime(iso: string, locale: Locale): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" }).format(d);
}

function roleLabel(role: string, locale: Locale): string {
  const key = `role.${role}` as MessageKey;
  const label = translate(locale, key);
  // an unknown role shows as itself (as text), never as a missing-key placeholder
  return label === key ? role : label;
}

function sessionFields(s: WhoAmI, locale: Locale): HTMLElement {
  const t = (k: MessageKey, p?: Record<string, string | number>) => translate(locale, k, p);
  const row = (label: string, value: string) => [h("dt", {}, label), h("dd", {}, value)];
  return h(
    "dl",
    { class: "fields", "data-testid": "session-fields" },
    ...row(t("home.field.assurance"), t("home.field.assurance.value", { aal: s.aal, required: s.requiredAal })),
    ...row(t("home.field.signedInAt"), formatTime(s.createdAt, locale)),
    ...row(t("home.field.lastActive"), formatTime(s.lastSeenAt, locale)),
    ...row(t("home.field.idleExpires"), formatTime(s.idleExpiresAt, locale)),
    ...row(t("home.field.expires"), formatTime(s.expiresAt, locale)),
    ...row(t("home.field.admin"), s.isAdmin ? t("common.yes") : t("common.no")),
  );
}

function roles(s: WhoAmI, locale: Locale): HTMLElement {
  const t = (k: MessageKey) => translate(locale, k);
  if (s.memberships.length === 0) return h("p", {}, t("home.roles.none"));
  return h(
    "ul",
    { class: "roles", "data-testid": "roles" },
    ...s.memberships.map((m) =>
      h(
        "li",
        {},
        h("strong", {}, roleLabel(m.role, locale)),
        " ",
        h("span", { class: "muted" }, translate(locale, "home.roles.scope", { facilities: plural(locale, "home.facilities", m.facilityIds.length), trails: plural(locale, "home.trails", m.trailIds.length) })),
      ),
    ),
  );
}

export function render(root: HTMLElement, state: AppState, controller: AppController, env: RenderEnv): void {
  const { locale } = env;
  const t = (k: MessageKey, p?: Record<string, string | number>) => translate(locale, k, p);
  document.documentElement.setAttribute("lang", locale);
  document.title = t("app.name");

  const langButton = h("button", { type: "button", class: "link", lang: locale === "en" ? "fr-CA" : "en", "aria-label": t("lang.toggle.label"), "data-testid": "lang-toggle", onclick: () => env.setLocale(locale === "en" ? "fr-CA" : "en") }, t("lang.toggle"));
  const header = h("header", { class: "bar" }, h("span", { class: "brand" }, t("app.name")), langButton);

  const notice = (n: Parameters<typeof noticeElement>[0]) => noticeElement(n, locale);
  const lockAndSignOut = () => [
    // Lock and Sign-out are NEVER disabled by a busy refresh (a refresh that never answers must not stand between a person and the lock); each takes effect at once
    h("button", { type: "button", "data-testid": "lock", onclick: () => void controller.lock() }, t("home.lock")),
    h("button", { type: "button", class: "danger", "data-testid": "sign-out", onclick: () => void controller.signOut() }, t("home.signOut")),
  ];

  let main: HTMLElement;
  if (state.screen === "signed-in" && state.panel !== null) {
    // a panel replaces the home / work screen; Lock and Sign out stay reachable from it (the forced first PIN has no other way out)
    main = panelView(state.panel, controller, locale);
    main.append(h("div", { class: "actions", "data-testid": "session-actions" }, ...lockAndSignOut()));
  } else if (state.screen === "signed-in" && state.work !== null) {
    main = workView(state, controller, locale);
    main.append(h("div", { class: "actions", "data-testid": "session-actions" }, ...lockAndSignOut()));
  } else if (state.screen === "signed-in") {
    const busy = state.busy !== null;
    const needsSecondFactor = state.session.aal < state.session.requiredAal;
    const firstFacility = state.session.memberships.flatMap((m) => m.facilityIds)[0] ?? "";
    const firstTrail = trailChoices(state.session)[0] ?? "";
    const showAdminOps = canOpenAdminOps(state.session);
    const showReview = canOpenReview(state.session);
    main = h(
      "main",
      { "aria-busy": busy ? "true" : "false", "data-screen": "signed-in" },
      h("h1", { tabindex: "-1", "data-testid": "heading" }, t("home.title")),
      notice(state.notice),
      needsSecondFactor ? h("p", { class: "notice", role: "status", "data-testid": "aal-low" }, t("home.aalLow")) : null,
      h("section", {}, h("h2", {}, t("home.session.title")), sessionFields(state.session, locale)),
      h("section", {}, h("h2", {}, t("home.roles.title")), roles(state.session, locale)),
      h(
        "section",
        {},
        h("h2", {}, t("home.work.title")),
        h("p", { class: "muted" }, t("home.work.hint")),
        h(
          "div",
          { class: "actions" },
          h("button", { type: "button", class: "primary", disabled: busy || needsSecondFactor, "data-testid": "open-attest", onclick: () => controller.openAttest(firstFacility) }, t("home.work.attest")),
          h("button", { type: "button", disabled: busy || needsSecondFactor, "data-testid": "open-course-qr", onclick: () => controller.openCourseQr(firstFacility) }, t("home.work.courseQr")),
          h("button", { type: "button", disabled: busy || needsSecondFactor, "data-testid": "open-handover", onclick: () => controller.openHandover(firstFacility) }, t("home.work.handover")),
          h("button", { type: "button", disabled: busy || needsSecondFactor, "data-testid": "open-stock", onclick: () => controller.openStock(firstFacility) }, t("home.work.stock")),
        ),
      ),
      showAdminOps || showReview
        ? h(
            "section",
            { "data-testid": "home-admin" },
            h("h2", {}, t("home.admin.title")),
            h("p", { class: "muted" }, t("home.admin.hint")),
            h(
              "div",
              { class: "actions" },
              showAdminOps
                ? h("button", { type: "button", disabled: busy || needsSecondFactor, "data-testid": "open-programme", onclick: () => controller.openProgramme(firstTrail) }, t("home.admin.programme"))
                : null,
              showAdminOps
                ? h("button", { type: "button", disabled: busy || needsSecondFactor, "data-testid": "open-offers", onclick: () => controller.openOffers(firstTrail) }, t("home.admin.offers"))
                : null,
              showAdminOps
                ? h("button", { type: "button", disabled: busy || needsSecondFactor, "data-testid": "open-sponsorships", onclick: () => controller.openSponsorships(firstTrail) }, t("home.admin.sponsorships"))
                : null,
              showAdminOps
                ? h("button", { type: "button", disabled: busy || needsSecondFactor, "data-testid": "open-rollups", onclick: () => controller.openRollups(firstTrail) }, t("home.admin.rollups"))
                : null,
              showReview
                ? h("button", { type: "button", disabled: busy || needsSecondFactor, "data-testid": "open-review", onclick: () => controller.openReview() }, t("home.admin.review"))
                : null,
            ),
          )
        : null,
      h(
        "section",
        {},
        h("h2", {}, t("home.pin.title")),
        h("p", { class: "muted" }, t("home.pin.hint")),
        h("div", { class: "actions" }, h("button", { type: "button", disabled: busy, "data-testid": "pin-setup-open", onclick: () => void controller.openPinSetup() }, t("home.pin.button"))),
      ),
      needsSecondFactor
        ? h(
            "section",
            {},
            h("h2", {}, t("home.totp.title")),
            h(
              "div",
              { class: "actions" },
              h("button", { type: "button", class: "primary", disabled: busy, "data-testid": "totp-open", onclick: () => void controller.openTotp("verify") }, t("home.totp.enter")),
              h("button", { type: "button", disabled: busy, "data-testid": "totp-enrol-open", onclick: () => void controller.openTotp("enrol") }, t("home.totp.add")),
            ),
          )
        : null,
      h("div", { class: "actions" }, h("button", { type: "button", disabled: state.busy === "refresh", "data-testid": "refresh", onclick: () => void controller.refresh() }, t("home.refresh")), ...lockAndSignOut()),
      h("p", { class: "muted" }, t("home.lock.hint")),
      h("p", { class: "muted" }, t("home.reloadNote")),
      h("p", { class: "muted" }, t("home.later")),
    );
  } else if (state.screen === "enrol") {
    main = enrolView(state, controller, locale);
  } else if (state.screen === "signing-in") {
    main = h(
      "main",
      { "aria-busy": "true", "data-screen": "signing-in" },
      h("h1", { tabindex: "-1", "data-testid": "heading" }, t("signIn.title")),
      h("p", { role: "status", "data-testid": "busy" }, t("signIn.busy")),
      h("div", { class: "actions" }, h("button", { type: "button", "data-testid": "cancel", onclick: () => controller.cancelSignIn() }, t("signIn.cancel"))),
    );
  } else {
    main = h(
      "main",
      { "data-screen": "signed-out" },
      h("h1", { tabindex: "-1", "data-testid": "heading" }, t("signIn.title")),
      notice(state.notice),
      h("p", {}, t("signIn.lead")),
      h(
        "div",
        { class: "actions" },
        h("button", { type: "button", class: "primary", disabled: state.retryUntilMs !== undefined && Date.now() < state.retryUntilMs, "data-testid": "sign-in", onclick: () => void controller.signIn() }, t("signIn.button")),
        h("button", { type: "button", "data-testid": "have-invite", onclick: () => controller.startEnrol() }, t("signIn.haveInvite")),
      ),
    );
  }

  root.replaceChildren(header, main);
  // the first field of a form takes focus (so a screen-reader or keyboard user can type at once); otherwise the heading does
  const target = main.querySelector<HTMLElement>("[data-autofocus]") ?? main.querySelector<HTMLElement>("h1");
  target?.focus({ preventScroll: true });
}
