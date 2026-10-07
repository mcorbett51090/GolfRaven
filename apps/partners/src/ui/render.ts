/**
 * Draws an `AppState`. Plain DOM, `textContent` only (see dom.ts). The whole tree is rebuilt on every state change: it is a few dozen nodes, and a
 * rebuild means no stale node can keep showing data from a session that has ended. After the rebuild the heading takes focus, so a screen-reader
 * user lands on the new screen.
 */

import type { WhoAmI } from "../api/types";
import type { AppState, AppController, Notice } from "../app/controller";
import { translate, plural, type Locale, type MessageKey } from "../i18n";
import { h } from "./dom";

export interface RenderEnv {
  readonly locale: Locale;
  readonly setLocale: (l: Locale) => void;
}

const NOTICE_KEY: Record<Exclude<Notice["kind"], "error">, MessageKey> = {
  locked: "notice.locked",
  "signed-out": "notice.signedOut",
  expired: "notice.expired",
  "sign-out-offline": "notice.signOutOffline",
  "lock-offline": "notice.lockOffline",
};

function noticeText(n: Notice, locale: Locale): string {
  if (n.kind === "error") return translate(locale, n.message.key, n.message.params);
  return translate(locale, NOTICE_KEY[n.kind]);
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

  const notice = (n: Notice | null) => (n === null ? null : h("p", { class: n.kind === "error" ? "notice error" : "notice", role: n.kind === "error" ? "alert" : "status", "data-testid": "notice" }, noticeText(n, locale)));

  let main: HTMLElement;
  let heading: HTMLElement;
  if (state.screen === "signed-in") {
    const busy = state.busy !== null;
    heading = h("h1", { tabindex: "-1", "data-testid": "heading" }, t("home.title"));
    main = h(
      "main",
      { "aria-busy": busy ? "true" : "false", "data-screen": "signed-in" },
      heading,
      notice(state.notice),
      state.session.aal < state.session.requiredAal ? h("p", { class: "notice", role: "status", "data-testid": "aal-low" }, t("home.aalLow")) : null,
      h("section", {}, h("h2", {}, t("home.session.title")), sessionFields(state.session, locale)),
      h("section", {}, h("h2", {}, t("home.roles.title")), roles(state.session, locale)),
      h(
        "div",
        { class: "actions" },
        h("button", { type: "button", disabled: busy, "data-testid": "refresh", onclick: () => void controller.refresh() }, t("home.refresh")),
        h("button", { type: "button", disabled: busy, "data-testid": "lock", onclick: () => void controller.lock() }, t("home.lock")),
        h("button", { type: "button", class: "danger", disabled: busy, "data-testid": "sign-out", onclick: () => void controller.signOut() }, t("home.signOut")),
      ),
      h("p", { class: "muted" }, t("home.lock.hint")),
      h("p", { class: "muted" }, t("home.reloadNote")),
      h("p", { class: "muted" }, t("home.later")),
    );
  } else if (state.screen === "signing-in") {
    heading = h("h1", { tabindex: "-1", "data-testid": "heading" }, t("signIn.title"));
    main = h(
      "main",
      { "aria-busy": "true", "data-screen": "signing-in" },
      heading,
      h("p", { role: "status", "data-testid": "busy" }, t("signIn.busy")),
      h("div", { class: "actions" }, h("button", { type: "button", "data-testid": "cancel", onclick: () => controller.cancelSignIn() }, t("signIn.cancel"))),
    );
  } else {
    heading = h("h1", { tabindex: "-1", "data-testid": "heading" }, t("signIn.title"));
    main = h(
      "main",
      { "data-screen": "signed-out" },
      heading,
      notice(state.notice),
      h("p", {}, t("signIn.lead")),
      h("div", { class: "actions" }, h("button", { type: "button", class: "primary", "data-testid": "sign-in", onclick: () => void controller.signIn() }, t("signIn.button"))),
    );
  }

  root.replaceChildren(header, main);
  heading.focus({ preventScroll: true });
}
