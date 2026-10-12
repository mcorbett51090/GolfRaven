/**
 * Form pieces: a labelled input, and a form whose submit is handled in script (the page's CSP has `form-action 'none'`, and a prevented submit never
 * navigates). Every value is read from the input on submit and the field is emptied at once, so a PIN or a code does not outlive the press.
 */

import { h } from "./dom";

export type FieldKind = "pin" | "code" | "totp" | "token";

export interface Field {
  readonly row: HTMLElement;
  readonly input: HTMLInputElement;
  /** The current value, and the field emptied. */
  take(): string;
}

export function field(opts: { id: string; label: string; kind: FieldKind; autofocus?: boolean; disabled?: boolean }): Field {
  const base = { id: opts.id, class: "text-field", "data-testid": opts.id, required: true, spellcheck: "false" as const, disabled: opts.disabled === true, "data-autofocus": opts.autofocus === true };
  let input: HTMLElement;
  switch (opts.kind) {
    case "pin":
      // masked, numeric keypad, never offered to a password manager as a login
      input = h("input", { ...base, type: "password", inputmode: "numeric", maxlength: 4, pattern: "[0-9]*", autocomplete: "off" });
      break;
    case "code":
      input = h("input", { ...base, type: "text", inputmode: "numeric", maxlength: 10, pattern: "[0-9]*", autocomplete: "one-time-code" });
      break;
    case "totp":
      input = h("input", { ...base, type: "text", inputmode: "numeric", maxlength: 6, pattern: "[0-9]*", autocomplete: "one-time-code" });
      break;
    default:
      input = h("input", { ...base, type: "text", inputmode: "text", autocomplete: "off", autocapitalize: "none" });
  }
  const el = input as HTMLInputElement;
  return {
    row: h("div", { class: "field" }, h("label", { for: opts.id }, opts.label), el),
    input: el,
    take() {
      const v = el.value;
      el.value = "";
      return v;
    },
  };
}

/** A form that calls `onSubmit` on Enter or on its submit button, and never navigates. */
export function form(onSubmit: () => void, testId: string, ...children: Array<Node | null | false>): HTMLElement {
  return h(
    "form",
    {
      novalidate: true,
      "data-testid": testId,
      onsubmit: (ev) => {
        ev.preventDefault();
        onSubmit();
      },
    },
    ...children,
  );
}
