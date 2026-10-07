/**
 * A tiny element builder. Every dynamic string reaches the page through `textContent` (a text node), never through `innerHTML`, `outerHTML`,
 * `insertAdjacentHTML` or `document.write`: a name, a handle or a server string is therefore always inert text (design 4.6 "handles are escaped"),
 * and the page can run under `require-trusted-types-for 'script'`, which refuses every one of those sinks. `test/source-scan.test.ts` keeps the
 * sinks out of the source, and the build scan keeps them out of the bundle.
 */

export type Child = Node | string | null | undefined | false;

export interface Props {
  readonly class?: string;
  readonly id?: string;
  readonly type?: string;
  readonly role?: string;
  readonly lang?: string;
  readonly tabindex?: string;
  readonly hidden?: boolean;
  readonly disabled?: boolean;
  readonly "aria-live"?: "polite" | "assertive";
  readonly "aria-busy"?: "true" | "false";
  readonly "aria-label"?: string;
  readonly "data-testid"?: string;
  readonly "data-screen"?: string;
  readonly onclick?: (ev: MouseEvent) => void;
}

/** Builds `<tag>` with the given attributes and children. Event handlers are attached with `addEventListener`, never as attributes (CSP has no `unsafe-inline`). */
export function h(tag: string, props: Props = {}, ...children: Child[]): HTMLElement {
  const el = document.createElement(tag);
  for (const [name, value] of Object.entries(props)) {
    if (value === undefined || value === false) continue;
    if (name === "onclick") el.addEventListener("click", value as (ev: MouseEvent) => void);
    else if (value === true) el.setAttribute(name, "");
    else el.setAttribute(name, String(value));
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    el.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return el;
}
