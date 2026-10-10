/**
 * A paste field plus an optional camera QR scan that writes the value into the input. The token is never copied into status text.
 */

import type { MessageKey } from "../i18n";
import { browserCameraPorts, scanCheckinQr, stopCameraScan, type CameraScanPorts } from "./camera-scan";
import { h } from "./dom";

export function tokenScanField(opts: {
  name: string;
  label: string;
  testid: string;
  busy: boolean;
  autofocus?: boolean;
  t: (k: MessageKey) => string;
  ports?: CameraScanPorts | null;
}): HTMLElement {
  const ports = opts.ports === undefined ? browserCameraPorts() : opts.ports;
  const input = h("input", {
    name: opts.name,
    type: "text",
    autocomplete: "off",
    spellcheck: "false",
    required: true,
    ...(opts.autofocus === true ? { "data-autofocus": true } : {}),
    "data-testid": opts.testid,
    disabled: opts.busy,
  });
  const video = h("video", {
    class: "scan-preview",
    muted: true,
    autoplay: true,
    playsinline: true,
    hidden: true,
    "aria-label": opts.t("scan.preview"),
    "data-testid": `${opts.testid}-preview`,
  }) as HTMLVideoElement;
  const status = h("p", { class: "muted", role: "status", "data-testid": `${opts.testid}-scan-status` });
  const setStatus = (key: MessageKey | null) => {
    status.replaceChildren(key === null ? "" : opts.t(key));
  };
  const stopBtn = h(
    "button",
    {
      type: "button",
      hidden: true,
      disabled: opts.busy,
      "data-testid": `${opts.testid}-scan-stop`,
      onclick: () => {
        video.hidden = true;
        stopBtn.hidden = true;
        scanBtn.hidden = false;
        setStatus(null);
        stopCameraScan();
      },
    },
    opts.t("scan.stop"),
  );
  const scanBtn = h(
    "button",
    {
      type: "button",
      disabled: opts.busy,
      "data-testid": `${opts.testid}-scan`,
      onclick: () => {
        if (ports === null) {
          setStatus("scan.unsupported");
          return;
        }
        setStatus(null);
        video.hidden = false;
        scanBtn.hidden = true;
        stopBtn.hidden = false;
        void scanCheckinQr(video, ports).then((result) => {
          video.hidden = true;
          stopBtn.hidden = true;
          scanBtn.hidden = false;
          if (result.ok) {
            (input as HTMLInputElement).value = result.value;
            setStatus(null);
            return;
          }
          if (result.reason === "aborted") {
            setStatus(null);
            return;
          }
          setStatus(result.reason === "denied" ? "scan.denied" : result.reason === "timeout" ? "scan.timeout" : "scan.unsupported");
        });
      },
    },
    opts.t("scan.button"),
  );
  return h(
    "div",
    { class: "scan-field" },
    h("label", { class: "field" }, h("span", {}, opts.label), input),
    h("div", { class: "actions" }, scanBtn, stopBtn),
    video,
    status,
  );
}
