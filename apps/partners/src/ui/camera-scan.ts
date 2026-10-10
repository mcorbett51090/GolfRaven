/**
 * Shop-floor QR scan of a player check-in token (or hand-over token). Ports are injected so unit cells never open a camera.
 * A rebuild of the page (render.ts) calls `stopCameraScan` so tracks cannot outlive the screen.
 */

export type VideoSink = { srcObject: MediaProvider | null; play?: () => Promise<void> };

export type DetectedBarcode = { readonly rawValue: string };

export type CameraScanPorts = {
  getUserMedia: (constraints: MediaStreamConstraints) => Promise<MediaStream>;
  detect: (source: VideoSink) => Promise<readonly DetectedBarcode[]>;
  now: () => number;
  delay: (ms: number, signal: AbortSignal) => Promise<void>;
};

export type ScanFailure = "unsupported" | "denied" | "timeout" | "aborted";
export type ScanResult = { ok: true; value: string } | { ok: false; reason: ScanFailure };

const CONSTRAINTS: MediaStreamConstraints = { video: { facingMode: "environment" }, audio: false };
const POLL_MS = 200;
const DEFAULT_TIMEOUT_MS = 20_000;

let active: { abort: AbortController; stream: MediaStream } | null = null;

export function normalizeScannedValue(raw: string): string {
  const first = raw.trim().split(/\s+/)[0] ?? "";
  return first.slice(0, 256);
}

export function cameraScanSupported(ports: CameraScanPorts | null): boolean {
  return ports !== null;
}

export function stopCameraScan(): void {
  const session = active;
  active = null;
  if (session === null) return;
  session.abort.abort();
  for (const track of session.stream.getTracks()) track.stop();
}

export function browserDelay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new DOMException("aborted", "AbortError"));
      return;
    }
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new DOMException("aborted", "AbortError"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

export function browserCameraPorts(): CameraScanPorts | null {
  const media = typeof navigator !== "undefined" ? navigator.mediaDevices : undefined;
  const Detector = (globalThis as { BarcodeDetector?: new (opts: { formats: string[] }) => { detect: (source: VideoSink) => Promise<readonly DetectedBarcode[]> } }).BarcodeDetector;
  if (media === undefined || typeof media.getUserMedia !== "function" || Detector === undefined) return null;
  const detector = new Detector({ formats: ["qr_code"] });
  return {
    getUserMedia: (c) => media.getUserMedia(c),
    detect: (source) => detector.detect(source),
    now: () => Date.now(),
    delay: browserDelay,
  };
}

export async function scanCheckinQr(video: VideoSink, ports: CameraScanPorts | null, opts?: { timeoutMs?: number }): Promise<ScanResult> {
  if (ports === null) return { ok: false, reason: "unsupported" };
  stopCameraScan();
  const abort = new AbortController();
  let stream: MediaStream;
  try {
    stream = await ports.getUserMedia(CONSTRAINTS);
  } catch {
    return { ok: false, reason: "denied" };
  }
  if (abort.signal.aborted) {
    for (const track of stream.getTracks()) track.stop();
    return { ok: false, reason: "aborted" };
  }
  active = { abort, stream };
  video.srcObject = stream;
  try {
    await video.play?.();
  } catch {
    /* autoplay can refuse; detect() still sees frames on most engines */
  }
  const deadline = ports.now() + (opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  try {
    while (!abort.signal.aborted && ports.now() < deadline) {
      const hits = await ports.detect(video);
      const value = normalizeScannedValue(hits[0]?.rawValue ?? "");
      if (value.length > 0) return { ok: true, value };
      try {
        await ports.delay(POLL_MS, abort.signal);
      } catch {
        return { ok: false, reason: "aborted" };
      }
    }
    if (abort.signal.aborted) return { ok: false, reason: "aborted" };
    return { ok: false, reason: "timeout" };
  } finally {
    video.srcObject = null;
    stopCameraScan();
  }
}
