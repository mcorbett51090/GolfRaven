import { afterEach, describe, expect, it } from "vitest";
import {
  browserCameraPorts,
  cameraScanSupported,
  normalizeScannedValue,
  scanCheckinQr,
  stopCameraScan,
  type CameraScanPorts,
  type VideoSink,
} from "../src/ui/camera-scan";

function ports(over: Partial<CameraScanPorts> & Pick<CameraScanPorts, "getUserMedia" | "detect">): CameraScanPorts {
  return {
    now: () => 0,
    delay: async () => undefined,
    ...over,
  };
}

function video(): VideoSink & { srcObject: MediaStream | null } {
  return { srcObject: null };
}

function stream(): MediaStream {
  const track = { stop: () => undefined } as MediaStreamTrack;
  return { getTracks: () => [track] } as MediaStream;
}

afterEach(() => stopCameraScan());

describe("normalizeScannedValue", () => {
  it("trims, takes the first token, and caps length", () => {
    expect(normalizeScannedValue("  abc-123  extra ")).toBe("abc-123");
    expect(normalizeScannedValue("")).toBe("");
    expect(normalizeScannedValue("x".repeat(300)).length).toBe(256);
  });
});

describe("cameraScanSupported", () => {
  it("is false only when ports are absent", () => {
    expect(cameraScanSupported(null)).toBe(false);
    expect(cameraScanSupported(ports({ getUserMedia: async () => stream(), detect: async () => [] }))).toBe(true);
  });
});

describe("browserCameraPorts", () => {
  it("is null in this unit environment (no BarcodeDetector)", () => {
    expect(browserCameraPorts()).toBeNull();
  });
});

describe("scanCheckinQr", () => {
  it("returns unsupported without ports", async () => {
    expect(await scanCheckinQr(video(), null)).toEqual({ ok: false, reason: "unsupported" });
  });

  it("returns denied when getUserMedia refuses", async () => {
    const p = ports({
      getUserMedia: async () => {
        throw new Error("NotAllowedError");
      },
      detect: async () => [],
    });
    expect(await scanCheckinQr(video(), p)).toEqual({ ok: false, reason: "denied" });
  });

  it("returns the first QR rawValue and stops tracks", async () => {
    let stopped = 0;
    const track = { stop: () => {
      stopped += 1;
    } } as MediaStreamTrack;
    const media = { getTracks: () => [track] } as MediaStream;
    const sink = video();
    const p = ports({
      getUserMedia: async () => media,
      detect: async () => [{ rawValue: "  cccccccc-cccc-4ccc-8ccc-cccccccccccc  " }],
    });
    expect(await scanCheckinQr(sink, p)).toEqual({ ok: true, value: "cccccccc-cccc-4ccc-8ccc-cccccccccccc" });
    expect(sink.srcObject).toBeNull();
    expect(stopped).toBe(1);
  });

  it("times out when no barcode appears before the deadline", async () => {
    let now = 0;
    const p = ports({
      getUserMedia: async () => stream(),
      detect: async () => [],
      now: () => now,
      delay: async () => {
        now = 30_000;
      },
    });
    expect(await scanCheckinQr(video(), p, { timeoutMs: 1_000 })).toEqual({ ok: false, reason: "timeout" });
  });

  it("returns aborted when stopCameraScan runs mid-loop", async () => {
    const p = ports({
      getUserMedia: async () => stream(),
      detect: async () => [],
      now: () => 0,
      delay: async () => {
        stopCameraScan();
        throw new DOMException("aborted", "AbortError");
      },
    });
    expect(await scanCheckinQr(video(), p)).toEqual({ ok: false, reason: "aborted" });
  });
});
