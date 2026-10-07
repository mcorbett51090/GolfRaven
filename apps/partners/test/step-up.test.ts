import { describe, expect, it } from "vitest";
import { StepUpUnavailable, unavailableStepUp } from "../src/auth/step-up";

describe("the step-up seam (PIN prompt and browser derivation arrive with S1.3)", () => {
  it("fails closed for every action class until a real implementation is wired in", async () => {
    for (const cls of ["A1", "A2"] as const) await expect(unavailableStepUp.requirePin(cls)).rejects.toBeInstanceOf(StepUpUnavailable);
  });

  it("the placeholder carries no PIN handling at all: no derivation, no storage, no network", async () => {
    const src = await import("node:fs").then((fs) => fs.readFileSync(new URL("../src/auth/step-up.ts", import.meta.url), "utf8"));
    const code = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    expect(code).not.toMatch(/PBKDF2|crypto\.subtle|deriveBits|fetch\(|localStorage|sessionStorage/);
  });
});
