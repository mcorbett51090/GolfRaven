// supabase/functions/_shared/partner/offer-eligibility.ts
//
// Re-exports `validateOfferEligibility` (A2-05 / AT(14)) from packages/rules so the Edge handler stays one hop from the SSOT. The relative path is the Deno-friendly form (no package
// root that would pull score-play / matching); vitest resolves `@golfraven/catalog` inside that tree via the `@golfraven/rules` workspace install. Deno maps `@golfraven/catalog` in
// supabase/functions/deno.json.

export { validateOfferEligibility } from "../../../../packages/rules/src/offer-eligibility.ts";
