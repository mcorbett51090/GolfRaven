// Clean fixture: the service-role client is never constructed here; the
// only privileged call happens inside a withOwnership() callback, using
// the repository object the callback receives — never a raw client.
import { withOwnership, type Actor } from "../_shared/privileged.ts";

interface EvidenceRepo {
  insertForActor(actor: Actor, evidence: unknown): Promise<{ id: string }>;
}

export async function handleEvidence(actor: Actor, body: unknown) {
  return withOwnership(actor, async (repo) => {
    const evidenceRepo = repo as EvidenceRepo;
    return evidenceRepo.insertForActor(actor, body);
  });
}
