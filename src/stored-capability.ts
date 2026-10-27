import type { UnitOfWork } from "@accountability/evidence/database";
import { verifyCapability } from "./index.ts";
import type { Action, Capability } from "./index.ts";
import { digest, invariant, nonempty, validTime } from "./contracts.ts";
import type { Context } from "./contracts.ts";
import type { RevocationState } from "./revocations.ts";
// Internal only: caller owns the project lock, principal admission and copied key lifetime.
export async function verifyStoredCapability(
  tx: UnitOfWork,
  c: Context,
  token: string,
  action: Action,
  resourceId: string,
  key: Uint8Array,
  clock: () => string,
): Promise<Capability> {
  const row = await tx.get<RevocationState>(
    "identity-revocations",
    digest({ aggregate: "identity-revocations" }),
  );
  invariant(row, "not_initialized", "Revocations unavailable");
  const state = row.value;
  const now = clock();
  invariant(
    validTime(now) >= validTime(c.now),
    "invalid_time",
    "Trusted clock regressed",
  );
  const cap = verifyCapability(
    token,
    { ...c, now },
    {
      action,
      resourceId,
      policyRevision: state.policyRevision,
      actorEpoch:
        state.actorEpochs.find((a) => a.actorId === c.actor.id)?.epoch ?? 0,
      revokedIds: state.revokedIds,
    },
    key,
  );
  // Signed data is still validated before it leaves this boundary.
  invariant(
    Object.keys(cap).length === 11 &&
      [
        "tenantId",
        "projectId",
        "id",
        "actorId",
        "action",
        "purpose",
        "resourceIds",
        "policyRevision",
        "actorEpoch",
        "notBefore",
        "expiresAt",
      ].every((k) => Object.hasOwn(cap, k)),
    "invalid_capability",
    "Exact capability profile required",
  );
  nonempty(cap.id, "Capability", 128);
  invariant(
    cap.resourceIds.length > 0 &&
      cap.resourceIds.length <= 128 &&
      new Set(cap.resourceIds).size === cap.resourceIds.length &&
      validTime(cap.expiresAt) - validTime(cap.notBefore) > 0 &&
      validTime(cap.expiresAt) - validTime(cap.notBefore) <= 3600000,
    "invalid_capability",
    "Bounded capability profile required",
  );
  for (const id of cap.resourceIds) nonempty(id, "Resource", 128);
  return cap;
}
