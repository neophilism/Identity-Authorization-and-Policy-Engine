import { ACTIONS } from "./index.ts";
import type { Action } from "./index.ts";
import { canonical, digest, invariant, nonempty } from "./contracts.ts";
export type ResourcePolicy = Readonly<{
  resourceId: string;
  memberIds: readonly string[];
  purposes: readonly string[];
  actions: readonly Action[];
}>;
export type ResourcePolicySnapshot = Readonly<{
  revision: number;
  policies: readonly ResourcePolicy[];
}>;
export const RESOURCE_POLICY_KIND = "identity-resource-policy";
export const RESOURCE_POLICY_KEY = digest({ aggregate: RESOURCE_POLICY_KIND });
export function validateResourcePolicy(policy: ResourcePolicy) {
  invariant(
    policy &&
      Object.getPrototypeOf(policy) === Object.prototype &&
      Object.keys(policy).length === 4 &&
      ["resourceId", "memberIds", "purposes", "actions"].every((k) =>
        Object.hasOwn(policy, k),
      ),
    "invalid_resource_policy",
    "Exact resource policy required",
  );
  nonempty(policy.resourceId, "Resource", 128);
  for (const [values, max, length] of [
    [policy.memberIds, 64, 128],
    [policy.purposes, 32, 200],
    [policy.actions, ACTIONS.length, 128],
  ] as const) {
    invariant(
      Array.isArray(values) &&
        values.length <= max &&
        new Set(values).size === values.length,
      "invalid_resource_policy",
      "Bounded distinct policy values required",
    );
    for (const value of values) nonempty(value, "Policy value", length);
  }
  invariant(
    policy.actions.every((a) => ACTIONS.includes(a)),
    "invalid_resource_policy",
    "Known actions required",
  );
}
export function validateResourcePolicies(value: {
  policies: ResourcePolicy[];
}) {
  invariant(
    value &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Object.keys(value).length === 1 &&
      Object.hasOwn(value, "policies") &&
      Array.isArray(value.policies) &&
      value.policies.length <= 256,
    "invalid_resource_policy",
    "Bounded resource policy registry required",
  );
  const ids = new Set<string>();
  for (const p of value.policies) {
    validateResourcePolicy(p);
    invariant(
      !ids.has(p.resourceId),
      "invalid_resource_policy",
      "Distinct resources required",
    );
    ids.add(p.resourceId);
  }
  invariant(
    Buffer.byteLength(canonical(value)) <= 1024 * 1024,
    "registry_full",
    "Resource policies exceed byte budget",
  );
}
