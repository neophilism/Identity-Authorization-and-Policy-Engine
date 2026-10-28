import {
  RESOURCE_POLICY_KIND,
  RESOURCE_POLICY_KEY,
  validateResourcePolicy,
  validateResourcePolicies,
} from "./resource-policy.ts";
import type {
  ResourcePolicy,
  ResourcePolicySnapshot,
} from "./resource-policy.ts";
export type {
  ResourcePolicy,
  ResourcePolicySnapshot,
} from "./resource-policy.ts";
import { scoped } from "@accountability/evidence/database";
import type { Database, UnitOfWork } from "@accountability/evidence/database";
import { ACTIONS, authorize } from "./index.ts";
import type { Capability } from "./index.ts";
import { verifyStoredCapability } from "./stored-capability.ts";
import type { Action } from "./index.ts";
import {
  canonical,
  digest,
  invariant,
  nonempty,
  requireScope,
  validTime,
} from "./contracts.ts";
import type { Actor, Context, Json, Scope } from "./contracts.ts";
export const MEMBERSHIP_ROLES = Object.freeze([
  "viewer",
  "researcher",
  "operator",
  "owner",
] as const);
export type MembershipRole = (typeof MEMBERSHIP_ROLES)[number];
export type Member = Readonly<{
  id: string;
  kind: Actor["kind"];
  roles: readonly MembershipRole[];
  disabled: boolean;
  epoch: number;
}>;
export type MembershipSnapshot = Readonly<{
  revision: number;
  members: readonly Member[];
}>;
export type MembershipCommand =
  | Readonly<{
      type: "set-member";
      id: string;
      kind: Actor["kind"];
      roles: readonly MembershipRole[];
    }>
  | Readonly<{ type: "disable-member"; id: string }>;
export type MembershipPolicy = Scope &
  Readonly<{ bootstrapOwnerIds: readonly string[] }>;
const KIND = "identity-membership",
  KEY = digest({ aggregate: KIND });
const json = (value: unknown): Json => JSON.parse(canonical(value));
function exact(value: object, fields: readonly string[]) {
  invariant(
    Object.keys(value).length === fields.length &&
      fields.every((k) => Object.hasOwn(value, k)),
    "invalid_membership",
    "Exact membership fields required",
  );
}
function principal(id: string, kind: Actor["kind"]) {
  nonempty(id, "Actor", 128);
  invariant(
    ["human", "agent", "service"].includes(kind),
    "invalid_membership",
    "Known actor kind required",
  );
}
function roles(value: readonly MembershipRole[], kind: Actor["kind"]) {
  invariant(
    Array.isArray(value) &&
      value.length > 0 &&
      value.length <= MEMBERSHIP_ROLES.length &&
      new Set(value).size === value.length &&
      value.every((r) => MEMBERSHIP_ROLES.includes(r)),
    "invalid_membership",
    "Distinct known roles required",
  );
  invariant(
    !value.includes("owner") || kind === "human",
    "human_authority_required",
    "Only humans can own a project",
  );
}
function increment(n: number) {
  invariant(
    Number.isSafeInteger(n) && n > 0 && n < Number.MAX_SAFE_INTEGER,
    "revision_exhausted",
    "Membership epoch exhausted",
  );
  return n + 1;
}
function validate(members: readonly Member[]) {
  invariant(
    Array.isArray(members) &&
      members.length > 0 &&
      members.length <= 1024 &&
      Buffer.byteLength(canonical(members)) <= 1024 * 1024,
    "registry_full",
    "Bounded membership required",
  );
  const ids = new Set<string>();
  for (const m of members) {
    exact(m, ["id", "kind", "roles", "disabled", "epoch"]);
    principal(m.id, m.kind);
    roles(m.roles, m.kind);
    invariant(
      typeof m.disabled === "boolean" &&
        Number.isSafeInteger(m.epoch) &&
        m.epoch > 0 &&
        !ids.has(m.id),
      "invalid_membership",
      "Distinct permanent actor IDs and valid member epochs required",
    );
    ids.add(m.id);
  }
  invariant(
    members.some(
      (m) => m.kind === "human" && !m.disabled && m.roles.includes("owner"),
    ),
    "last_owner",
    "An active human owner must remain",
  );
}
/** Identity-owned policy storage. The host authenticates principal kind/id; supplied roles are ignored after bootstrap. */
export class MembershipRegistry {
  readonly #db: Database;
  readonly #policy: MembershipPolicy;
  readonly #clock: () => string;
  constructor(db: Database, policy: MembershipPolicy, clock: () => string) {
    this.#db = db;
    this.#policy = structuredClone(policy);
    this.#clock = clock;
    nonempty(policy.tenantId, "Tenant", 128);
    nonempty(policy.projectId, "Project", 128);
    invariant(
      typeof clock === "function" &&
        policy.bootstrapOwnerIds.length > 0 &&
        policy.bootstrapOwnerIds.length <= 128 &&
        new Set(policy.bootstrapOwnerIds).size ===
          policy.bootstrapOwnerIds.length,
      "invalid_policy",
      "Bounded distinct bootstrap owners required",
    );
    for (const id of policy.bootstrapOwnerIds)
      nonempty(id, "Bootstrap owner", 128);
  }
  #context(context: Context) {
    const c = structuredClone(context);
    requireScope(c, this.#policy);
    principal(c.actor.id, c.actor.kind);
    nonempty(c.purpose, "Purpose", 200);
    nonempty(c.requestId, "Request", 128);
    validTime(c.now);
    return c;
  }
  async #load(tx: UnitOfWork): Promise<MembershipSnapshot | null> {
    const r = await tx.get<{ members: Member[] }>(KIND, KEY);
    if (!r) return null;
    exact(r.value, ["members"]);
    validate(r.value.members);
    return { revision: r.revision, members: r.value.members };
  }
  #resolve(c: Context, snapshot: MembershipSnapshot, action: Action): Context {
    const member = snapshot.members.find((m) => m.id === c.actor.id);
    invariant(
      member && member.kind === c.actor.kind && !member.disabled,
      "member_denied",
      "Current active project member required",
    );
    const now = this.#clock();
    invariant(
      validTime(now) >= validTime(c.now),
      "invalid_time",
      "Trusted clock regressed",
    );
    const resolved: Context = {
      ...c,
      now,
      actor: { id: member.id, kind: member.kind, roles: [...member.roles] },
    };
    authorize(resolved, action);
    return resolved;
  }
  async initialize(
    context: Context,
    commandId: string,
  ): Promise<MembershipSnapshot> {
    const c = this.#context(context);
    return scoped(this.#db, c, async (tx) => {
      await tx.audit("identity.membership.initialize.checked", {});
      const existing = await this.#load(tx);
      if (existing) this.#resolve(c, existing, "admin");
      else {
        authorize(c, "admin");
        invariant(
          this.#policy.bootstrapOwnerIds.includes(c.actor.id),
          "bootstrap_denied",
          "Listed trusted human bootstrap owner required",
        );
        invariant(
          validTime(this.#clock()) >= validTime(c.now),
          "invalid_time",
          "Trusted clock regressed",
        );
      }
      return tx.idempotent(
        commandId,
        json({
          operation: "initialize-membership",
          purpose: c.purpose,
          actorKind: c.actor.kind,
        }),
        async () => {
          invariant(
            !existing,
            "already_initialized",
            "Membership cannot be reset",
          );
          const members: Member[] = [
            {
              id: c.actor.id,
              kind: "human",
              roles: ["owner"],
              disabled: false,
              epoch: 1,
            },
          ];
          const saved = await tx.put(KIND, KEY, 0, json({ members }));
          await tx.enqueue(
            "identity.membership.initialized",
            { revision: saved.revision },
            digest({ event: "identity.membership.initialized" }),
          );
          return json({ revision: saved.revision, members });
        },
      );
    }) as Promise<unknown> as Promise<MembershipSnapshot>;
  }
  async read(context: Context): Promise<MembershipSnapshot> {
    const c = this.#context(context);
    return scoped(this.#db, c, async (tx) => {
      await tx.audit("identity.membership.read.checked", {});
      const snapshot = await this.#load(tx);
      invariant(snapshot, "not_initialized", "Membership unavailable");
      this.#resolve(c, snapshot, "admin");
      return snapshot;
    });
  }
  async resolve(
    context: Context,
    action: Action,
  ): Promise<
    Readonly<{ revision: number; memberEpoch: number; context: Context }>
  > {
    const c = this.#context(context);
    invariant(
      ACTIONS.includes(action),
      "invalid_action",
      "Known action required",
    );
    return scoped(this.#db, c, async (tx) => {
      // Same project lock as policy changes, including before the actual policy read.
      await tx.audit("identity.membership.authorize.checked", { action });
      const snapshot = await this.#load(tx);
      invariant(snapshot, "not_initialized", "Membership unavailable");
      const resolved = this.#resolve(c, snapshot, action);
      return {
        revision: snapshot.revision,
        memberEpoch: snapshot.members.find((m) => m.id === c.actor.id)!.epoch,
        context: resolved,
      };
    });
  }
  async #resourcePolicies(tx: UnitOfWork): Promise<ResourcePolicySnapshot> {
    const row = await tx.get<{ policies: ResourcePolicy[] }>(
      RESOURCE_POLICY_KIND,
      RESOURCE_POLICY_KEY,
    );
    if (!row) return { revision: 0, policies: [] };
    validateResourcePolicies(row.value);
    return { revision: row.revision, policies: row.value.policies };
  }
  /** Owner-only inspector; same owning project lock as membership/resource policy mutations. */
  async readResourcePolicies(
    context: Context,
  ): Promise<ResourcePolicySnapshot> {
    const c = this.#context(context);
    return scoped(this.#db, c, async (tx) => {
      await tx.audit("identity.resource-policy.read.checked", {});
      const membership = await this.#load(tx);
      invariant(membership, "not_initialized", "Membership unavailable");
      this.#resolve(c, membership, "admin");
      return this.#resourcePolicies(tx);
    });
  }
  async setResourcePolicy(
    context: Context,
    expectedRevision: number,
    supplied: ResourcePolicy,
    commandId: string,
  ): Promise<ResourcePolicySnapshot> {
    const c = this.#context(context),
      policy = structuredClone(supplied);
    validateResourcePolicy(policy);
    invariant(
      Number.isSafeInteger(expectedRevision) && expectedRevision >= 0,
      "invalid_revision",
      "Exact nonnegative policy registry revision required",
    );
    return scoped(this.#db, c, async (tx) => {
      await tx.audit("identity.resource-policy.command.checked", {
        resourceId: policy.resourceId,
      });
      const membership = await this.#load(tx);
      invariant(membership, "not_initialized", "Membership unavailable");
      this.#resolve(c, membership, "admin");
      return tx.idempotent(
        commandId,
        json({
          operation: "set-resource-policy",
          expectedRevision,
          policy,
          actorKind: c.actor.kind,
          purpose: c.purpose,
        }),
        async () => {
          invariant(
            policy.memberIds.every((id) =>
              membership.members.some((m) => m.id === id),
            ),
            "unknown_member",
            "Registered permanent member IDs required",
          );
          const before = await this.#resourcePolicies(tx);
          invariant(
            before.revision === expectedRevision,
            "revision_conflict",
            "Resource policy registry changed",
          );
          const policies = before.policies
            .filter((p) => p.resourceId !== policy.resourceId)
            .concat(policy)
            .sort((a, b) =>
              a.resourceId < b.resourceId
                ? -1
                : a.resourceId > b.resourceId
                  ? 1
                  : 0,
            );
          validateResourcePolicies({ policies });
          const row = await tx.put(
            RESOURCE_POLICY_KIND,
            RESOURCE_POLICY_KEY,
            expectedRevision,
            { policies },
          );
          await tx.enqueue(
            "identity.resource-policy.changed",
            { revision: row.revision, resourceId: policy.resourceId },
            digest({ kind: RESOURCE_POLICY_KIND, revision: row.revision }),
          );
          return json({ revision: row.revision, policies });
        },
      ) as Promise<unknown> as Promise<ResourcePolicySnapshot>;
    });
  }
  /** Explicit resource restriction AND current stored role authority, never an external permit. */
  async resolveResource(
    context: Context,
    resourceId: string,
    action: Action,
  ): Promise<
    Readonly<{
      membershipRevision: number;
      memberEpoch: number;
      resourcePolicyRevision: number;
      resourceId: string;
      context: Context;
    }>
  > {
    const c = this.#context(context);
    nonempty(resourceId, "Resource", 128);
    invariant(
      ACTIONS.includes(action),
      "invalid_action",
      "Known action required",
    );
    return scoped(this.#db, c, async (tx) => {
      await tx.audit("identity.resource-policy.authorize.checked", {
        resourceId,
        action,
      });
      const membership = await this.#load(tx);
      invariant(membership, "not_initialized", "Membership unavailable");
      const policies = await this.#resourcePolicies(tx);
      const resolved = this.#resolve(c, membership, action); // Clock AFTER both stored reads.
      const policy = policies.policies.find((p) => p.resourceId === resourceId);
      invariant(
        policy &&
          policy.memberIds.includes(c.actor.id) &&
          policy.purposes.includes(c.purpose) &&
          policy.actions.includes(action),
        "resource_denied",
        "Explicit resource policy required",
      );
      return {
        membershipRevision: membership.revision,
        memberEpoch: membership.members.find((m) => m.id === c.actor.id)!.epoch,
        resourcePolicyRevision: policies.revision,
        resourceId,
        context: resolved,
      };
    });
  }
  /** Same-transaction current membership and revocation observation, never an execution permit. */
  async verifyCapability(
    context: Context,
    token: string,
    expected: Readonly<{ action: Action; resourceId: string }>,
    secret: Uint8Array,
  ): Promise<
    Readonly<{
      membershipRevision: number;
      memberEpoch: number;
      capability: Capability;
    }>
  > {
    const c = this.#context(context),
      action = expected.action,
      resourceId = expected.resourceId;
    exact(expected, ["action", "resourceId"]);
    nonempty(resourceId, "Resource", 128);
    invariant(
      ACTIONS.includes(action) &&
        typeof token === "string" &&
        token.length <= 10000 &&
        secret instanceof Uint8Array &&
        secret.byteLength >= 32 &&
        secret.byteLength <= 4096,
      "invalid_capability",
      "Bounded signed capability required",
    );
    const key = Uint8Array.from(secret);
    try {
      return await scoped(this.#db, c, async (tx) => {
        await tx.audit("identity.membership.capability.checked", {
          action,
          resourceId,
        });
        const snapshot = await this.#load(tx);
        invariant(snapshot, "not_initialized", "Membership unavailable");
        const resolved = this.#resolve(c, snapshot, action);
        const capability = await verifyStoredCapability(
          tx,
          resolved,
          token,
          action,
          resourceId,
          key,
          this.#clock,
        );
        return {
          membershipRevision: snapshot.revision,
          memberEpoch: snapshot.members.find((m) => m.id === c.actor.id)!.epoch,
          capability,
        };
      });
    } finally {
      key.fill(0);
    }
  }
  async apply(
    context: Context,
    expectedRevision: number,
    supplied: MembershipCommand,
    commandId: string,
  ): Promise<MembershipSnapshot> {
    const c = this.#context(context),
      command = structuredClone(supplied);
    invariant(
      Number.isSafeInteger(expectedRevision) && expectedRevision > 0,
      "invalid_revision",
      "Exact positive revision required",
    );
    invariant(
      command && ["set-member", "disable-member"].includes(command.type),
      "invalid_command",
      "Known membership command required",
    );
    if (command.type === "set-member") {
      exact(command, ["type", "id", "kind", "roles"]);
      principal(command.id, command.kind);
      roles(command.roles, command.kind);
    } else {
      exact(command, ["type", "id"]);
      nonempty(command.id, "Actor", 128);
    }
    return scoped(this.#db, c, async (tx) => {
      await tx.audit("identity.membership.command.checked", {
        type: command.type,
      });
      const before = await this.#load(tx);
      invariant(before, "not_initialized", "Membership unavailable");
      this.#resolve(c, before, "admin"); // Current stored authority BEFORE cached acknowledgement.
      return tx.idempotent(
        commandId,
        json({
          operation: "change-membership",
          expectedRevision,
          command,
          purpose: c.purpose,
          actorKind: c.actor.kind,
        }),
        async () => {
          invariant(
            before.revision === expectedRevision,
            "revision_conflict",
            "Membership changed",
          );
          const members = structuredClone([...before.members]),
            index = members.findIndex((m) => m.id === command.id),
            old = members[index];
          if (command.type === "set-member") {
            invariant(
              !old || old.kind === command.kind,
              "actor_kind_conflict",
              "An actor ID cannot change kind, including after disablement",
            );
            const member: Member = {
              id: command.id,
              kind: command.kind,
              roles: [...command.roles].sort(),
              disabled: false,
              epoch: old ? increment(old.epoch) : 1,
            };
            if (index < 0) members.push(member);
            else members[index] = member;
          } else {
            invariant(
              old && !old.disabled,
              "member_denied",
              "Active existing member required",
            );
            members[index] = {
              ...old,
              disabled: true,
              epoch: increment(old.epoch),
            };
          }
          validate(members);
          const saved = await tx.put(
            KIND,
            KEY,
            expectedRevision,
            json({ members }),
          );
          await tx.audit(
            "identity.membership.changed",
            json({ revision: saved.revision, command }),
          );
          await tx.enqueue(
            "identity.membership.changed",
            json({ revision: saved.revision, command }),
            digest({ aggregate: KEY, revision: saved.revision }),
          );
          return json({ revision: saved.revision, members });
        },
      );
    }) as Promise<unknown> as Promise<MembershipSnapshot>;
  }
}
