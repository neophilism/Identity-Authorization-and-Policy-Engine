import test from "node:test";
import assert from "node:assert/strict";
import { scoped, verifyAudit } from "@accountability/evidence/database";
import { MembershipRegistry } from "../src/membership.ts";
import { fixture, c } from "./session-fixture.ts";
const policy = {
  resourceId: "private-file",
  memberIds: ["owner"],
  purposes: [c.purpose],
  actions: ["read" as const],
};
test("owning resource policy denies by default and restricts even owners; exact editions and inspector are detached", async (t) => {
  const f = await fixture(t);
  await assert.rejects(
    f.registry.resolveResource(c, policy.resourceId, "read"),
    { code: "resource_denied" },
  );
  assert.deepEqual(await f.registry.readResourcePolicies(c), {
    revision: 0,
    policies: [],
  });
  const saved = await f.registry.setResourcePolicy(c, 0, policy, "policy");
  assert.equal(saved.revision, 1);
  const observation = await f.registry.resolveResource(
    { ...c, actor: { ...c.actor, roles: [] } },
    policy.resourceId,
    "read",
  );
  assert.equal(observation.membershipRevision, 1);
  assert.equal(observation.resourcePolicyRevision, 1);
  assert.deepEqual(observation.context.actor.roles, ["owner"]);
  await assert.rejects(
    f.registry.resolveResource(c, policy.resourceId, "process"),
    { code: "resource_denied" },
  );
  await assert.rejects(
    f.registry.resolveResource(
      { ...c, purpose: "other" },
      policy.resourceId,
      "read",
    ),
    { code: "resource_denied" },
  );
  (saved.policies[0]!.memberIds as string[]).push("forged");
  assert.deepEqual((await f.registry.readResourcePolicies(c)).policies, [
    policy,
  ]);
  assert(verifyAudit(await scoped(f.db, c, (tx) => tx.audits())));
});
test("current membership disable and demotion deny resource observation and cached policy acknowledgement", async (t) => {
  const f = await fixture(t);
  await f.registry.setResourcePolicy(c, 0, policy, "policy");
  await f.registry.apply(
    c,
    1,
    { type: "set-member", id: "second", kind: "human", roles: ["owner"] },
    "second",
  );
  await f.registry.apply(
    { ...c, actor: { ...c.actor, id: "second" } },
    2,
    { type: "set-member", id: "owner", kind: "human", roles: ["viewer"] },
    "demote",
  );
  await assert.rejects(f.registry.setResourcePolicy(c, 0, policy, "policy"), {
    code: "forbidden",
  });
  assert.equal(
    (await f.registry.resolveResource(c, policy.resourceId, "read"))
      .membershipRevision,
    3,
  );
  await f.registry.apply(
    { ...c, actor: { ...c.actor, id: "second" } },
    3,
    { type: "disable-member", id: "owner" },
    "disable",
  );
  await assert.rejects(
    f.registry.resolveResource(c, policy.resourceId, "read"),
    { code: "member_denied" },
  );
});
test("empty restrictions revoke without deletion; historical replay cannot choose current policy", async (t) => {
  const f = await fixture(t);
  const first = await f.registry.setResourcePolicy(c, 0, policy, "first");
  await f.registry.setResourcePolicy(
    c,
    1,
    { ...policy, memberIds: [] },
    "deny",
  );
  assert.deepEqual(
    await f.registry.setResourcePolicy(c, 0, policy, "first"),
    first,
  );
  await assert.rejects(
    f.registry.resolveResource(c, policy.resourceId, "read"),
    { code: "resource_denied" },
  );
  assert.equal((await f.registry.readResourcePolicies(c)).revision, 2);
  await scoped(f.db, c, async (tx) => {
    const rows = await tx.list("identity-resource-policy");
    assert.equal(rows.length, 1);
    assert.equal(
      (await tx.get("identity-resource-policy", rows[0]!.id, 1))?.revision,
      1,
    );
  });
});

test("policy cannot elevate roles or cross scope/kind and rejects malformed/unknown members", async (t) => {
  const f = await fixture(t);
  await f.registry.apply(
    c,
    1,
    { type: "set-member", id: "reader", kind: "human", roles: ["viewer"] },
    "reader",
  );
  await f.registry.setResourcePolicy(
    c,
    0,
    { ...policy, memberIds: ["reader"], actions: ["read", "process"] },
    "policy",
  );
  const reader = {
    ...c,
    actor: { id: "reader", kind: "human" as const, roles: ["owner"] },
  };
  assert.equal(
    (await f.registry.resolveResource(reader, policy.resourceId, "read"))
      .context.actor.roles[0],
    "viewer",
  );
  await assert.rejects(
    f.registry.resolveResource(reader, policy.resourceId, "process"),
    { code: "forbidden" },
  );
  await assert.rejects(
    f.registry.resolveResource(
      { ...reader, actor: { ...reader.actor, kind: "service" } },
      policy.resourceId,
      "read",
    ),
    { code: "member_denied" },
  );
  await assert.rejects(
    f.registry.resolveResource(
      { ...c, projectId: "foreign" },
      policy.resourceId,
      "read",
    ),
    { code: "scope_denied" },
  );
  for (const bad of [
    { ...policy, memberIds: ["missing"] },
    { ...policy, memberIds: ["owner", "owner"] },
    { ...policy, resourceId: "x".repeat(129) },
    { ...policy, purposes: Array.from({ length: 33 }, (_, i) => String(i)) },
    { ...policy, actions: ["unknown"] },
    { ...policy, extra: true },
  ])
    await assert.rejects(
      f.registry.setResourcePolicy(c, 1, bad as typeof policy, "bad"),
    );
  assert.equal((await f.registry.readResourcePolicies(c)).revision, 1);
});

test("post-COMMIT loss preserves one policy edition and exact replay; concurrent revisions have one winner", async (t) => {
  const f = await fixture(t);
  let lose = true;
  const store = new MembershipRegistry(
    {
      close: async () => {},
      transaction: async (fn) => {
        const value = await f.db.transaction(fn);
        if (lose) {
          lose = false;
          throw Error("lost acknowledgement");
        }
        return value;
      },
    },
    f.policy,
    () => c.now,
  );
  await assert.rejects(
    store.setResourcePolicy(c, 0, policy, "first"),
    /lost acknowledgement/,
  );
  const fresh = new MembershipRegistry(f.db, f.policy, () => c.now);
  assert.equal((await fresh.readResourcePolicies(c)).revision, 1);
  assert.equal(
    (await fresh.setResourcePolicy(c, 0, policy, "first")).revision,
    1,
  );
  const results = await Promise.allSettled([
    fresh.setResourcePolicy(c, 1, { ...policy, memberIds: [] }, "a"),
    fresh.setResourcePolicy(c, 1, { ...policy, actions: [] }, "b"),
  ]);
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  const audits = await scoped(f.db, c, (tx) => tx.audits());
  assert(verifyAudit(audits));
  assert.equal(
    audits.filter(
      (a) =>
        a.type === "record.revised" &&
        (a.payload as { kind?: string }).kind === "identity-resource-policy",
    ).length,
    2,
  );
});

test("post-outbox failure rolls back policy/audit and captured inputs cannot mutate pending writes", async (t) => {
  const f = await fixture(t);
  let fail = true;
  const bad = new MembershipRegistry(
    {
      close: async () => {},
      transaction: (fn) =>
        f.db.transaction((q) =>
          fn({
            query: async <T>(sql: string, v?: unknown[]) => {
              const value = await q.query<T>(sql, v);
              if (fail && sql.includes("INSERT INTO public.evidence_outbox")) {
                fail = false;
                throw Error("after outbox");
              }
              return value;
            },
          }),
        ),
    },
    f.policy,
    () => c.now,
  );
  await assert.rejects(
    bad.setResourcePolicy(c, 0, policy, "bad"),
    /after outbox/,
  );
  assert.deepEqual(await f.registry.readResourcePolicies(c), {
    revision: 0,
    policies: [],
  });
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  const waiting = new MembershipRegistry(
    {
      close: async () => {},
      transaction: async (fn) => {
        await gate;
        return f.db.transaction(fn);
      },
    },
    f.policy,
    () => c.now,
  );
  const input = { ...policy, memberIds: ["owner"] },
    context = structuredClone(c);
  const pending = waiting.setResourcePolicy(context, 0, input, "capture");
  input.memberIds[0] = "missing";
  (context as { purpose: string }).purpose = "changed";
  release();
  assert.deepEqual((await pending).policies, [policy]);
});

test("resource observation samples trusted clock after both actual reads; corrupt policy denies closed", async (t) => {
  const f = await fixture(t);
  await f.registry.setResourcePolicy(c, 0, policy, "policy");
  let now = c.now,
    read = false;
  const hooked = new MembershipRegistry(
    {
      close: async () => {},
      transaction: (fn) =>
        f.db.transaction((q) =>
          fn({
            query: async <T>(sql: string, v?: unknown[]) => {
              const value = await q.query<T>(sql, v);
              if (
                sql.includes("SELECT") &&
                v?.includes("identity-resource-policy")
              ) {
                read = true;
                now = "2026-01-01T00:01:00Z";
              }
              return value;
            },
          }),
        ),
    },
    f.policy,
    () => now,
  );
  assert.equal(
    (await hooked.resolveResource(c, policy.resourceId, "read")).context.now,
    "2026-01-01T00:01:00Z",
  );
  assert(read);
  const { digest } = await import("../src/contracts.ts");
  await scoped(f.db, c, (tx) =>
    tx.put(
      "identity-resource-policy",
      digest({ aggregate: "identity-resource-policy" }),
      1,
      { policies: [{ ...policy, actions: ["unknown"] }] },
    ),
  );
  await assert.rejects(
    f.registry.resolveResource(c, policy.resourceId, "read"),
    { code: "invalid_resource_policy" },
  );
});

test("256 permanent resource slots fail closed without eviction but allow explicit denial at capacity", async (t) => {
  const f = await fixture(t);
  const { digest } = await import("../src/contracts.ts");
  const policies = Array.from({ length: 256 }, (_, i) => ({
    ...policy,
    resourceId: "resource-" + i,
  }));
  await scoped(f.db, c, (tx) =>
    tx.put(
      "identity-resource-policy",
      digest({ aggregate: "identity-resource-policy" }),
      0,
      { policies },
    ),
  );
  await assert.rejects(f.registry.setResourcePolicy(c, 1, policy, "overflow"), {
    code: "invalid_resource_policy",
  });
  assert.equal((await f.registry.readResourcePolicies(c)).policies.length, 256);
  await f.registry.setResourcePolicy(
    c,
    1,
    { ...policies[0]!, memberIds: [] },
    "deny-existing",
  );
  await assert.rejects(f.registry.resolveResource(c, "resource-0", "read"), {
    code: "resource_denied",
  });
  assert.equal((await f.registry.readResourcePolicies(c)).policies.length, 256);
});
