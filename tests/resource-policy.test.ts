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
