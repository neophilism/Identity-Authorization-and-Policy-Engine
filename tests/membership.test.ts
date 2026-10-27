import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { scoped, verifyAudit } from "@accountability/evidence/database";
import type { Database } from "@accountability/evidence/database";
import { MembershipRegistry } from "../src/membership.ts";
import { digest } from "../src/contracts.ts";
import type { Context } from "../src/contracts.ts";
const c: Context = {
  tenantId: "fiction",
  projectId: "identity",
  actor: { id: "owner", kind: "human", roles: ["owner"] },
  purpose: "private-review",
  requestId: "r",
  now: "2026-01-01T00:00:00Z",
};
const actor = (
  id: string,
  kind: "human" | "agent" | "service" = "human",
  roles: string[] = [],
): Context => ({ ...c, actor: { id, kind, roles } });
const second = {
  type: "set-member" as const,
  id: "second",
  kind: "human" as const,
  roles: ["owner" as const],
};
async function fixture(t: test.TestContext) {
  const pg = new PGlite();
  await pg.exec(
    await readFile(
      new URL(
        "../migrations/001_foundation.sql",
        import.meta.resolve("@accountability/evidence/database"),
      ),
      "utf8",
    ),
  );
  await pg.exec(
    "CREATE ROLE identity_login LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION; GRANT evidence_runtime TO identity_login; SET SESSION AUTHORIZATION identity_login",
  );
  const db: Database = {
    transaction: (fn) =>
      pg.transaction((q) =>
        fn({
          query: async <T>(sql: string, v?: unknown[]) => ({
            rows: (await q.query(sql, v)).rows as T[],
          }),
        }),
      ),
    close: () => pg.close(),
  };
  t.after(() => pg.close());
  const policy = {
    tenantId: c.tenantId,
    projectId: c.projectId,
    bootstrapOwnerIds: ["owner"],
  };
  const clock = { now: c.now },
    registry = new MembershipRegistry(db, policy, () => clock.now);
  await registry.initialize(c, "initialize");
  return { db, policy, clock, registry };
}
test("membership persists current roles; injected roles never elevate a principal", async (t) => {
  const f = await fixture(t);
  await f.registry.apply(
    c,
    1,
    { type: "set-member", id: "reader", kind: "human", roles: ["viewer"] },
    "reader",
  );
  const resolved = await new MembershipRegistry(
    f.db,
    f.policy,
    () => c.now,
  ).resolve(actor("reader", "human", ["owner"]), "read");
  assert.equal(resolved.revision, 2);
  assert.equal(resolved.memberEpoch, 1);
  assert.deepEqual(resolved.context.actor.roles, ["viewer"]);
  await assert.rejects(
    f.registry.resolve(actor("reader", "human", ["owner"]), "admin"),
    { code: "forbidden" },
  );
  await assert.rejects(f.registry.read(actor("reader", "human", ["owner"])));
  assert.deepEqual(
    (await f.registry.resolve(actor("owner"), "admin")).context.actor.roles,
    ["owner"],
  );
  await scoped(f.db, c, async (tx) =>
    assert.ok(verifyAudit(await tx.audits())),
  );
});
test("stored owners rotate without bootstrap fallback or cached privilege resurrection", async (t) => {
  const f = await fixture(t);
  await f.registry.apply(c, 1, second, "second");
  const saved = await f.registry.apply(
    actor("second"),
    2,
    { type: "disable-member", id: "owner" },
    "remove-original",
  );
  for (const call of [
    () => f.registry.initialize(c, "initialize"),
    () => f.registry.read(c),
    () => f.registry.apply(c, 1, second, "second"),
    () => f.registry.resolve(c, "read"),
  ])
    await assert.rejects(call(), { code: "member_denied" });
  assert.deepEqual(
    await f.registry.apply(
      actor("second"),
      2,
      { type: "disable-member", id: "owner" },
      "remove-original",
    ),
    saved,
  );
  await assert.rejects(f.registry.initialize(actor("second"), "reset"), {
    code: "already_initialized",
  });
  await f.registry.apply(
    actor("second"),
    3,
    { type: "set-member", id: "owner", kind: "human", roles: ["viewer"] },
    "reenable",
  );
  assert.equal((await f.registry.resolve(c, "read")).memberEpoch, 3);
  await assert.rejects(f.registry.apply(c, 1, second, "second"), {
    code: "forbidden",
  });
});
test("last owner, permanent kind, human authority and scope boundaries fail closed", async (t) => {
  const f = await fixture(t);
  await assert.rejects(
    f.registry.apply(c, 1, { type: "disable-member", id: "owner" }, "last"),
    { code: "last_owner" },
  );
  await assert.rejects(
    f.registry.apply(
      c,
      1,
      { type: "set-member", id: "owner", kind: "human", roles: ["viewer"] },
      "demote",
    ),
    { code: "last_owner" },
  );
  await assert.rejects(
    f.registry.apply(
      c,
      1,
      { type: "set-member", id: "machine", kind: "agent", roles: ["owner"] },
      "bad",
    ),
    { code: "human_authority_required" },
  );
  await f.registry.apply(
    c,
    1,
    { type: "set-member", id: "machine", kind: "service", roles: ["operator"] },
    "service",
  );
  assert.deepEqual(
    (await f.registry.resolve(actor("machine", "service"), "process")).context
      .actor.roles,
    ["operator"],
  );
  await assert.rejects(
    f.registry.resolve(actor("machine", "human", ["owner"]), "read"),
    { code: "member_denied" },
  );
  await assert.rejects(
    f.registry.resolve(actor("owner", "service", ["owner"]), "admin"),
    { code: "member_denied" },
  );
  await f.registry.apply(
    c,
    2,
    { type: "disable-member", id: "machine" },
    "disable",
  );
  await assert.rejects(
    f.registry.apply(
      c,
      3,
      { type: "set-member", id: "machine", kind: "human", roles: ["viewer"] },
      "reuse",
    ),
    { code: "actor_kind_conflict" },
  );
  await assert.rejects(
    f.registry.resolve({ ...c, projectId: "foreign" }, "read"),
    { code: "scope_denied" },
  );
});
test("expected revision commands serialize; historical replay is not current membership", async (t) => {
  const f = await fixture(t);
  const outcomes = await Promise.allSettled([
    f.registry.apply(c, 1, second, "a"),
    f.registry.apply(c, 1, { ...second, id: "third" }, "b"),
  ]);
  assert.equal(outcomes.filter((o) => o.status === "fulfilled").length, 1);
  const winner =
    outcomes[0]!.status === "fulfilled"
      ? ([second, "a"] as const)
      : ([{ ...second, id: "third" }, "b"] as const);
  const old = await f.registry.apply(c, 1, winner[0], winner[1]);
  await f.registry.apply(
    c,
    2,
    { type: "disable-member", id: winner[0].id },
    "disable",
  );
  assert.deepEqual(await f.registry.apply(c, 1, winner[0], winner[1]), old);
  assert.equal((await f.registry.read(c)).revision, 3);
  await assert.rejects(f.registry.resolve(actor(winner[0].id), "read"), {
    code: "member_denied",
  });
  await assert.rejects(
    f.registry.apply({ ...c, purpose: "another" }, 1, winner[0], winner[1]),
    { code: "idempotency_conflict" },
  );
  await scoped(f.db, c, async (tx) =>
    assert.equal(
      (await tx.audits()).filter(
        (a) => a.type === "identity.membership.changed",
      ).length,
      2,
    ),
  );
});
