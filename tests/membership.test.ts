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

test("bootstrap is scoped, human and listed only, and cannot restore disabled owners", async (t) => {
  const f = await fixture(t),
    projectId = "new-project";
  const registry = new MembershipRegistry(
    f.db,
    { ...f.policy, projectId },
    () => c.now,
  );
  for (const bad of [
    actor("unlisted", "human", ["owner"]),
    actor("owner", "service", ["owner"]),
    actor("owner", "human", ["viewer"]),
  ])
    await assert.rejects(
      registry.initialize({ ...bad, projectId }, "bootstrap"),
    );
  await assert.rejects(registry.read({ ...c, projectId }), {
    code: "not_initialized",
  });
  const initialized = await registry.initialize(
    { ...c, projectId },
    "bootstrap",
  );
  assert.equal(initialized.revision, 1);
  assert.equal(initialized.members.length, 1);
  assert.deepEqual(
    await registry.initialize({ ...c, projectId }, "bootstrap"),
    initialized,
  );
  await assert.rejects(registry.initialize({ ...c, projectId }, "reset"), {
    code: "already_initialized",
  });
  await assert.rejects(registry.initialize(c, "cross-scope"), {
    code: "scope_denied",
  });
});
test("lost post-COMMIT acknowledgement survives a fresh facade and does not repeat the change", async (t) => {
  const f = await fixture(t);
  let lost = false;
  const db: Database = {
    transaction: async (fn) => {
      let committed = false;
      const result = await f.db.transaction((q) =>
        fn({
          query: async <T>(sql: string, values?: unknown[]) => {
            const result = await q.query<T>(sql, values);
            if (
              sql.includes("INSERT INTO public.evidence_outbox") &&
              values?.includes("identity.membership.changed")
            )
              committed = true;
            return result;
          },
        }),
      );
      if (committed && !lost) {
        lost = true;
        throw Error("fixture acknowledgement lost");
      }
      return result;
    },
    close: async () => {},
  };
  await assert.rejects(
    new MembershipRegistry(db, f.policy, () => c.now).apply(
      c,
      1,
      second,
      "second",
    ),
  );
  assert.equal(lost, true);
  const reopened = new MembershipRegistry(f.db, f.policy, () => c.now);
  assert.equal((await reopened.read(c)).revision, 2);
  assert.equal((await reopened.apply(c, 1, second, "second")).revision, 2);
  await scoped(f.db, c, async (tx) => {
    assert.equal(
      (await tx.audits()).filter(
        (a) => a.type === "identity.membership.changed",
      ).length,
      1,
    );
    assert.ok(verifyAudit(await tx.audits()));
  });
});
test("failure after membership outbox insertion rolls back policy, audit and cached acknowledgement", async (t) => {
  const f = await fixture(t);
  const before = await f.registry.read(c);
  let injected = false;
  const db: Database = {
    transaction: (fn) =>
      f.db.transaction((q) =>
        fn({
          query: async <T>(sql: string, values?: unknown[]) => {
            const result = await q.query<T>(sql, values);
            if (
              sql.includes("INSERT INTO public.evidence_outbox") &&
              values?.includes("identity.membership.changed")
            ) {
              injected = true;
              throw Error("fixture rollback");
            }
            return result;
          },
        }),
      ),
    close: async () => {},
  };
  await assert.rejects(
    new MembershipRegistry(db, f.policy, () => c.now).apply(
      c,
      1,
      second,
      "second",
    ),
  );
  assert.equal(injected, true);
  assert.deepEqual(await f.registry.read(c), before);
  await scoped(f.db, c, async (tx) =>
    assert.equal(
      (await tx.audits()).filter(
        (a) => a.type === "identity.membership.changed",
      ).length,
      0,
    ),
  );
  assert.equal((await f.registry.apply(c, 1, second, "second")).revision, 2);
});
test("commands, host context and bootstrap configuration are captured before SQL awaits", async (t) => {
  const f = await fixture(t);
  let entered!: () => void, release!: () => void;
  const ready = new Promise<void>((r) => {
      entered = r;
    }),
    wait = new Promise<void>((r) => {
      release = r;
    });
  const db: Database = {
    transaction: (fn) =>
      f.db.transaction((q) =>
        fn({
          query: async <T>(sql: string, values?: unknown[]) => {
            const result = await q.query<T>(sql, values);
            if (sql.includes("FOR UPDATE")) {
              entered();
              await wait;
            }
            return result;
          },
        }),
      ),
    close: async () => {},
  };
  const context = structuredClone(c),
    command = structuredClone(second),
    policy = structuredClone(f.policy);
  const registry = new MembershipRegistry(db, policy, () => c.now);
  const pending = registry.apply(context, 1, command, "captured");
  await ready;
  (context.actor as { id: string }).id = "forged";
  (command as { id: string }).id = "forged";
  command.roles.length = 0;
  policy.bootstrapOwnerIds[0] = "forged";
  release();
  assert.equal((await pending).members[1]!.id, "second");
  const read = await registry.read(c);
  (read.members[1] as unknown as { roles: string[] }).roles.length = 0;
  assert.deepEqual(
    (await f.registry.resolve(actor("second"), "admin")).context.actor.roles,
    ["owner"],
  );
  const newPolicy = {
    ...f.policy,
    projectId: "capture-bootstrap",
    bootstrapOwnerIds: ["owner"],
  };
  const boot = new MembershipRegistry(f.db, newPolicy, () => c.now);
  newPolicy.bootstrapOwnerIds[0] = "different";
  assert.equal(
    (await boot.initialize({ ...c, projectId: "capture-bootstrap" }, "init"))
      .members[0]!.id,
    "owner",
  );
});
test("fresh clock is sampled after actual membership load and regression blocks even cached replies", async (t) => {
  const f = await fixture(t);
  await f.registry.apply(c, 1, second, "second");
  let loaded = false;
  const db: Database = {
    transaction: (fn) =>
      f.db.transaction((q) =>
        fn({
          query: async <T>(sql: string, values?: unknown[]) => {
            const result = await q.query<T>(sql, values);
            if (sql.includes("FROM public.evidence_record")) {
              loaded = true;
              f.clock.now = "2026-01-01T00:01:00Z";
            }
            return result;
          },
        }),
      ),
    close: async () => {},
  };
  const registry = new MembershipRegistry(db, f.policy, () => f.clock.now);
  assert.equal(
    (await registry.resolve(actor("second"), "admin")).context.now,
    "2026-01-01T00:01:00Z",
  );
  assert.equal(loaded, true);
  f.clock.now = "2025-12-31T23:59:59Z";
  await assert.rejects(f.registry.apply(c, 1, second, "second"), {
    code: "invalid_time",
  });
  await assert.rejects(f.registry.initialize(c, "initialize"), {
    code: "invalid_time",
  });
  await assert.rejects(f.registry.read(c), { code: "invalid_time" });
});
test("exact roles/fields, permanent capacity and epoch overflow reject without eviction", async (t) => {
  const f = await fixture(t);
  for (const command of [
    { ...second, roles: ["unknown"] },
    { ...second, roles: ["owner", "owner"] },
    { ...second, roles: [] },
    { ...second, extra: true },
    { type: "disable-member", id: "missing", roles: [] },
    { type: "reset" },
    { ...second, id: "x".repeat(129) },
    { ...second, kind: "robot" },
  ])
    await assert.rejects(f.registry.apply(c, 1, command as never, "malformed"));
  assert.equal((await f.registry.read(c)).revision, 1);
  const key = digest({ aggregate: "identity-membership" });
  const owner = (await f.registry.read(c)).members[0]!;
  await scoped(f.db, c, (tx) =>
    tx.put("identity-membership", key, 1, {
      members: [
        owner,
        ...Array.from({ length: 1023 }, (_, i) => ({
          id: `disabled-${i}`,
          kind: "human",
          roles: ["viewer"],
          disabled: true,
          epoch: 1,
        })),
      ],
    }),
  );
  await assert.rejects(f.registry.apply(c, 2, second, "full"), {
    code: "registry_full",
  });
  assert.equal((await f.registry.read(c)).members.length, 1024);
  await scoped(f.db, c, (tx) =>
    tx.put("identity-membership", key, 2, {
      members: [{ ...owner, epoch: Number.MAX_SAFE_INTEGER }],
    }),
  );
  await assert.rejects(
    f.registry.apply(c, 3, { ...second, id: "owner" }, "overflow"),
    { code: "revision_exhausted" },
  );
  assert.equal((await f.registry.read(c)).revision, 3);
});
