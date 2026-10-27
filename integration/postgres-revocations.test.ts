import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import {
  postgresDatabase,
  scoped,
  verifyAudit,
} from "@accountability/evidence/database";
import type { Database } from "@accountability/evidence/database";
import { RevocationRegistry } from "../src/revocations.ts";
import type { RevocationState } from "../src/revocations.ts";
import { issueCapability } from "../src/index.ts";
import type { Context } from "../src/contracts.ts";
import { digest } from "../src/contracts.ts";
// Intentionally refuses arbitrary or persistent database targets. CI owns this empty fixture only.
const supplied = process.env.IAP_TEST_ADMIN_URL;
assert.ok(
  process.env.IAP_TEST_DISPOSABLE_POSTGRES === "1" && supplied,
  "Explicit disposable PostgreSQL fixture configuration required",
);
const url = new URL(supplied);
assert.ok(
  ["postgres:", "postgresql:"].includes(url.protocol) &&
    ["localhost", "127.0.0.1"].includes(url.hostname) &&
    url.pathname === "/identity_ci" &&
    url.username === "postgres" &&
    !url.search &&
    !url.hash,
  "Only the designated empty loopback fixture is accepted",
);
const admin = postgresDatabase(url.toString());
before(async () => {
  await admin.transaction(async (q) => {
    assert.equal(
      (
        await q.query<{ fresh: boolean }>(
          "SELECT to_regclass('public.evidence_project') IS NULL AS fresh",
        )
      ).rows[0]!.fresh,
      true,
      "Fixture must be empty; never reset a database here",
    );
    const migration = await readFile(
      new URL(
        "../migrations/001_foundation.sql",
        import.meta.resolve("@accountability/evidence/database"),
      ),
      "utf8",
    );
    assert.equal(migration.match(/^BEGIN;$/gm)?.length, 1);
    assert.equal(migration.match(/^COMMIT;$/gm)?.length, 1);
    // The SDK transaction owns BEGIN/COMMIT; every actual migration statement is unchanged.
    await q.query(migration.replace(/^BEGIN;$/m, "").replace(/^COMMIT;$/m, ""));
    await q.query(
      "CREATE ROLE identity_network_login LOGIN PASSWORD 'fixture-runtime-only' NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION; GRANT evidence_runtime TO identity_network_login",
    );
  });
});
after(() => admin.close());

function gate() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { resolve, promise };
}

async function fixture(t: test.TestContext, id: string) {
  const context: Context = {
    tenantId: "fiction",
    projectId: id,
    actor: { id: "owner", kind: "human", roles: ["owner"] },
    purpose: "review",
    requestId: "fixture",
    now: "2026-01-01T00:00:00Z",
  };
  const reader: Context = {
    ...context,
    actor: { id: "reader", kind: "human", roles: ["viewer"] },
  };
  const policy = {
    tenantId: context.tenantId,
    projectId: id,
    administratorIds: ["owner"],
  };
  const clock = { now: context.now },
    key = randomBytes(32);
  const token = issueCapability(
    context,
    {
      tenantId: context.tenantId,
      projectId: id,
      id: "grant",
      actorId: "reader",
      action: "read",
      purpose: context.purpose,
      resourceIds: ["document"],
      policyRevision: 1,
      actorEpoch: 0,
      notBefore: context.now,
      expiresAt: "2026-01-01T00:01:00Z",
    },
    key,
  );
  const expected = { action: "read" as const, resourceId: "document" };
  function connect(label: string) {
    const u = new URL(url);
    u.username = "identity_network_login";
    u.password = "fixture-runtime-only";
    u.searchParams.set("application_name", id + "-" + label);
    const raw = postgresDatabase(u.toString());
    let closed = false;
    const db: Database = {
      transaction: raw.transaction.bind(raw),
      close: async () => {
        if (!closed) {
          closed = true;
          await raw.close();
        }
      },
    };
    t.after(() => db.close());
    return db;
  }
  const a = connect("a"),
    b = connect("b");
  const pids = await Promise.all(
    [a, b].map((db) =>
      db.transaction((q) =>
        q.query<{ pid: number; login: string }>(
          "SELECT pg_backend_pid() AS pid, session_user AS login",
        ),
      ),
    ),
  );
  assert.notEqual(pids[0]!.rows[0]!.pid, pids[1]!.rows[0]!.pid);
  assert.ok(pids.every((p) => p.rows[0]!.login === "identity_network_login"));
  const sa = new RevocationRegistry(a, policy, () => clock.now),
    sb = new RevocationRegistry(b, policy, () => clock.now);
  await sa.initialize(context, "initialize");
  return {
    context,
    reader,
    policy,
    clock,
    key,
    token,
    expected,
    a,
    b,
    sa,
    sb,
    connect,
    id,
  };
}
test(
  "independent PostgreSQL revocation contenders preserve one revision and one change effect",
  { timeout: 20000 },
  async (t) => {
    const f = await fixture(t, "identity-contenders");
    const r = await Promise.allSettled([
      f.sa.apply(f.context, 1, { type: "advance-policy" }, "a"),
      f.sb.apply(f.context, 1, { type: "revoke-capability", id: "grant" }, "b"),
    ]);
    assert.equal(r.filter((x) => x.status === "fulfilled").length, 1);
    const denied = r.find(
      (x) => x.status === "rejected",
    ) as PromiseRejectedResult;
    assert.equal(denied.reason.code, "revision_conflict");
    assert.equal((await f.sb.read(f.context)).revision, 2);
    await assert.rejects(f.sb.verify(f.reader, f.token, f.expected, f.key), {
      code: "revoked_capability",
    });
    await scoped(f.b, f.context, async (tx) => {
      assert.ok(verifyAudit(await tx.audits()));
      assert.equal(
        (await tx.audits()).filter(
          (x) => x.type === "identity.revocations.changed",
        ).length,
        1,
      );
      const topics: string[] = [];
      for (;;) {
        const e = await tx.claim("fixture-inspector");
        if (!e) break;
        topics.push(e.topic);
        await tx.acknowledge(e);
      }
      assert.equal(
        topics.filter((x) => x === "identity.revocations.changed").length,
        1,
      );
    });
  },
);
for (const mode of ["revocation", "expiry"] as const) {
  test(
    `verification observes ${mode} after a directly observed PostgreSQL lock wait`,
    { timeout: 20000 },
    async (t) => {
      const f = await fixture(t, "identity-lock-" + mode),
        locked = gate(),
        release = gate();
      const hold = scoped(f.a, f.context, async (tx) => {
        await tx.audit("fixture.identity-lock", { fixture: true });
        if (mode === "revocation") {
          const id = digest({ aggregate: "identity-revocations" }),
            row = await tx.get<RevocationState>("identity-revocations", id);
          await tx.put("identity-revocations", id, row!.revision, {
            ...row!.value,
            revokedIds: ["grant"],
          });
        }
        locked.resolve();
        await release.promise;
      });
      let verifying: Promise<unknown> | undefined;
      try {
        await Promise.race([locked.promise, hold]);
        verifying = f.sb.verify(f.reader, f.token, f.expected, f.key);
        const result = verifying.then(
          (value) => ({ value }),
          (error) => ({ error }),
        );
        const deadline = Date.now() + 5000;
        let observed = false;
        while (Date.now() < deadline) {
          const r = await admin.transaction((q) =>
            q.query<{ blocked: boolean }>(
              "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND cardinality(pg_blocking_pids(pid))>0) AS blocked",
              [f.id + "-b"],
            ),
          );
          if (r.rows[0]!.blocked) {
            observed = true;
            break;
          }
          await new Promise((r) => setTimeout(r, 10));
        }
        assert.equal(
          observed,
          true,
          "Must observe real backend blocking before changing clock",
        );
        if (mode === "expiry") f.clock.now = "2026-01-01T00:02:00Z";
        release.resolve();
        await hold;
        const r = await result;
        assert.ok("error" in r);
        assert.equal(
          (r.error as { code: string }).code,
          mode === "expiry" ? "expired_capability" : "revoked_capability",
        );
        await scoped(f.b, f.context, async (tx) =>
          assert.ok(verifyAudit(await tx.audits())),
        );
      } finally {
        release.resolve();
        await hold;
        await verifying?.catch(() => {});
      }
    },
  );
}
test(
  "lost post-COMMIT revocation acknowledgement survives a fresh PostgreSQL pool without replaying effect",
  { timeout: 20000 },
  async (t) => {
    const f = await fixture(t, "identity-lost-ack");
    let lost = false;
    const db: Database = {
      transaction: async (fn) => {
        let changed = false;
        const value = await f.a.transaction((q) =>
          fn({
            query: async <T>(sql: string, v?: unknown[]) => {
              const r = await q.query<T>(sql, v);
              if (
                sql.includes("INSERT INTO public.evidence_outbox") &&
                v?.includes("identity.revocations.changed")
              )
                changed = true;
              return r;
            },
          }),
        );
        if (changed && !lost) {
          lost = true;
          throw Error("fixture lost committed acknowledgement");
        }
        return value;
      },
      close: async () => {},
    };
    const registry = new RevocationRegistry(db, f.policy, () => f.clock.now);
    await assert.rejects(
      registry.apply(
        f.context,
        1,
        { type: "advance-actor", actorId: "reader" },
        "advance",
      ),
    );
    assert.equal(lost, true);
    await f.a.close();
    const fresh = f.connect("fresh"),
      reopened = new RevocationRegistry(fresh, f.policy, () => f.clock.now);
    assert.equal(
      (await reopened.read(f.context)).state.actorEpochs[0]!.epoch,
      1,
    );
    await assert.rejects(
      reopened.verify(f.reader, f.token, f.expected, f.key),
      { code: "revoked_capability" },
    );
    assert.equal(
      (
        await reopened.apply(
          f.context,
          1,
          { type: "advance-actor", actorId: "reader" },
          "advance",
        )
      ).revision,
      2,
    );
    await scoped(fresh, f.context, async (tx) =>
      assert.equal(
        (await tx.audits()).filter(
          (x) => x.type === "identity.revocations.changed",
        ).length,
        1,
      ),
    );
  },
);
test(
  "restricted network roles reject migration administrators and enforce scoped visibility",
  { timeout: 20000 },
  async (t) => {
    const f = await fixture(t, "identity-isolation");
    await assert.rejects(
      new RevocationRegistry(admin, f.policy, () => f.clock.now).read(
        f.context,
      ),
      { code: "unsafe_database_role" },
    );
    const lowered: Database = {
      transaction: (fn) =>
        admin.transaction(async (q) => {
          await q.query("SET LOCAL ROLE evidence_runtime");
          return fn(q);
        }),
      close: async () => {},
    };
    await assert.rejects(
      new RevocationRegistry(lowered, f.policy, () => f.clock.now).read(
        f.context,
      ),
      { code: "unsafe_database_role" },
    );
    await assert.rejects(
      f.b.transaction((q) =>
        q.query("CREATE TABLE public.identity_forbidden(id integer)"),
      ),
    );
    await assert.rejects(f.b.transaction((q) => q.query("SET ROLE postgres")));
    assert.equal(
      (
        await f.b.transaction(async (q) => {
          await q.query("SET LOCAL ROLE evidence_runtime");
          return q.query("SELECT * FROM public.evidence_record");
        })
      ).rows.length,
      0,
    );
    await scoped(f.b, { ...f.context, projectId: "unrelated" }, async (tx) =>
      assert.deepEqual(await tx.list("identity-revocations"), []),
    );
    assert.equal((await f.sb.read(f.context)).revision, 1);
  },
);
