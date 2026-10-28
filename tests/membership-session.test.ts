import test from "node:test";
import assert from "node:assert/strict";
import { MembershipRegistry } from "../src/membership.ts";
import { createMembershipSessionAuthentication } from "../src/membership-session.ts";
import type { HumanSessionProvider } from "../src/membership-session.ts";
import { fixture, c } from "./session-fixture.ts";
const origin = "https://private.example";
const policy = {
  tenantId: c.tenantId,
  projectId: c.projectId,
  purpose: c.purpose,
  action: "admin" as const,
  origin,
};
const metadata = () => ({
  url: origin + "/processing/session",
  method: "GET",
  headers: new Headers({ cookie: "fictional-session" }),
});
const identity = {
  actorId: "owner",
  requestId: "host-request",
  csrfToken: "s".repeat(40),
};
const signal = () => new AbortController().signal;
const unavailable = {
  code: "authentication_unavailable",
  message: "Session unavailable",
};

test("host session resolves current stored owner, never accepts provider roles/scope, and sees demotion on next call", async (t) => {
  const f = await fixture(t);
  const provider = { authenticate: async () => identity };
  const adapter = createMembershipSessionAuthentication(
    f.registry,
    provider,
    policy,
    () => c.now,
  );
  const result = await adapter.authenticate(metadata(), signal());
  assert.deepEqual(result?.context.actor, c.actor);
  assert.equal(result?.context.requestId, "host-request");
  assert.deepEqual(Object.keys(result!).sort(), ["context", "csrfToken"]);
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
  await assert.rejects(adapter.authenticate(metadata(), signal()), unavailable);
  const read = createMembershipSessionAuthentication(
    f.registry,
    provider,
    { ...policy, action: "read" },
    () => c.now,
  );
  assert.deepEqual(
    (await read.authenticate(metadata(), signal()))?.context.actor.roles,
    ["viewer"],
  );
  const forged = createMembershipSessionAuthentication(
    f.registry,
    { authenticate: async () => ({ ...identity, roles: ["owner"] }) },
    policy,
    () => c.now,
  );
  await assert.rejects(forged.authenticate(metadata(), signal()), unavailable);
});

test("provider refusal, wrong human binding and unsafe metadata do not expose stored policy", async (t) => {
  const f = await fixture(t);
  let calls = 0;
  const adapter = createMembershipSessionAuthentication(
    f.registry,
    {
      authenticate: async () => {
        calls++;
        return null;
      },
    },
    policy,
    () => c.now,
  );
  assert.equal(await adapter.authenticate(metadata(), signal()), null);
  for (const m of [
    { ...metadata(), url: "https://foreign.example/x" },
    { ...metadata(), method: "DELETE" },
    { ...metadata(), headers: new Headers({ x: "a".repeat(16385) }) },
  ])
    await assert.rejects(adapter.authenticate(m, signal()), unavailable);
  assert.equal(calls, 1);
  await f.registry.apply(
    c,
    1,
    { type: "set-member", id: "machine", kind: "service", roles: ["viewer"] },
    "machine",
  );
  for (const actorId of ["missing", "machine"]) {
    const bad = createMembershipSessionAuthentication(
      f.registry,
      { authenticate: async () => ({ ...identity, actorId }) },
      { ...policy, action: "read" },
      () => c.now,
    );
    await assert.rejects(bad.authenticate(metadata(), signal()), unavailable);
  }
});

test("captured provider receiver/configuration/metadata and detached results survive caller mutation", async (t) => {
  const f = await fixture(t),
    configuration = { ...policy },
    m = metadata();
  let release!: () => void;
  const ready = new Promise<void>((resolve) => {
    release = resolve;
  });
  let seen = "";
  const provider = {
    marker: "bound",
    async authenticate(meta: ReturnType<typeof metadata>) {
      assert.equal(this.marker, "bound");
      await ready;
      seen = meta.headers.get("cookie")!;
      return { ...identity };
    },
  };
  const adapter = createMembershipSessionAuthentication(
    f.registry,
    provider,
    configuration,
    () => c.now,
  );
  const pending = adapter.authenticate(m, signal());
  configuration.purpose = "mutated";
  m.headers.set("cookie", "changed");
  m.url = "https://foreign.example";
  provider.authenticate = async () => {
    throw Error("replaced");
  };
  release();
  const result = await pending;
  assert.equal(seen, "fictional-session");
  assert.equal(result?.context.purpose, policy.purpose);
  (result!.context.actor.roles as string[]).push("mutated");
  assert.deepEqual(
    (await adapter.authenticate(metadata(), signal()))?.context.actor.roles,
    ["owner"],
  );
});

function block(ms: number) {
  const end = performance.now() + ms;
  while (performance.now() < end) {}
}
test("bounded provider closes signals and sanitizes blocked, hung, throwing and cancelled authentication", async (t) => {
  const f = await fixture(t);
  for (const behavior of ["blocked", "hung", "throw", "ok"]) {
    let owned: AbortSignal | undefined;
    const provider: HumanSessionProvider = {
      authenticate: async (_m, s) => {
        owned = s;
        if (behavior === "blocked") block(35);
        if (behavior === "hung") return new Promise(() => {});
        if (behavior === "throw") throw Error("secret credential");
        return identity;
      },
    };
    const adapter = createMembershipSessionAuthentication(
      f.registry,
      provider,
      { ...policy, timeoutMs: behavior === "ok" ? 5000 : 10 },
      () => c.now,
    );
    if (behavior === "ok")
      assert.ok(await adapter.authenticate(metadata(), signal()));
    else
      await assert.rejects(
        adapter.authenticate(metadata(), signal()),
        unavailable,
      );
    assert.equal(owned?.aborted, true);
  }
  const controller = new AbortController();
  controller.abort();
  let calls = 0;
  const adapter = createMembershipSessionAuthentication(
    f.registry,
    {
      authenticate: async () => {
        calls++;
        return identity;
      },
    },
    policy,
    () => c.now,
  );
  await assert.rejects(
    adapter.authenticate(metadata(), controller.signal),
    unavailable,
  );
  assert.equal(calls, 0);
});

test("begun actual SQL is awaited but its expired snapshot is refused; clock failures are sanitized", async (t) => {
  const f = await fixture(t);
  let observed = false;
  const delayed = {
    transaction: <T>(fn: Parameters<typeof f.db.transaction<T>>[0]) =>
      f.db.transaction((tx) =>
        fn({
          query: async <R>(sql: string, params?: unknown[]) => {
            const result = await tx.query<R>(sql, params);
            if (sql.includes("evidence_record") && sql.includes("SELECT")) {
              observed = true;
              block(35);
            }
            return result;
          },
        }),
      ),
    close: async () => {},
  };
  const registry = new MembershipRegistry(delayed, f.policy, () => c.now);
  const adapter = createMembershipSessionAuthentication(
    registry,
    { authenticate: async () => identity },
    { ...policy, timeoutMs: 10 },
    () => c.now,
  );
  await assert.rejects(adapter.authenticate(metadata(), signal()), unavailable);
  assert.equal(observed, true);
  for (const clock of [
    () => "invalid",
    () => {
      throw Error("private clock");
    },
  ]) {
    const bad = createMembershipSessionAuthentication(
      f.registry,
      { authenticate: async () => identity },
      policy,
      clock,
    );
    await assert.rejects(bad.authenticate(metadata(), signal()), unavailable);
  }
});

test("active cancellation fences late provider results; invalid configuration is refused before authentication", async (t) => {
  const f = await fixture(t);
  for (const bad of [
    { ...policy, origin: "http://private.example" },
    { ...policy, timeoutMs: 0 },
    { ...policy, action: "unknown" },
  ])
    assert.throws(() =>
      createMembershipSessionAuthentication(
        f.registry,
        { authenticate: async () => identity },
        bad as typeof policy,
        () => c.now,
      ),
    );
  let started!: () => void,
    finish!: (v: typeof identity) => void,
    owned: AbortSignal | undefined;
  const ready = new Promise<void>((r) => {
    started = r;
  });
  const adapter = createMembershipSessionAuthentication(
    f.registry,
    {
      authenticate: async (_m, s) => {
        owned = s;
        started();
        return new Promise((r) => {
          finish = r;
        });
      },
    },
    policy,
    () => c.now,
  );
  const controller = new AbortController(),
    result = adapter.authenticate(metadata(), controller.signal);
  await ready;
  controller.abort();
  await assert.rejects(result, unavailable);
  assert.equal(owned?.aborted, true);
  finish(identity);
  await new Promise((r) => setImmediate(r));
  const stored = await f.registry.read(c);
  assert.equal(stored.revision, 1);
});
