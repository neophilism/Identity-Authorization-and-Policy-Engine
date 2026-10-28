import test from "node:test";
import assert from "node:assert/strict";
import { scoped, verifyAudit } from "@accountability/evidence/database";
import { MembershipRegistry } from "../src/membership.ts";
import { createMembershipHandler } from "../src/membership-http.ts";
import type { MembershipHttpPolicy } from "../src/membership-http.ts";
import { fixture, c } from "./session-fixture.ts";
const origin = "https://private.example",
  csrf = "s".repeat(40);
const policy: MembershipHttpPolicy = {
  tenantId: c.tenantId,
  projectId: c.projectId,
  origin,
  purpose: c.purpose,
};
const second = {
  type: "set-member" as const,
  id: "second",
  kind: "human" as const,
  roles: ["owner" as const],
};
function request(
  path = "/identity/membership",
  body?: unknown,
  headers: Record<string, string> = {},
  signal?: AbortSignal,
) {
  return new Request(origin + path, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      origin,
      "sec-fetch-site": "same-origin",
      ...(body === undefined
        ? {}
        : { "content-type": "application/json", "x-csrf-token": csrf }),
      ...headers,
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    ...(signal ? { signal } : {}),
  });
}
function command(
  commandId: string,
  expectedRevision: number,
  value: unknown = second,
) {
  return { commandId, expectedRevision, command: value };
}
async function host(
  t: test.TestContext,
  configuration: MembershipHttpPolicy = policy,
) {
  const f = await fixture(t),
    session = { actorId: "owner", requestId: "host-request", csrfToken: csrf };
  const provider = { authenticate: async () => ({ ...session }) };
  return {
    ...f,
    session,
    provider,
    handle: createMembershipHandler(
      f.registry,
      provider,
      configuration,
      () => f.clock.now,
    ),
  };
}
async function rows(f: Awaited<ReturnType<typeof fixture>>) {
  const audit = await scoped(f.db, c, (tx) => tx.audits());
  const outbox = await f.db.transaction(async (q) => {
    await q.query("SET LOCAL ROLE evidence_runtime");
    await q.query(
      "SELECT set_config('evidence.tenant_id',$1,true), set_config('evidence.project_id',$2,true)",
      [c.tenantId, c.projectId],
    );
    return (await q.query("SELECT topic FROM public.evidence_outbox")).rows;
  });
  return { audit, outbox };
}

test("private membership HTTP uses actual stored owners for session/read/set/disable and preserves last owner and immutable history", async (t) => {
  const f = await host(t);
  const session = await f.handle(request("/identity/session"));
  assert.equal(session.status, 200);
  assert.deepEqual(await session.json(), {
    tenantId: c.tenantId,
    projectId: c.projectId,
    actorId: "owner",
    csrfToken: csrf,
  });
  const result = await f.handle(
    request("/identity/membership/command", command("second", 1)),
  );
  assert.equal(result.status, 200);
  const snapshot = await result.json();
  assert.equal(snapshot.revision, 2);
  assert.equal(snapshot.members.length, 2);
  assert.equal(result.headers.get("cache-control"), "private, no-store");
  assert.deepEqual(await (await f.handle(request())).json(), snapshot);
  f.session.actorId = "second";
  assert.equal(
    (
      await f.handle(
        request(
          "/identity/membership/command",
          command("disable", 2, { type: "disable-member", id: "owner" }),
        ),
      )
    ).status,
    200,
  );
  const last = await f.handle(
    request(
      "/identity/membership/command",
      command("last", 3, { type: "disable-member", id: "second" }),
    ),
  );
  assert.equal(last.status, 409);
  assert.deepEqual(await last.json(), { error: "last_owner" });
  assert.equal(
    (await f.registry.read({ ...c, actor: { ...c.actor, id: "second" } }))
      .revision,
    3,
  );
  const records = await rows(f);
  assert.equal(records.outbox.length, 3);
  assert.equal(verifyAudit(records.audit), true);
});

test("cached HTTP mutation acknowledgement requires current stored owner and preserves exact historical command replay", async (t) => {
  const f = await host(t),
    write = () => request("/identity/membership/command", command("second", 1));
  const first = await (await f.handle(write())).json();
  assert.equal((await f.handle(write())).status, 200);
  await f.registry.apply(
    { ...c, actor: { ...c.actor, id: "second" } },
    2,
    { type: "set-member", id: "owner", kind: "human", roles: ["viewer"] },
    "demote",
  );
  const denied = await f.handle(write());
  assert.equal(denied.status, 503);
  assert.deepEqual(await denied.json(), {
    error: "authentication_unavailable",
  });
  assert.equal((await f.handle(request())).status, 503);
  await f.registry.apply(
    { ...c, actor: { ...c.actor, id: "second" } },
    3,
    { type: "set-member", id: "owner", kind: "human", roles: ["owner"] },
    "restore",
  );
  assert.deepEqual(await (await f.handle(write())).json(), first);
  assert.equal((await f.registry.read(c)).revision, 4);
  assert.equal((await rows(f)).outbox.length, 4);
});

test("strict same-origin HTTP routes/CSRF/fields cannot bootstrap, issue credentials or mutate without an exact reviewed revision", async (t) => {
  const f = await host(t);
  for (const [req, status] of [
    [request("/identity/initialize", {}), 404],
    [request("/identity/revocations", {}), 404],
    [request("/identity/membership/command"), 405],
    [request("/identity/membership?x=1"), 400],
    [
      request("/identity/membership/command", command("x", 1), {
        origin: "https://foreign.example",
      }),
      403,
    ],
    [
      request("/identity/membership/command", command("x", 1), {
        "sec-fetch-site": "cross-site",
      }),
      403,
    ],
    [
      request("/identity/membership/command", command("x", 1), {
        "x-csrf-token": "x".repeat(40),
      }),
      403,
    ],
    [
      request("/identity/membership/command", {
        ...command("x", 1),
        roles: ["owner"],
      }),
      400,
    ],
    [request("/identity/membership/command", command("x", 0)), 400],
    [
      request(
        "/identity/membership/command",
        command("x", 1, { ...second, secret: "forbidden" }),
      ),
      400,
    ],
    [
      request(
        "/identity/membership/command",
        command("x", 1, { ...second, roles: ["invented"] }),
      ),
      400,
    ],
    [
      request("/identity/membership/command", command("x", 1), {
        "content-type": "text/plain",
      }),
      415,
    ],
  ] as const) {
    const response = await f.handle(req);
    assert.equal(response.status, status, req.url);
    assert.deepEqual(Object.keys(await response.json()), ["error"]);
  }
  assert.equal((await f.registry.read(c)).revision, 1);
  assert.equal((await rows(f)).outbox.length, 1);
});

test("actual post-COMMIT lost HTTP acknowledgement is unknown, and explicit identical replay never repeats the mutation", async (t) => {
  const f = await host(t);
  let lose = false;
  const db = {
    ...f.db,
    transaction: async <T>(fn: Parameters<typeof f.db.transaction<T>>[0]) => {
      const result = await f.db.transaction(fn);
      if (lose) {
        lose = false;
        throw Error("private driver secret");
      }
      return result;
    },
  };
  const registry = new MembershipRegistry(db, f.policy, () => f.clock.now),
    apply = registry.apply.bind(registry);
  registry.apply = async (...args) => {
    lose = true;
    return apply(...args);
  };
  const handle = createMembershipHandler(
      registry,
      f.provider,
      policy,
      () => f.clock.now,
    ),
    write = () => request("/identity/membership/command", command("lost", 1));
  const unknown = await handle(write());
  assert.equal(unknown.status, 503);
  assert.deepEqual(await unknown.json(), { error: "operation_unavailable" });
  assert.equal((await f.registry.read(c)).revision, 2);
  registry.apply = apply; // Factory captured receiver remains, so use a fresh host after the simulated connection loss.
  const reopened = createMembershipHandler(
    new MembershipRegistry(f.db, f.policy, () => f.clock.now),
    f.provider,
    policy,
    () => f.clock.now,
  );
  const replay = await reopened(write());
  assert.equal(replay.status, 200);
  assert.equal((await replay.json()).revision, 2);
  assert.equal((await rows(f)).outbox.length, 2);
  assert.equal(verifyAudit((await rows(f)).audit), true);
});
