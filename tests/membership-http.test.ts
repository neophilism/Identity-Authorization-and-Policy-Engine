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

function block(ms: number) {
  const end = performance.now() + ms;
  while (performance.now() < end) {}
}
function streamed(
  body: ReadableStream<Uint8Array>,
  signal?: AbortSignal,
  extra: Record<string, string> = {},
) {
  return new Request(origin + "/identity/membership/command", {
    method: "POST",
    headers: {
      origin,
      "sec-fetch-site": "same-origin",
      "content-type": "application/json",
      "x-csrf-token": csrf,
      ...extra,
    },
    body,
    duplex: "half",
    ...(signal ? { signal } : {}),
  } as RequestInit);
}

test("slow command bodies are fully captured before current human session resolution, so a committed demotion denies", async (t) => {
  const f = await host(t);
  await f.registry.apply(c, 1, second, "second");
  let release!: () => void,
    entered!: () => void,
    calls = 0;
  const gate = new Promise<void>((r) => {
      release = r;
    }),
    started = new Promise<void>((r) => {
      entered = r;
    });
  const handle = createMembershipHandler(
    f.registry,
    {
      authenticate: async () => {
        calls++;
        return { ...f.session };
      },
    },
    policy,
    () => c.now,
  );
  const pending = handle(
    streamed(
      new ReadableStream(
        {
          async pull(ctrl) {
            entered();
            await gate;
            ctrl.enqueue(
              new TextEncoder().encode(
                JSON.stringify(
                  command("stalled", 2, { ...second, id: "third" }),
                ),
              ),
            );
            ctrl.close();
          },
        },
        { highWaterMark: 0 },
      ),
    ),
  );
  await started;
  assert.equal(calls, 0);
  await f.registry.apply(
    { ...c, actor: { ...c.actor, id: "second" } },
    2,
    { type: "disable-member", id: "owner" },
    "disable",
  );
  release();
  const denied = await pending;
  assert.equal(denied.status, 503);
  assert.equal(calls, 1);
  assert.equal(
    (await f.registry.read({ ...c, actor: { ...c.actor, id: "second" } }))
      .revision,
    3,
  );
  assert.equal((await rows(f)).outbox.length, 3);
});

test("registry rechecks committed demotion after session resolution before both reads and cached mutation acknowledgement", async (t) => {
  const f = await host(t);
  await f.registry.apply(c, 1, second, "second");
  const resolve = f.registry.resolve.bind(f.registry);
  let armed = false,
    hit = false;
  f.registry.resolve = async (...args) => {
    const result = await resolve(...args);
    if (armed) {
      armed = false;
      hit = true;
      await f.registry.apply(
        { ...c, actor: { ...c.actor, id: "second" } },
        result.revision,
        { type: "set-member", id: "owner", kind: "human", roles: ["viewer"] },
        "gap-demotion-" + result.revision,
      );
    }
    return result;
  };
  const handle = createMembershipHandler(
    f.registry,
    f.provider,
    policy,
    () => c.now,
  );
  armed = true;
  const denied = await handle(
    request("/identity/membership/command", command("second", 1)),
  );
  assert.equal(hit, true);
  assert.equal(denied.status, 403);
  assert.deepEqual(await denied.json(), { error: "forbidden" });
  assert.equal((await rows(f)).outbox.length, 3);
  await f.registry.apply(
    { ...c, actor: { ...c.actor, id: "second" } },
    3,
    { type: "set-member", id: "owner", kind: "human", roles: ["owner"] },
    "restore",
  );
  hit = false;
  armed = true;
  const read = await handle(request());
  assert.equal(hit, true);
  assert.equal(read.status, 403);
  assert.deepEqual(await read.json(), { error: "forbidden" });
});

test("HTTP admission bounds actual bytes/chunks/UTF8/blocked reads and cancels hostile streams without waiting for cleanup", async (t) => {
  const f = await host(t, { ...policy, bodyTimeoutMs: 10 });
  let calls = 0;
  const provider = {
    authenticate: async () => {
      calls++;
      return { ...f.session };
    },
  };
  const wire = new TextEncoder().encode(JSON.stringify(command("body", 1)));
  for (const behavior of ["bytes", "chunks", "utf8", "blocked", "hung"]) {
    const handle = createMembershipHandler(
      f.registry,
      provider,
      {
        ...policy,
        bodyTimeoutMs: ["blocked", "hung"].includes(behavior) ? 10 : 5000,
      },
      () => c.now,
    );
    let cancelled = false,
      count = 0;
    const stream = new ReadableStream<Uint8Array>(
      {
        pull(ctrl) {
          if (behavior === "hung") return new Promise(() => {});
          if (behavior === "blocked") block(40);
          if (behavior === "chunks") {
            ctrl.enqueue(new Uint8Array());
            if (++count === 4097) ctrl.close();
            return;
          }
          ctrl.enqueue(
            behavior === "bytes"
              ? new Uint8Array(16385)
              : behavior === "utf8"
                ? new Uint8Array([0xff])
                : wire,
          );
          ctrl.close();
        },
        cancel() {
          cancelled = true;
          return new Promise(() => {});
        },
      },
      { highWaterMark: 0 },
    );
    const response = await handle(
      streamed(
        stream,
        undefined,
        behavior === "bytes" ? { "content-length": "1" } : {},
      ),
    );
    assert.equal(
      response.status,
      behavior === "utf8"
        ? 400
        : ["blocked", "hung"].includes(behavior)
          ? 408
          : 413,
      behavior,
    );
    if (behavior === "hung") assert.equal(cancelled, true);
  }
  assert.equal(calls, 0);
  assert.equal((await f.registry.read(c)).revision, 1);
});

test("provider failures, blocked/hung authentication and cancellation never mutate and close all owned auth signals", async (t) => {
  const f = await host(t);
  for (const behavior of [
    "blocked",
    "hung",
    "throw",
    "forged",
    "null",
    "abort",
    "ok",
  ]) {
    let owned: AbortSignal | undefined, entered!: () => void;
    const started = new Promise<void>((r) => {
        entered = r;
      }),
      controller = new AbortController();
    const handle = createMembershipHandler(
      f.registry,
      {
        authenticate: async (_m, s) => {
          owned = s;
          entered();
          if (behavior === "blocked") block(40);
          if (behavior === "hung" || behavior === "abort")
            return new Promise(() => {});
          if (behavior === "throw") throw Error("private session credential");
          if (behavior === "null") return null;
          return {
            ...f.session,
            ...(behavior === "forged" ? { roles: ["owner"] } : {}),
          };
        },
      },
      { ...policy, authenticationTimeoutMs: behavior === "ok" ? 5000 : 10 },
      () => c.now,
    );
    const pending = handle(
      request("/identity/session", undefined, {}, controller.signal),
    );
    if (behavior === "abort") {
      await started;
      controller.abort();
    }
    const response = await pending;
    assert.equal(
      response.status,
      behavior === "ok"
        ? 200
        : behavior === "null"
          ? 401
          : behavior === "abort"
            ? 408
            : 503,
      behavior,
    );
    assert.equal(owned?.aborted, true);
    assert.equal((await response.text()).includes("credential"), false);
  }
  const controller = new AbortController();
  controller.abort();
  assert.equal(
    (
      await f.handle(
        request(
          "/identity/membership/command",
          command("abort", 1),
          {},
          controller.signal,
        ),
      )
    ).status,
    408,
  );
  assert.equal((await f.registry.read(c)).revision, 1);
});

test("begun mutation SQL is awaited and its committed acknowledgement is retained after cancellation; cancelled reads are withheld", async (t) => {
  const f = await host(t);
  let entered!: () => void,
    release!: () => void,
    hold = false;
  let started = new Promise<void>((r) => {
      entered = r;
    }),
    gate = new Promise<void>((r) => {
      release = r;
    });
  const db = {
    ...f.db,
    transaction: async <T>(fn: Parameters<typeof f.db.transaction<T>>[0]) => {
      const result = await f.db.transaction(fn);
      if (hold) {
        hold = false;
        entered();
        await gate;
      }
      return result;
    },
  };
  const registry = new MembershipRegistry(db, f.policy, () => c.now),
    originalApply = registry.apply.bind(registry),
    originalRead = registry.read.bind(registry);
  registry.apply = async (...args) => {
    hold = true;
    return originalApply(...args);
  };
  registry.read = async (...args) => {
    hold = true;
    return originalRead(...args);
  };
  const handle = createMembershipHandler(
      registry,
      f.provider,
      policy,
      () => c.now,
    ),
    controller = new AbortController();
  let settled = false;
  const pending = handle(
    request(
      "/identity/membership/command",
      command("cancel-late", 1),
      {},
      controller.signal,
    ),
  ).then((r) => {
    settled = true;
    return r;
  });
  await started;
  controller.abort();
  await Promise.resolve();
  assert.equal(settled, false);
  release();
  const committed = await pending;
  assert.equal(committed.status, 200);
  assert.equal((await committed.json()).revision, 2);
  started = new Promise<void>((r) => {
    entered = r;
  });
  gate = new Promise<void>((r) => {
    release = r;
  });
  const readAbort = new AbortController(),
    read = handle(
      request("/identity/membership", undefined, {}, readAbort.signal),
    );
  await started;
  readAbort.abort();
  release();
  assert.equal((await read).status, 408);
  assert.equal((await rows(f)).outbox.length, 2);
});

test("HTTP contenders and command collisions use actual registry revision/idempotency instead of issuing replacement transitions", async (t) => {
  const f = await host(t);
  const result = await Promise.all([
    f.handle(request("/identity/membership/command", command("race-a", 1))),
    f.handle(
      request(
        "/identity/membership/command",
        command("race-b", 1, { ...second, id: "third" }),
      ),
    ),
  ]);
  assert.deepEqual(result.map((r) => r.status).sort(), [200, 409]);
  const winning =
    result[0]!.status === 200
      ? command("race-a", 1)
      : command("race-b", 1, { ...second, id: "third" });
  const replay = await f.handle(
    request("/identity/membership/command", winning),
  );
  assert.equal(replay.status, 200);
  const collision = await f.handle(
    request("/identity/membership/command", {
      ...winning,
      expectedRevision: 2,
    }),
  );
  assert.equal(collision.status, 409);
  assert.deepEqual(await collision.json(), { error: "idempotency_conflict" });
  assert.equal((await f.registry.read(c)).revision, 2);
  assert.equal((await rows(f)).outbox.length, 2);
});

test("HTTP factory captures policy, provider and registry receivers and cannot expose a foreign scope or bootstrap an empty project", async (t) => {
  const f = await host(t),
    configuration = { ...policy },
    provider = {
      marker: "trusted",
      async authenticate() {
        assert.equal(this.marker, "trusted");
        return { ...f.session };
      },
    };
  const handle = createMembershipHandler(
    f.registry,
    provider,
    configuration,
    () => c.now,
  );
  configuration.origin = "https://changed.example";
  configuration.purpose = "changed";
  provider.authenticate = async () => {
    throw Error("replacement");
  };
  const read = f.registry.read;
  f.registry.read = async () => {
    throw Error("replacement");
  };
  assert.equal((await handle(request())).status, 200);
  f.registry.read = read;
  const foreign = new MembershipRegistry(
      f.db,
      { ...f.policy, projectId: "foreign" },
      () => c.now,
    ),
    denied = createMembershipHandler(foreign, f.provider, policy, () => c.now);
  assert.equal((await denied(request())).status, 503);
  const empty = createMembershipHandler(
    new MembershipRegistry(
      f.db,
      { ...f.policy, projectId: "empty" },
      () => c.now,
    ),
    f.provider,
    { ...policy, projectId: "empty" },
    () => c.now,
  );
  assert.equal((await empty(request("/identity/session"))).status, 503);
  assert.equal((await empty(request("/identity/initialize", {}))).status, 404);
  assert.equal((await f.registry.read(c)).revision, 1);
});

test("HTTP post-outbox failure rolls back membership/ack/audit and only later explicit identical replay can commit", async (t) => {
  const f = await host(t);
  let fail = true,
    hit = false;
  const db = {
    ...f.db,
    transaction: <T>(fn: Parameters<typeof f.db.transaction<T>>[0]) =>
      f.db.transaction((q) =>
        fn({
          query: async <R>(sql: string, values?: unknown[]) => {
            const result = await q.query<R>(sql, values);
            if (fail && sql.includes("INSERT INTO public.evidence_outbox")) {
              fail = false;
              hit = true;
              throw Object.assign(Error("private driver failure"), {
                code: "revision_conflict",
              });
            }
            return result;
          },
        }),
      ),
  };
  const registry = new MembershipRegistry(db, f.policy, () => c.now),
    handle = createMembershipHandler(registry, f.provider, policy, () => c.now),
    write = () =>
      request("/identity/membership/command", command("rollback", 1));
  const response = await handle(write());
  assert.equal(hit, true);
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: "operation_unavailable" });
  assert.equal((await f.registry.read(c)).revision, 1);
  assert.equal((await rows(f)).outbox.length, 1);
  assert.equal(
    (await rows(f)).audit.filter(
      (a) => a.type === "identity.membership.changed",
    ).length,
    0,
  );
  assert.equal((await handle(write())).status, 200);
  assert.equal((await rows(f)).outbox.length, 2);
  assert.equal(verifyAudit((await rows(f)).audit), true);
});
