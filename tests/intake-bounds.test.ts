import test from "node:test";
import assert from "node:assert/strict";
import { verifyIntakeService } from "../src/intake-service-adapter.ts";
import type { IntakeServiceMapping } from "../src/intake-service-adapter.ts";
import { DomainError } from "../src/contracts.ts";
import { tokenHash } from "../src/index.ts";
const token = "synthetic_managed_credential_at_least32chars";
const now = "2026-01-01T00:00:00Z";
const mapping: IntakeServiceMapping = {
  tenantId: "fiction",
  projectId: "study",
  connectionId: "intake",
  origin: "https://intake.example",
  credentialFingerprint: tokenHash(token),
  actorId: "service",
  localRoles: ["viewer"],
  requiredScopes: ["case:view"],
  supportedVersions: ["1.0.0-rc.9"],
  epoch: 1,
  enabled: true,
};
const body = {
  data: {
    schemaVersion: 1,
    apiVersion: "v1",
    engine: {
      service: "secure-intake-case-workflow-engine",
      version: "1.0.0-rc.9",
    },
    authentication: {
      scheme: "bearer",
      tenantSource: "api_client",
      grantedScopes: ["case:view"],
    },
  },
};
function gate<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
test("captured trusted mapping cannot drift across credential and response awaits", async () => {
  const supplied = structuredClone(mapping),
    credential = gate<string>(),
    entered = gate<void>();
  const pending = verifyIntakeService(
    supplied,
    async (id, signal) => {
      assert.equal(id, "intake");
      assert.equal(signal.aborted, false);
      entered.resolve();
      return credential.promise;
    },
    now,
    async (url) => {
      assert.equal(url, "https://intake.example/api/v1/capabilities");
      return Response.json(body);
    },
  );
  await entered.promise;
  (supplied as {tenantId: string}).tenantId = "foreign";
  (supplied as {projectId: string}).projectId = "foreign";
  supplied.actorId = "foreign";
  supplied.origin = "https://foreign.example";
  supplied.credentialFingerprint = tokenHash("other");
  supplied.epoch = 9;
  supplied.localRoles = ["operator"];
  supplied.requiredScopes = ["secret"];
  supplied.supportedVersions = ["other"];
  credential.resolve(token);
  const verified = await pending;
  assert.equal(verified.tenantId, mapping.tenantId);
  assert.equal(verified.projectId, mapping.projectId);
  assert.equal(verified.actor.id, "service");
  assert.deepEqual(verified.actor.roles, ["viewer"]);
  assert.equal(verified.actorEpoch, 1);
});
test("one finite deadline includes credential lookup and fences late transport after timeout", async () => {
  let calls = 0,
    signal: AbortSignal | undefined;
  const credential = gate<string>();
  await assert.rejects(
    verifyIntakeService(
      mapping,
      async (_id, s) => {
        signal = s;
        return credential.promise;
      },
      now,
      async () => {
        calls++;
        return Response.json(body);
      },
      { timeoutMs: 10 },
    ),
    { code: "verification_timeout" },
  );
  assert.equal(signal?.aborted, true);
  credential.resolve(token);
  await new Promise((r) => setImmediate(r));
  assert.equal(calls, 0);
});
test("pre-abort and active abort cancel noncooperative transport, discard late bodies and never return identity", async () => {
  const pre = new AbortController();
  pre.abort();
  let calls = 0;
  await assert.rejects(
    verifyIntakeService(
      mapping,
      async () => {
        calls++;
        return token;
      },
      now,
      async () => Response.json(body),
      { signal: pre.signal },
    ),
    { code: "verification_cancelled" },
  );
  assert.equal(calls, 0);
  const external = new AbortController(),
    response = gate<Response>(),
    entered = gate<void>();
  let signal: AbortSignal | undefined,
    cancelled = false;
  const pending = verifyIntakeService(
    mapping,
    async () => token,
    now,
    async (_url, o) => {
      signal = o.signal;
      entered.resolve();
      return response.promise;
    },
    { signal: external.signal, timeoutMs: 1000 },
  );
  await entered.promise;
  external.abort();
  await assert.rejects(pending, { code: "verification_cancelled" });
  assert.equal(signal?.aborted, true);
  response.resolve(
    new Response(
      new ReadableStream({
        cancel() {
          cancelled = true;
        },
      }),
      { headers: { "content-type": "application/json" } },
    ),
  );
  await new Promise((r) => setImmediate(r));
  assert.equal(cancelled, true);
});
test("body stall and nonacknowledging cancellation cannot evade the total deadline", async () => {
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    start(c) {
      c.enqueue(new TextEncoder().encode("{"));
    },
    cancel() {
      cancelled = true;
      return new Promise(() => {});
    },
  });
  await assert.rejects(
    verifyIntakeService(
      mapping,
      async () => token,
      now,
      async () =>
        new Response(stream, {
          headers: { "content-type": "application/json" },
        }),
      { timeoutMs: 10 },
    ),
    { code: "verification_timeout" },
  );
  assert.equal(cancelled, true);
});
test("empty chunk floods and exact byte overflows reject without truncation", async () => {
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    pull(c) {
      c.enqueue(new Uint8Array());
    },
    cancel() {
      cancelled = true;
    },
  });
  await assert.rejects(
    verifyIntakeService(
      mapping,
      async () => token,
      now,
      async () =>
        new Response(stream, {
          headers: { "content-type": "application/json" },
        }),
    ),
    { code: "invalid_capabilities" },
  );
  assert.equal(cancelled, true);
  await assert.rejects(
    verifyIntakeService(
      mapping,
      async () => token,
      now,
      async () =>
        new Response("x".repeat(65537), {
          headers: { "content-type": "application/json" },
        }),
    ),
    { code: "invalid_capabilities" },
  );
});
test("credential transport and stream errors are sanitized even if callbacks throw engine DomainError", async () => {
  const secret = "private callback diagnostics";
  for (const stage of ["credential", "transport", "stream"]) {
    await assert.rejects(
      verifyIntakeService(
        mapping,
        async () => {
          if (stage === "credential") throw new DomainError("private", secret);
          return token;
        },
        now,
        async () => {
          if (stage === "transport") throw new DomainError("private", secret);
          return new Response(
            new ReadableStream({
              start(c) {
                c.error(new DomainError("private", secret));
              },
            }),
            { headers: { "content-type": "application/json" } },
          );
        },
      ),
      (error) => {
        assert.equal(String(error).includes(secret), false);
        assert.notEqual((error as { code: string }).code, "private");
        return true;
      },
    );
  }
});
