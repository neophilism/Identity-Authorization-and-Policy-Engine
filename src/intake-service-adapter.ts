import {
  DomainError,
  invariant,
  nonempty,
  validTime,
  digest,
} from "./contracts.ts";
import type { Actor, Scope } from "./contracts.ts";
import { tokenHash } from "./index.ts";

export type IntakeServiceMapping = Scope & {
  connectionId: string;
  origin: string;
  credentialFingerprint: string;
  actorId: string;
  localRoles: readonly ("viewer" | "researcher" | "operator")[];
  requiredScopes: readonly string[];
  supportedVersions: readonly string[];
  epoch: number;
  enabled: boolean;
};
export type VerifiedService = Scope & {
  actor: Actor;
  connectionId: string;
  actorEpoch: number;
  verifiedAt: string;
  upstreamVersion: string;
  upstreamScopeDigest: string;
};
export type CapabilityTransport = (
  url: string,
  options: {
    method: "GET";
    headers: Readonly<Record<string, string>>;
    redirect: "manual";
    signal: AbortSignal;
  },
) => Promise<Response>;
export type IntakeVerificationOptions = Readonly<{
  timeoutMs?: number;
  signal?: AbortSignal;
}>;
function strings(
  value: unknown,
  maxCount: number,
  maxLength: number,
): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= maxCount &&
    value.every(
      (s) => typeof s === "string" && s.length > 0 && s.length <= maxLength,
    )
  );
}
function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function cancel(body: ReadableStream<Uint8Array> | null) {
  // Cancellation may itself never acknowledge. It must not defeat the outer deadline.
  if (body) void body.cancel().catch(() => {});
}
/** Verifies one trusted managed connection. This does not authenticate end users. */
export async function verifyIntakeService(
  supplied: IntakeServiceMapping,
  readManagedCredential: (
    connectionId: string,
    signal: AbortSignal,
  ) => Promise<string>,
  now: string,
  transport: CapabilityTransport = fetch,
  options: IntakeVerificationOptions = {},
): Promise<VerifiedService> {
  const mapping = structuredClone(supplied);
  const timeout = options.timeoutMs ?? 10000;
  const external = options.signal;
  validTime(now);
  invariant(
    Number.isSafeInteger(timeout) && timeout >= 10 && timeout <= 30000,
    "invalid_timeout",
    "Verification deadline must be 10–30000 milliseconds",
  );
  invariant(
    mapping.enabled === true &&
      Number.isSafeInteger(mapping.epoch) &&
      mapping.epoch > 0,
    "connection_disabled",
    "Managed service connection is not enabled",
  );
  for (const [name, value] of Object.entries({
    connection: mapping.connectionId,
    actor: mapping.actorId,
    tenant: mapping.tenantId,
    project: mapping.projectId,
  }))
    nonempty(value, name, 128);
  let url: URL;
  try {
    url = new URL(mapping.origin);
  } catch {
    throw new DomainError(
      "invalid_origin",
      "Use an explicitly configured HTTPS origin",
    );
  }
  invariant(
    url.protocol === "https:" &&
      !url.username &&
      !url.password &&
      url.pathname === "/" &&
      !url.search &&
      !url.hash,
    "invalid_origin",
    "Use an explicitly configured HTTPS origin",
  );
  invariant(
    Array.isArray(mapping.localRoles) &&
      mapping.localRoles.length > 0 &&
      mapping.localRoles.length <= 3 &&
      mapping.localRoles.every((r) =>
        ["viewer", "researcher", "operator"].includes(r),
      ),
    "invalid_mapping",
    "Managed service cannot acquire owner authority",
  );
  invariant(
    typeof mapping.credentialFingerprint === "string" &&
      /^[a-f0-9]{64}$/.test(mapping.credentialFingerprint) &&
      strings(mapping.requiredScopes, 200, 128) &&
      strings(mapping.supportedVersions, 32, 64) &&
      mapping.supportedVersions.length > 0,
    "invalid_mapping",
    "Bounded pinned credential scopes and engine versions required",
  );
  const controller = new AbortController();
  const abort = () => controller.abort();
  external?.addEventListener("abort", abort, { once: true });
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeout);
  let rejectStopped!: (reason: unknown) => void;
  const stopped = new Promise<never>((_resolve, reject) => {
    rejectStopped = reject;
  });
  // Pre-aborted admission can exit before the first race is attached.
  void stopped.catch(() => {});
  const onAbort = () =>
    rejectStopped(
      new DomainError(
        timedOut ? "verification_timeout" : "verification_cancelled",
        timedOut
          ? "Managed service verification timed out"
          : "Managed service verification cancelled",
      ),
    );
  controller.signal.addEventListener("abort", onAbort, { once: true });
  if (external?.aborted) controller.abort();
  function active() {
    if (controller.signal.aborted)
      throw new DomainError(
        timedOut ? "verification_timeout" : "verification_cancelled",
        timedOut
          ? "Managed service verification timed out"
          : "Managed service verification cancelled",
      );
  }
  async function wait<T>(work: Promise<T>): Promise<T> {
    const result = await Promise.race([work, stopped]);
    active();
    return result;
  }
  let response: Response | undefined;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  try {
    active();
    const token = await wait(
      Promise.resolve()
        .then(() => {
          active();
          return readManagedCredential(mapping.connectionId, controller.signal);
        })
        .catch(() => {
          throw new DomainError(
            "verification_unavailable",
            "Managed credential unavailable",
          );
        }),
    );
    invariant(
      typeof token === "string" &&
        token.length >= 32 &&
        token.length <= 512 &&
        !/[\r\n]/.test(token) &&
        tokenHash(token) === mapping.credentialFingerprint,
      "credential_mismatch",
      "Credential does not match the configured connection",
    );
    const pending = Promise.resolve()
      .then(() => {
        active();
        return transport(new URL("/api/v1/capabilities", url).href, {
          method: "GET",
          headers: {
            authorization: "Bearer " + token,
            accept: "application/json",
          },
          redirect: "manual",
          signal: controller.signal,
        });
      })
      .catch(() => {
        throw new DomainError(
          "verification_unavailable",
          "Managed service transport unavailable",
        );
      });
    // A noncooperative transport may return a body after cancellation. Discard it.
    void pending
      .then(
        (r) => {
          if (controller.signal.aborted) cancel(r.body);
        },
        () => {},
      )
      .catch(() => {});
    response = await wait(pending);
    invariant(
      response.status === 200 && !response.redirected,
      "upstream_denied",
      "Upstream service authentication failed",
    );
    invariant(
      response.headers
        .get("content-type")
        ?.split(";")[0]
        ?.trim()
        .toLowerCase() === "application/json" && response.body,
      "invalid_capabilities",
      "JSON capability response body required",
    );
    reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0,
      count = 0;
    for (;;) {
      const r = await wait(
        reader.read().catch(() => {
          throw new DomainError(
            "invalid_capabilities",
            "Capability response read failed",
          );
        }),
      );
      if (r.done) break;
      size += r.value.byteLength;
      invariant(
        ++count <= 4096 && size <= 65536,
        "invalid_capabilities",
        "Capability response exceeds byte or chunk budget",
      );
      chunks.push(Uint8Array.from(r.value));
    }
    let body: unknown;
    try {
      body = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)),
      );
    } catch {
      throw new DomainError(
        "invalid_capabilities",
        "Invalid capability response",
      );
    }
    const data = record(body) && record(body.data) ? body.data : undefined;
    const engine = data && record(data.engine) ? data.engine : undefined;
    const auth =
      data && record(data.authentication) ? data.authentication : undefined;
    invariant(
      data?.schemaVersion === 1 &&
        data.apiVersion === "v1" &&
        engine?.service === "secure-intake-case-workflow-engine" &&
        typeof engine.version === "string" &&
        mapping.supportedVersions.includes(engine.version),
      "incompatible_upstream",
      "Unsupported intake capability contract",
    );
    const scopes = auth?.grantedScopes;
    invariant(
      auth?.scheme === "bearer" &&
        auth.tenantSource === "api_client" &&
        strings(scopes, 200, 128) &&
        mapping.requiredScopes.every((s) => scopes.includes(s)),
      "insufficient_upstream_scope",
      "Managed credential lacks required capabilities",
    );
    active();
    // Upstream discovery omits organization/client IDs; only this captured mapping
    // and its pinned credential establish local scope, actor and non-owner roles.
    return {
      tenantId: mapping.tenantId,
      projectId: mapping.projectId,
      actor: {
        id: mapping.actorId,
        kind: "service",
        roles: [...mapping.localRoles],
      },
      connectionId: mapping.connectionId,
      actorEpoch: mapping.epoch,
      verifiedAt: now,
      upstreamVersion: engine.version,
      upstreamScopeDigest: digest([...scopes].sort()),
    };
  } catch (error) {
    if (error instanceof DomainError) throw error;
    throw new DomainError(
      "verification_unavailable",
      "Managed service verification unavailable",
    );
  } finally {
    clearTimeout(timer);
    external?.removeEventListener("abort", abort);
    controller.signal.removeEventListener("abort", onAbort);
    controller.abort();
    if (reader) {
      void reader.cancel().catch(() => {});
      try {
        reader.releaseLock();
      } catch {
        /* A noncooperative reader cannot extend the deadline. */
      }
    } else if (response) cancel(response.body);
  }
}
