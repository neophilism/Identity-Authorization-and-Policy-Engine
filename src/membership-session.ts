import { DomainError, invariant, nonempty, validTime } from "./contracts.ts";
import type { Context, Scope } from "./contracts.ts";
import { ACTIONS } from "./index.ts";
import type { Action } from "./index.ts";
import type { MembershipRegistry } from "./membership.ts";

export type SessionMetadata = Readonly<{
  url: string;
  method: string;
  headers: Headers;
}>;
/** The provider authenticates the human independently; it cannot supply local roles or scope. */
export type HumanSessionProvider = Readonly<{
  authenticate(
    metadata: SessionMetadata,
    signal: AbortSignal,
  ): Promise<Readonly<{
    actorId: string;
    requestId: string;
    csrfToken: string;
  }> | null>;
}>;
export type MembershipSessionPolicy = Scope &
  Readonly<{
    origin: string;
    purpose: string;
    action: Action;
    timeoutMs?: number;
  }>;

/** Current stored role observation for host HTTP adapters; never a transferable action permit. */
export function createMembershipSessionAuthentication(
  registry: MembershipRegistry,
  provider: HumanSessionProvider,
  configuration: MembershipSessionPolicy,
  clock: () => string,
): {
  authenticate(
    metadata: SessionMetadata,
    signal: AbortSignal,
  ): Promise<Readonly<{ context: Context; csrfToken: string }> | null>;
} {
  const policy = structuredClone(configuration),
    resolve = registry.resolve.bind(registry),
    authenticate = provider.authenticate.bind(provider),
    timeout = policy.timeoutMs ?? 5000;
  for (const value of [policy.tenantId, policy.projectId, policy.purpose])
    nonempty(value, "Fixed session policy", 200);
  const origin = new URL(policy.origin);
  invariant(
    origin.protocol === "https:" &&
      origin.origin === policy.origin &&
      !origin.username &&
      !origin.password &&
      ACTIONS.includes(policy.action) &&
      typeof clock === "function" &&
      Number.isSafeInteger(timeout) &&
      timeout >= 10 &&
      timeout <= 30000,
    "invalid_policy",
    "Invalid fixed session policy",
  );
  return {
    async authenticate(metadata, signal) {
      const controller = new AbortController(),
        deadline = performance.now() + timeout;
      const gate = () =>
        invariant(
          !controller.signal.aborted && performance.now() < deadline,
          "authentication_unavailable",
          "Session unavailable",
        );
      const abort = () => controller.abort();
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) abort();
      let interrupt = () => {};
      const interrupted = new Promise<never>((_, reject) => {
        interrupt = () =>
          reject(
            new DomainError(
              "authentication_unavailable",
              "Session unavailable",
            ),
          );
        controller.signal.addEventListener("abort", interrupt, { once: true });
      });
      // Handle pre-abort without leaving an unobserved rejected promise.
      const timer = setTimeout(abort, timeout);
      try {
        gate();
        nonempty(metadata.url, "URL", 2048);
        const url = new URL(metadata.url);
        invariant(
          url.origin === policy.origin &&
            !url.username &&
            !url.password &&
            ["GET", "POST"].includes(metadata.method),
          "authentication_unavailable",
          "Session unavailable",
        );
        const headers = new Headers(metadata.headers);
        let bytes = 0,
          count = 0;
        for (const [key, value] of headers) {
          bytes += Buffer.byteLength(key) + Buffer.byteLength(value);
          count++;
        }
        invariant(
          bytes <= 16384 && count <= 128,
          "authentication_unavailable",
          "Session unavailable",
        );
        const captured = {
          url: metadata.url,
          method: metadata.method,
          headers,
        };
        gate();
        const identity = await Promise.race([
          Promise.resolve()
            .then(() => {
              gate();
              return authenticate(captured, controller.signal);
            })
            .then((value) => {
              gate();
              const copy = structuredClone(value);
              gate();
              return copy;
            }),
          interrupted,
        ]);
        gate();
        if (identity === null) return null;
        invariant(
          identity &&
            typeof identity === "object" &&
            Object.keys(identity).length === 3 &&
            ["actorId", "requestId", "csrfToken"].every((k) =>
              Object.hasOwn(identity, k),
            ),
          "authentication_unavailable",
          "Session unavailable",
        );
        nonempty(identity.actorId, "Human actor", 128);
        nonempty(identity.requestId, "Request", 128);
        invariant(
          typeof identity.csrfToken === "string" &&
            /^[A-Za-z0-9_-]{32,256}$/.test(identity.csrfToken),
          "authentication_unavailable",
          "Session unavailable",
        );
        const now = clock();
        nonempty(now, "Trusted time", 64);
        validTime(now);
        gate();
        const c: Context = {
          tenantId: policy.tenantId,
          projectId: policy.projectId,
          purpose: policy.purpose,
          actor: { id: identity.actorId, kind: "human", roles: [] },
          requestId: identity.requestId,
          now,
        };
        // Begun SQL is awaited, never raced/abandoned. Deadline/cancellation denies its late snapshot.
        const result = await resolve(c, policy.action);
        gate();
        return {
          context: structuredClone(result.context),
          csrfToken: identity.csrfToken,
        };
      } catch {
        throw new DomainError(
          "authentication_unavailable",
          "Session unavailable",
        );
      } finally {
        clearTimeout(timer);
        signal.removeEventListener("abort", abort);
        controller.signal.removeEventListener("abort", interrupt);
        controller.abort();
      }
    },
  };
}
