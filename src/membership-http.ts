import { timingSafeEqual } from "node:crypto";
import { DomainError, invariant, nonempty } from "./contracts.ts";
import type { Scope } from "./contracts.ts";
import { MembershipRegistry } from "./membership.ts";
import type { MembershipCommand } from "./membership.ts";
import { createMembershipSessionAuthentication } from "./membership-session.ts";
import type { HumanSessionProvider } from "./membership-session.ts";

export type MembershipHttpPolicy = Scope &
  Readonly<{
    origin: string;
    purpose: string;
    authenticationTimeoutMs?: number;
    bodyTimeoutMs?: number;
  }>;
const headers = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "private, no-store",
  pragma: "no-cache",
  vary: "Cookie, Authorization",
  "x-content-type-options": "nosniff",
  "cross-origin-resource-policy": "same-origin",
};
function reply(status: number, value: unknown): Response {
  const body = JSON.stringify(value);
  invariant(
    Buffer.byteLength(body) <= 2097152,
    "response_too_large",
    "Response budget exceeded",
  );
  return new Response(body, { status, headers });
}
function exact(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  invariant(
    value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Object.keys(value).length === keys.length &&
      keys.every((k) => Object.hasOwn(value, k)),
    "invalid_request",
    "Exact JSON fields required",
  );
  return value as Record<string, unknown>;
}
function commandBody(value: unknown): {
  commandId: string;
  expectedRevision: number;
  command: MembershipCommand;
} {
  const input = exact(value, ["commandId", "expectedRevision", "command"]);
  nonempty(input.commandId, "Command", 128);
  invariant(
    Number.isSafeInteger(input.expectedRevision) &&
      (input.expectedRevision as number) > 0,
    "invalid_request",
    "Exact positive membership revision required",
  );
  // The registry independently validates kinds/roles, permanent binding and last-owner rules under lock.
  const command = input.command as MembershipCommand;
  invariant(
    command && ["set-member", "disable-member"].includes(command.type),
    "invalid_request",
    "Known command required",
  );
  exact(
    command,
    command.type === "set-member"
      ? ["type", "id", "kind", "roles"]
      : ["type", "id"],
  );
  nonempty(command.id, "Member", 128);
  if (command.type === "set-member") {
    invariant(
      ["human", "service", "agent"].includes(command.kind) &&
        Array.isArray(command.roles) &&
        command.roles.length > 0 &&
        command.roles.length <= 4 &&
        new Set(command.roles).size === command.roles.length &&
        command.roles.every((r) =>
          ["owner", "viewer", "researcher", "operator"].includes(r),
        ),
      "invalid_request",
      "Known distinct roles/kind required",
    );
  }
  return {
    commandId: input.commandId,
    expectedRevision: input.expectedRevision as number,
    command,
  };
}
const codes: Readonly<Record<string, number>> = {
  authentication_required: 401,
  authentication_unavailable: 503,
  origin_denied: 403,
  csrf_denied: 403,
  member_denied: 403,
  forbidden: 403,
  human_authority_required: 403,
  scope_denied: 403,
  route_not_found: 404,
  method_denied: 405,
  request_aborted: 408,
  body_timeout: 408,
  body_too_large: 413,
  response_too_large: 413,
  unsupported_media: 415,
  invalid_request: 400,
  invalid_input: 400,
  invalid_membership: 400,
  revision_conflict: 409,
  actor_kind_conflict: 409,
  last_owner: 409,
  not_initialized: 409,
  idempotency_conflict: 409,
  registry_full: 409,
  revision_exhausted: 409,
};
async function jsonBody(request: Request, timeoutMs: number): Promise<unknown> {
  invariant(
    /^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(
      request.headers.get("content-type") ?? "",
    ) && [null, "identity"].includes(request.headers.get("content-encoding")),
    "unsupported_media",
    "Uncompressed JSON required",
  );
  const length = request.headers.get("content-length");
  invariant(
    length === null || (/^\d+$/.test(length) && Number(length) <= 16384),
    "body_too_large",
    "Request body exceeds budget",
  );
  invariant(request.body, "invalid_request", "Body required");
  const reader = request.body.getReader(),
    deadline = performance.now() + timeoutMs;
  function gate() {
    invariant(!request.signal.aborted, "request_aborted", "Request cancelled");
    invariant(
      performance.now() < deadline,
      "body_timeout",
      "Body deadline exceeded",
    );
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  let interrupt = () => {};
  const interrupted = new Promise<never>((_, reject) => {
    interrupt = () =>
      reject(new DomainError("request_aborted", "Request cancelled"));
    request.signal.addEventListener("abort", interrupt, { once: true });
    timer = setTimeout(
      () => reject(new DomainError("body_timeout", "Body deadline exceeded")),
      timeoutMs,
    );
  });
  try {
    invariant(!request.signal.aborted, "request_aborted", "Request cancelled");
    const chunks: Uint8Array[] = [];
    let bytes = 0,
      count = 0;
    while (true) {
      gate();
      const part = await Promise.race([reader.read(), interrupted]);
      gate();
      if (part.done) break;
      count++;
      bytes += part.value.byteLength;
      invariant(
        bytes <= 16384 && count <= 4096,
        "body_too_large",
        "Request body exceeds budget",
      );
      chunks.push(new Uint8Array(part.value));
    }
    let parsed: unknown;
    gate();
    try {
      parsed = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)),
      );
    } catch {
      throw new DomainError("invalid_request", "UTF8 JSON required");
    }
    gate();
    return parsed;
  } finally {
    if (timer) clearTimeout(timer);
    request.signal.removeEventListener("abort", interrupt);
    // A hostile stream cancellation callback must not hold the handler open.
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

/** Private Fetch adapter over an already initialized registry; opens no port and issues no credentials. */
export function createMembershipHandler(
  registry: MembershipRegistry,
  provider: HumanSessionProvider,
  configuration: MembershipHttpPolicy,
  clock: () => string,
): (request: Request) => Promise<Response> {
  const policy = structuredClone(configuration),
    read = registry.read.bind(registry),
    apply = registry.apply.bind(registry),
    bodyTimeout = policy.bodyTimeoutMs ?? 5000;
  invariant(
    Number.isSafeInteger(bodyTimeout) &&
      bodyTimeout >= 10 &&
      bodyTimeout <= 30000,
    "invalid_policy",
    "Finite body timeout required",
  );
  const auth = createMembershipSessionAuthentication(
    registry,
    provider,
    {
      tenantId: policy.tenantId,
      projectId: policy.projectId,
      origin: policy.origin,
      purpose: policy.purpose,
      action: "admin",
      timeoutMs: policy.authenticationTimeoutMs ?? 5000,
    },
    clock,
  );
  return async (request) => {
    try {
      const url = new URL(request.url),
        isSession = url.pathname === "/identity/session",
        isRead = url.pathname === "/identity/membership";
      invariant(
        url.origin === policy.origin && !url.username && !url.password,
        "origin_denied",
        "Origin denied",
      );
      invariant(
        isSession || isRead || url.pathname === "/identity/membership/command",
        "route_not_found",
        "Unknown route",
      );
      invariant(
        request.method === (isSession || isRead ? "GET" : "POST"),
        "method_denied",
        "Unsupported method",
      );
      invariant(
        !url.search && !url.hash,
        "invalid_request",
        "Query and fragment forbidden",
      );
      const origin = request.headers.get("origin"),
        site = request.headers.get("sec-fetch-site");
      invariant(
        (origin === null || origin === policy.origin) &&
          (site === null || site === "same-origin") &&
          (isSession || isRead
            ? origin === policy.origin || site === "same-origin"
            : origin === policy.origin),
        "origin_denied",
        "Same origin required",
      );
      // Capture bounded command bytes BEFORE fresh membership-backed authentication, including slow bodies.
      const input =
        isSession || isRead
          ? null
          : commandBody(await jsonBody(request, bodyTimeout));
      invariant(
        !request.signal.aborted,
        "request_aborted",
        "Request cancelled",
      );
      let identity;
      try {
        identity = await auth.authenticate(
          {
            url: request.url,
            method: request.method,
            headers: request.headers,
          },
          request.signal,
        );
      } catch {
        throw new DomainError(
          request.signal.aborted
            ? "request_aborted"
            : "authentication_unavailable",
          "Session unavailable",
        );
      }
      invariant(identity, "authentication_required", "Session required");
      invariant(
        !request.signal.aborted,
        "request_aborted",
        "Request cancelled",
      );
      if (isSession)
        return reply(200, {
          tenantId: policy.tenantId,
          projectId: policy.projectId,
          actorId: identity.context.actor.id,
          csrfToken: identity.csrfToken,
        });
      if (isRead) {
        const result = await read(identity.context);
        invariant(
          !request.signal.aborted,
          "request_aborted",
          "Request cancelled",
        );
        return reply(200, result);
      }
      const csrf = request.headers.get("x-csrf-token") ?? "";
      invariant(
        /^[A-Za-z0-9_-]{32,256}$/.test(csrf) &&
          csrf.length === identity.csrfToken.length &&
          timingSafeEqual(Buffer.from(csrf), Buffer.from(identity.csrfToken)),
        "csrf_denied",
        "Session CSRF required",
      );
      // Registry reloads stored owner authority under the SAME mutation lock before cached command lookup.
      // Await begun SQL; an acknowledged committed mutation remains acknowledged even after cancellation.
      const result = await apply(
        identity.context,
        input!.expectedRevision,
        input!.command,
        input!.commandId,
      );
      return reply(200, result);
    } catch (error) {
      const code =
        error instanceof DomainError && Object.hasOwn(codes, error.code)
          ? error.code
          : "operation_unavailable";
      return reply(codes[code] ?? 503, { error: code });
    }
  };
}
