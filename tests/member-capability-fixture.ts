import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { scoped, verifyAudit } from "@accountability/evidence/database";
import type { Database } from "@accountability/evidence/database";
import { MembershipRegistry } from "../src/membership.ts";
import { digest } from "../src/contracts.ts";
import type { Context } from "../src/contracts.ts";
export const c: Context = {
  tenantId: "fiction",
  projectId: "identity",
  actor: { id: "owner", kind: "human", roles: ["owner"] },
  purpose: "private-review",
  requestId: "r",
  now: "2026-01-01T00:00:00Z",
};
export const actor = (
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
export async function fixture(t: test.TestContext) {
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
