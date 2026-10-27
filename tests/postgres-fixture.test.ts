import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
test("PostgreSQL fixture refuses unapproved, absent, remote and query-bearing targets before connecting", () => {
  for (const [flag, url] of [
    ["", "postgresql://postgres:fixture@127.0.0.1:5432/identity_ci"],
    ["1", ""],
    ["1", "postgresql://postgres:fixture@example.invalid/identity_ci"],
    [
      "1",
      "postgresql://postgres:fixture@127.0.0.1:5432/identity_ci?sslmode=disable",
    ],
  ]) {
    const r = spawnSync(
      process.execPath,
      ["integration/postgres-revocations.test.ts"],
      {
        cwd: new URL("..", import.meta.url),
        env: {
          ...process.env,
          IAP_TEST_DISPOSABLE_POSTGRES: flag!,
          IAP_TEST_ADMIN_URL: url!,
        },
        encoding: "utf8",
        timeout: 10000,
      },
    );
    assert.equal(r.error, undefined);
    assert.notEqual(r.status, 0);
    assert.match(
      r.stdout + r.stderr,
      /Explicit disposable|Only the designated empty loopback/,
    );
  }
});
