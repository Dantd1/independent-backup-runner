import test from "node:test";
import assert from "node:assert/strict";
import {
  connectConfigurationSource,
  sanitizeConfiguration,
  validateConfigurationPackage,
  validateConfigurationScope,
} from "../configuration.mjs";
import { backupConfiguration } from "../configuration-backup.mjs";
const uuid = (n) =>
  String(n).repeat(8) + "-" + String(n).repeat(4) + "-4" + String(n).repeat(3) +
  "-8" + String(n).repeat(3) + "-" + String(n).repeat(12);
const scope = () => ({
  environment: "staging",
  projectRef: "abcdefghijklmnopqrst",
  accountId: "a".repeat(32),
  apps: [{ id: uuid(1), domain: "staging.example.invalid" }, {
    id: uuid(2),
    domain: "admin-staging.example.invalid",
  }, { id: uuid(3), domain: "staging.sites.invalid" }],
  workers: ["public-staging", "admin-staging", "sites-staging"],
  identityProviders: [uuid(4), uuid(5)],
  zones: [{
    id: "b".repeat(32),
    name: "example.invalid",
    dnsNames: ["staging.example.invalid"],
  }, {
    id: "c".repeat(32),
    name: "sites.invalid",
    dnsNames: ["staging.sites.invalid"],
  }],
  escrowObjects: [
    "staging/credentials/supabase-config-fixture.age",
    "staging/credentials/cloudflare-config-fixture.age",
  ],
  readersExpireAt: "2099-01-01T00:00:00Z",
});
function fixture(modify = (x) => x) {
  const s = scope(), calls = [];
  const fetcher = async (url, options) => {
    const u = new URL(url);
    calls.push({ host: u.hostname, path: u.pathname, method: options.method });
    assert.equal(options.method, "GET");
    assert.equal(options.redirect, "error");
    let result = { configuration: "synthetic", jwt_secret: "must-be-removed" };
    if (u.hostname === "api.cloudflare.com") {
      const app = s.apps.find((a) => u.pathname.endsWith("/apps/" + a.id));
      if (app) {
        result = {
          ...app,
          destinations: [{ type: "public", uri: app.domain }],
        };
      } else if (u.pathname.endsWith("/policies")) {
        result = [{
          id: uuid(6),
          decision: "allow",
          include: [{ service_token: { token_id: uuid(7) } }],
          require: [{ email: { email: "fixture@example.invalid" } }],
        }];
      } else if (u.pathname.includes("/identity_providers/")) {
        result = {
          id: u.pathname.split("/").at(-1),
          type: "google",
          config: {
            client_id: "fixture-client",
            client_secret: "must-be-removed",
          },
        };
      } else if (u.pathname.endsWith("/settings")) {
        result = {
          bindings: [{
            name: "ENVIRONMENT",
            type: "plain_text",
            text: "staging",
          }, {
            name: "CREDENTIAL",
            type: "secret_text",
            text: "opaque-must-be-removed",
          }],
        };
      } else if (u.pathname.endsWith("/schedules")) result = { schedules: [] };
      else if (u.pathname.endsWith("/dns_records")) {
        result = [{
          id: "record",
          name: u.searchParams.get("name"),
          type: "CNAME",
          content: "worker.invalid",
          proxied: true,
        }];
      } else if (u.pathname.endsWith("/routes")) {
        result = [{
          pattern: "staging.example.invalid/*",
          script: "public-staging",
        }, { pattern: "example.invalid/*", script: "public-production" }];
      } else result = { id: u.pathname.split("/").at(-1), value: "on" };
    }
    result = modify(result, u);
    return new Response(
      JSON.stringify(
        u.hostname === "api.cloudflare.com"
          ? { success: true, result }
          : result,
      ),
    );
  };
  return {
    s,
    calls,
    source: connectConfigurationSource({
      scope: s,
      base: {
        environment: "staging",
        projectRef: s.projectRef,
        cfAccount: s.accountId,
      },
      supabaseToken: ["sbp", "fc_synthetic_only"].join("_"),
      cloudflareToken: "synthetic-only-not-a-provider-token".repeat(2),
      fetcher,
    }),
  };
}
test("sanitizer removes credentials at every depth while preserving Access service-token selectors", () => {
  const input = {
    nested: {
      client_secret: "hidden",
      password: "hidden",
      password_min_length: 12,
      password_required_characters: "lower_upper_letters_digits_symbols",
    },
    include: [{ service_token: { token_id: uuid(1) } }],
    binding: { name: "X", type: "secret_text", text: "opaque" },
  };
  const result = sanitizeConfiguration(input);
  assert.deepEqual(result.include, input.include);
  assert.deepEqual(result.nested, {
    password_min_length: 12,
    password_required_characters: "lower_upper_letters_digits_symbols",
  });
  assert.equal("text" in result.binding, false);
  assert.equal(result.binding.valueAvailable, false);
  assert.throws(() =>
    sanitizeConfiguration({
      unexpected: ["AGE", "SECRET", "KEY", ""].join("-"),
    })
  );
});
test("configuration scope rejects production before source calls", () => {
  const s = scope();
  assert.throws(() =>
    validateConfigurationScope({ ...s, environment: "production" }, {
      environment: "staging",
      projectRef: s.projectRef,
      cfAccount: s.accountId,
    })
  );
  assert.throws(() =>
    validateConfigurationScope({ ...s, workers: ["public-production"] }, {
      environment: "staging",
      projectRef: s.projectRef,
      cfAccount: s.accountId,
    })
  );
});
test("capture is bounded GET-only, removes secret bindings, preserves policy semantics and excludes production routes", async () => {
  const f = fixture(), captured = await f.source.capture();
  assert.equal(captured.summary.supabaseGroups, 5);
  assert.equal(captured.summary.accessApplications, 3);
  assert.equal(
    captured.data.apps[0].policies[0].include[0].service_token.token_id,
    uuid(7),
  );
  assert.equal(captured.bytes.toString().includes("must-be-removed"), false);
  assert.equal(captured.bytes.toString().includes("production"), false);
  assert.ok(f.calls.length < 100 && f.calls.every((c) => c.method === "GET"));
  assert.throws(() =>
    validateConfigurationPackage({ ...captured.data, supabase: {} }, f.s)
  );
  assert.throws(() =>
    validateConfigurationPackage({ ...captured.data, password: "secret" }, f.s)
  );
});
test("capture refuses a widened Access destination or production worker marker", async () => {
  for (
    const mutate of [
      (r, u) =>
        u.pathname.includes("/apps/") && !u.pathname.endsWith("/policies")
          ? { ...r, destinations: [{ type: "public", uri: "example.invalid" }] }
          : r,
      (r, u) =>
        u.pathname.endsWith("/settings")
          ? {
            bindings: [{
              name: "ENVIRONMENT",
              type: "plain_text",
              text: "production",
            }],
          }
          : r,
    ]
  ) await assert.rejects(fixture(mutate).source.capture());
});
test("configuration commit requires escrow, capacity, readback and retention before publishing health", async () => {
  const f = fixture(),
    files = new Map(
      f.s.escrowObjects.map(
        (o) => [o, { mode: "compliance", until: Date.now() + 32 * 86400000 }],
      ),
    ),
    values = new Map();
  const b2 = {
    inventory: async () => ({ bytes: 1024, files }),
    extend: async () => {},
    put: async (name, bytes, { until }) => {
      values.set(name, Buffer.from(bytes));
      files.set(name, { mode: "compliance", until });
      return { id: "synthetic-file-id", size: bytes.length };
    },
    read: async (name) => {
      if (!values.has(name)) {
        throw Object.assign(Error("missing"), {
          safeCode: "provider_http_404",
        });
      }
      return values.get(name);
    },
  };
  const report = await backupConfiguration({
    source: f.source,
    b2,
    encrypter: {
      encrypt: async (clear) =>
        Buffer.concat([Buffer.from("encrypted-fixture:"), clear]),
    },
  });
  assert.equal(report.status, "configuration_snapshot_committed");
  assert.ok(values.has("staging/health/configuration-success.json"));
  assert.equal(
    (await backupConfiguration({ source: f.source, b2, encrypter: {} })).status,
    "configuration_snapshot_fresh",
  );
  assert.equal(
    (await backupConfiguration({
      source: f.source,
      b2,
      encrypter: {},
      commissioningUntil: new Date(Date.now() + 2 * 3600000).toISOString(),
    })).status,
    "configuration_snapshot_fresh",
  );
  assert.equal(
    (await backupConfiguration({
      source: f.source,
      b2,
      encrypter: {
        encrypt: async (clear) =>
          Buffer.concat([Buffer.from("encrypted-fixture:"), clear]),
      },
      commissioningUntil: new Date(Date.now() + 1800000).toISOString(),
    })).status,
    "configuration_snapshot_committed",
  );
  values.delete("staging/health/configuration-success.json");
  const blocked = { ...b2, inventory: async () => ({ bytes: 9e9, files }) };
  await assert.rejects(
    backupConfiguration({ source: f.source, b2: blocked, encrypter: {} }),
    /free_configuration_capacity_limit/,
  );
  const missing = {
    ...b2,
    inventory: async () => ({ bytes: 0, files: new Map() }),
  };
  await assert.rejects(
    backupConfiguration({ source: f.source, b2: missing, encrypter: {} }),
    /configuration_reader_not_escrowed/,
  );
  values.clear();
  const corrupt = {
    ...b2,
    read: async (name) => {
      if (name.endsWith("configuration-success.json")) {
        throw Object.assign(Error("missing"), {
          safeCode: "provider_http_404",
        });
      }
      return Buffer.from("corrupt");
    },
  };
  await assert.rejects(
    backupConfiguration({
      source: f.source,
      b2: corrupt,
      encrypter: { encrypt: async (clear) => clear },
    }),
    /configuration_ciphertext_readback_failed/,
  );
  assert.equal(values.has("staging/health/configuration-success.json"), false);
});
