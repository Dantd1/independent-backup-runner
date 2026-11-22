// deno-lint-ignore-file require-await
// Fixture providers intentionally expose asynchronous network-port contracts.
import { test } from "node:test";
import { Buffer } from "node:buffer";
import assert from "node:assert/strict";
import * as age from "age-encryption";
import {
  assertDatabaseWriteScope,
  captureDatabase,
  inspectDatabase,
  retrySourceRead,
} from "../providers.mjs";
import { rootCertificates } from "node:tls";
import { X509Certificate } from "node:crypto";
import {
  b2Url,
  CAP,
  checkBackupCadence,
  configFromEnv,
  DAY,
  digest,
  parseR2List,
  recordAttempt,
  requireSpace,
  scheduleObservation,
  snapshot,
  sourcePath,
  validateDatabaseCa,
  validateDatabaseUrl,
} from "../core.mjs";
test("schedule telemetry distinguishes UTC windows, rollover and legacy events", () => {
  const morning = scheduleObservation(
    "schedule",
    "23 3 * * *",
    "2026-11-21T03:25:00Z",
  );
  assert.equal(morning.inferredScheduledAt, "2026-11-21T03:23:00.000Z");
  assert.equal(morning.inferredDelaySeconds, 120);
  assert.equal(morning.scheduledDateIsInferred, true);
  const afternoon = scheduleObservation(
    "schedule",
    "23 15 * * *",
    "2026-11-21T15:23:00Z",
  );
  assert.equal(
    Date.parse(afternoon.inferredScheduledAt) -
      Date.parse(morning.inferredScheduledAt),
    12 * 3600000,
  );
  assert.equal(
    scheduleObservation("schedule", "23 15 * * *", "2026-11-22T02:00:00Z")
      .inferredScheduledAt,
    afternoon.inferredScheduledAt,
  );
  assert.equal(
    scheduleObservation("schedule", "23 3,15 * * *", "2026-11-21T11:25:25Z")
      .inferredDelaySeconds,
    28945,
  );
  assert.equal(
    scheduleObservation("workflow_dispatch", "", "2026-11-21T11:25:25Z").event,
    "manual",
  );
  assert.throws(
    () => scheduleObservation("schedule", "* * * * *"),
    /unexpected_backup_schedule/,
  );
  assert.throws(
    () => scheduleObservation("schedule", "23 3 * * *", "invalid"),
    /invalid_schedule_clock/,
  );
});
test("cadence reads only bounded staging health and never runs early or on invalid markers", async () => {
  const captured = Date.parse("2026-11-22T03:00:00Z");
  const health = {
    format: "xfinder-backup-health-v1",
    environment: "staging",
    databaseCapturedAt: new Date(captured).toISOString(),
    completedAt: new Date(captured + 600000).toISOString(),
    databaseTables: 177,
  };
  const reads = [];
  const reader = {
    read: async (name, limit) => {
      reads.push({ name, limit });
      return Buffer.from(JSON.stringify(health));
    },
  };
  assert.equal(
    (await checkBackupCadence(reader, captured + 12 * 3600000 - 1)).due,
    false,
  );
  assert.equal(
    (await checkBackupCadence(reader, captured + 12 * 3600000)).due,
    true,
  );
  assert.equal(
    (await checkBackupCadence(reader, captured + 16 * 3600000)).due,
    true,
  );
  assert.equal(
    (await checkBackupCadence(reader, captured + 12 * 3600000, false)).due,
    false,
  );
  assert.equal(
    (await checkBackupCadence(reader, captured + 600000 + 12 * 3600000, false))
      .due,
    true,
  );
  assert.ok(
    reads.every((x) =>
      x.name === "staging/health/success.json" && x.limit === 4096
    ),
  );
  health.environment = "production";
  await assert.rejects(
    () => checkBackupCadence(reader, captured + 13 * 3600000),
    /cadence_marker_scope_invalid/,
  );
  health.environment = "staging";
  health.databaseCapturedAt = "invalid";
  await assert.rejects(
    () => checkBackupCadence(reader, captured + 13 * 3600000),
    /cadence_marker_invalid/,
  );
  health.databaseCapturedAt = new Date(captured + 20 * 3600000).toISOString();
  await assert.rejects(
    () => checkBackupCadence(reader, captured + 13 * 3600000),
    /cadence_marker_invalid/,
  );
  health.databaseCapturedAt = new Date(captured).toISOString();
  health.databaseTables = 0;
  await assert.rejects(
    () => checkBackupCadence(reader, captured + 13 * 3600000),
    /cadence_marker_invalid/,
  );
  await assert.rejects(() =>
    checkBackupCadence({
      read: async () => {
        throw Error("unavailable");
      },
    }), /unavailable/);
  const periodic = scheduleObservation(
    "schedule",
    "8,23,38,53 * * * *",
    "2026-11-22T03:39:00Z",
  );
  assert.equal(periodic.inferredScheduledAt, "2026-11-22T03:38:00.000Z");
});
const scope = {
  environment: "staging",
  projectRef: "a".repeat(20),
  cfAccount: "b".repeat(32),
  kvNamespace: "c".repeat(32),
  r2Bucket: "synthetic-staging",
  b2Account: "synthetic",
  b2Bucket: "fixture",
  b2Name: "synthetic-staging-backup",
  sitesExportUrl: "https://synthetic-staging.example.workers.dev/",
  recoveryObject: "staging/recovery/synthetic/identity.age",
};

test("managed platform capabilities require explicit acceptance and never permit application writes", () => {
  const empty = {
    unsafe_tables: 0,
    unsafe_sequences: 0,
    managed_tables: 0,
    managed_sequences: 0,
    managed_functions: 0,
  };
  assert.doesNotThrow(() => assertDatabaseWriteScope(empty));
  const managed = {
    ...empty,
    managed_tables: 3,
    managed_sequences: 1,
    managed_functions: 17,
  };
  assert.throws(
    () => assertDatabaseWriteScope(managed),
    /database_managed_public_writes_unapproved/,
  );
  assert.doesNotThrow(() =>
    assertDatabaseWriteScope(managed, { allowManagedPublicWrites: true })
  );
  assert.throws(
    () =>
      assertDatabaseWriteScope({ ...managed, unsafe_tables: 1 }, {
        allowManagedPublicWrites: true,
      }),
    /database_application_write_privileges_denied/,
  );
  assert.throws(
    () =>
      assertDatabaseWriteScope({ ...managed, unsafe_sequences: 1 }, {
        allowManagedPublicWrites: true,
      }),
    /database_application_write_privileges_denied/,
  );
  assert.throws(
    () => assertDatabaseWriteScope({}),
    /database_scope_inspection_required/,
  );
});
const environment = () => ({
  XFINDER_ENVIRONMENT: "staging",
  BACKUP_ZERO_COST_VERIFIED: "true",
  BACKUP_SCOPE_JSON: JSON.stringify(scope),
  STORAGE_READER_ID: "11111111-1111-4111-8111-111111111111",
  STORAGE_READER_KEY: "synthetic-storage-reader-value-not-live",
  SITES_READER_ID: "22222222-2222-4222-8222-222222222222",
  SITES_READER_KEY: "synthetic-sites-reader-value-not-live",
  B2_READ_KEY_ID: "synthetic-reader",
  B2_READ_KEY: "synthetic",
  B2_WRITE_KEY_ID: "synthetic-writer",
  B2_WRITE_KEY: "synthetic",
  AGE_RECIPIENT: "synthetic",
});

test("read-only exporters retry transport/body failures, bound retries and refuse auth failures", async () => {
  let calls = 0;
  const result = await retrySourceRead(async () => {
    if (++calls === 1) {
      return new Response(
        new ReadableStream({
          start(controller) {
            controller.error(new TypeError("private details"));
          },
        }),
      );
    }
    if (calls === 2) return new Response("unavailable", { status: 503 });
    return new Response("synthetic", { headers: { etag: "synthetic" } });
  }, { pause: async () => {} });
  assert.equal(calls, 3);
  assert.equal(await result.text(), "synthetic");
  assert.equal(result.headers.get("etag"), "synthetic");
  calls = 0;
  await assert.rejects(
    retrySourceRead(async () => {
      calls++;
      return new Response("private", { status: 403 });
    }, { pause: async () => {} }),
    /provider_http_403/,
  );
  assert.equal(calls, 1);
  calls = 0;
  await assert.rejects(
    retrySourceRead(async () => {
      calls++;
      throw new DOMException("private", "TimeoutError");
    }, { pause: async () => {} }),
    /source_read_transport_failed/,
  );
  assert.equal(calls, 3);
});
test("temporary 404 reads may recover but persistent missing sources remain failures", async () => {
  let calls = 0;
  const result = await retrySourceRead(
    async () =>
      ++calls === 1
        ? new Response("missing", { status: 404 })
        : new Response("synthetic"),
    { pause: async () => {} },
  );
  assert.equal(await result.text(), "synthetic");
  assert.equal(calls, 2);
  calls = 0;
  await assert.rejects(
    retrySourceRead(async () => {
      calls++;
      return new Response("missing", { status: 404 });
    }, { pause: async () => {} }),
    /provider_http_404/,
  );
  assert.equal(calls, 3);
});

test("attempt telemetry is bounded, operational only and blocked when free capacity is exhausted", async () => {
  const calls = [];
  const b2 = {
    inventory: async () => ({ bytes: 1000 }),
    put: async (name, bytes, options) => {
      calls.push({ name, payload: JSON.parse(bytes), options });
    },
  };
  await recordAttempt(b2, "failure", 1700000000000);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].name, "staging/health/attempt.json");
  assert.deepEqual(Object.keys(calls[0].payload).sort(), [
    "completedAt",
    "conclusion",
    "environment",
    "format",
  ]);
  assert.equal(calls[0].payload.conclusion, "failure");
  await assert.rejects(
    recordAttempt(
      { ...b2, inventory: async () => ({ bytes: CAP }) },
      "success",
    ),
    /free_capacity_limit/,
  );
  await assert.rejects(
    recordAttempt(b2, "unexpected"),
    /invalid_attempt_conclusion/,
  );
});

test("database connections reject production, admin roles, transaction poolers and unsafe URL options", () => {
  const role = "xfinder_db_bak_stg_20261121_00000001",
    ref = "a".repeat(20),
    password = "synthetic-".repeat(8);
  const url =
    `postgresql://${role}.${ref}:${password}@aws-0-sa-east-1.pooler.supabase.com:5432/postgres`;
  assert.equal(validateDatabaseUrl(url, ref).role, role);
  for (
    const value of [
      url.replace(":5432", ":6543"),
      url + "?options=unsafe",
      url.replace(role, "postgres"),
      url.replace(".pooler.supabase.com", ".attacker.invalid"),
      url.replace("/postgres", "/template1"),
    ]
  ) assert.throws(() => validateDatabaseUrl(value, ref));
  assert.throws(
    () => validateDatabaseUrl(url, "ozryyalyaquujtfaudzi"),
    /database_stage_required/,
  );
});

test("database CA is required and production is refused before any SQL", async () => {
  const valid = rootCertificates.find((pem) => {
    const cert = new X509Certificate(pem);
    return cert.ca && Date.parse(cert.validFrom) <= Date.now() &&
      Date.parse(cert.validTo) > Date.now();
  });
  assert.equal(validateDatabaseCa(valid), valid);
  assert.throws(() => validateDatabaseCa("untrusted"), /database_ca_invalid/);
  let queries = 0;
  const sql = {
    unsafe: () => {
      queries++;
    },
    begin: () => {
      queries++;
    },
  };
  await assert.rejects(
    inspectDatabase(sql, "ozryyalyaquujtfaudzi", "postgres"),
    /database_stage_required/,
  );
  assert.throws(
    () => captureDatabase(sql, "ozryyalyaquujtfaudzi", "postgres", () => {}),
    /database_stage_required/,
  );
  assert.equal(queries, 0);
});
test("activation, staging scope, independent B2 roles and free-cap guards fail closed", () => {
  assert.equal(configFromEnv(environment()).scope.environment, "staging");
  for (
    const changes of [
      { XFINDER_ENVIRONMENT: "production" },
      { BACKUP_ZERO_COST_VERIFIED: "false" },
      { STORAGE_READER_ID: "invalid" },
      { B2_WRITE_KEY_ID: "synthetic-reader" },
      { STORAGE_READER_KEY: "too-short" },
    ]
  ) assert.throws(() => configFromEnv({ ...environment(), ...changes }));
  assert.throws(() =>
    configFromEnv({
      ...environment(),
      BACKUP_SCOPE_JSON: JSON.stringify({
        ...scope,
        r2Bucket: "synthetic-production",
      }),
    })
  );
  requireSpace(CAP - 1, 1);
  assert.throws(() => requireSpace(CAP, 1));
  assert.throws(() => requireSpace(-1, 1));
  assert.throws(() => b2Url("https://backblazeb2.com.attacker.invalid/"));
  assert.throws(() => b2Url("http://api.backblazeb2.com/"));
  assert.throws(() => sourcePath("../private"));
  assert.equal(sourcePath("folder/a & b.png"), "folder/a%20%26%20b.png");
});
test("S3 XML handles encoded filenames, empty pages and opaque cursors; rejects DTDs", () => {
  const xml =
    "<ListBucketResult><Contents><Key>a&amp;b/&#xE7;.png</Key><Size>4</Size><ETag>&quot;opaque&quot;</ETag><LastModified>2026-01-01T00:00:00Z</LastModified></Contents><IsTruncated>true</IsTruncated><NextContinuationToken>a&amp;b=</NextContinuationToken></ListBucketResult>";
  const result = parseR2List(xml);
  assert.equal(result.objects[0].key, "a&b/ç.png");
  assert.equal(result.objects[0].etag, "opaque");
  assert.equal(result.next, "a&b=");
  assert.equal(
    parseR2List(
      "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>",
    ).objects.length,
    0,
  );
  assert.throws(() =>
    parseR2List('<!DOCTYPE x [<!ENTITY x SYSTEM "file:///secret">]>' + xml)
  );
});
async function fixture() {
  const now = Date.parse("2026-11-20T00:00:00Z");
  const bytes = {
    storage: Buffer.from("synthetic image"),
    r2: Buffer.from("synthetic site"),
    kv: Buffer.from('{"synthetic":true}'),
  };
  const item = {
    id: "synthetic",
    bucket: "private-fixture",
    name: "folder/image.png",
    updated: "2026-11-20",
    size: bytes.storage.length,
    etag: "storage-etag",
  };
  const catalog = {
    buckets: [{ id: item.bucket, public: false }],
    objects: [item],
  };
  const r2Item = {
    key: "site/index.html",
    size: bytes.r2.length,
    etag: "r2-etag",
    last_modified: "2026-11-20",
  };
  const files = new Map(), payloads = new Map(), writes = [], extensions = [];
  let used = 0, catalogCalls = 0;
  for (
    const name of [
      scope.recoveryObject,
      "staging/credentials/synthetic-reader.age",
      "staging/credentials/synthetic-writer.age",
    ]
  ) {
    files.set(name, {
      name,
      id: name,
      size: 10,
      mode: "compliance",
      until: now + 31 * DAY,
    });
    used += 10;
  }
  const b2 = {
    keyIds: ["synthetic-reader", "synthetic-writer"],
    async inventory() {
      return {
        bytes: used,
        files: new Map([...files].map(([name, file]) => [name, { ...file }])),
      };
    },
    async extend(file, until) {
      files.get(file.name).until = until;
      extensions.push(file.name);
    },
    async put(name, data, options) {
      const id = String(writes.length);
      used += data.length;
      payloads.set(name, Buffer.from(data));
      files.set(name, {
        id,
        name,
        size: data.length,
        mode: "compliance",
        until: options.until,
        sourceDigest: options.sourceDigest,
      });
      writes.push(name);
      return { id, size: data.length };
    },
    async read(name) {
      return payloads.get(name);
    },
  };
  const identity = await age.generateX25519Identity();
  const encrypter = new age.Encrypter();
  encrypter.addRecipient(await age.identityToRecipient(identity));
  return {
    scope,
    now,
    encrypter,
    b2,
    files,
    payloads,
    writes,
    extensions,
    identity,
    storage: {
      async list() {
        catalogCalls++;
        return structuredClone(catalog);
      },
      async read() {
        return { bytes: bytes.storage, etag: 'W/"storage-etag"' };
      },
    },
    r2: {
      async list() {
        return structuredClone([r2Item]);
      },
      async read() {
        return { bytes: bytes.r2, etag: '"r2-etag"' };
      },
    },
    kv: {
      async list() {
        return [{ name: "synthetic-key" }];
      },
      async read() {
        return { bytes: bytes.kv };
      },
    },
    changeCatalog() {
      catalog.objects[0].updated = "changed";
    },
    catalogCalls: () => catalogCalls,
  };
}
test("inventory performs no writes, retention changes or credential archive rewrites", async () => {
  const f = await fixture();
  const result = await snapshot({ ...f, mode: "inventory" });
  assert.equal(result.status, "inventory_verified");
  assert.deepEqual(f.writes, []);
  assert.deepEqual(f.extensions, []);
});
test("encrypted snapshot restores all fixture sources, then reuses unchanged blobs and extends protection", async () => {
  const f = await fixture();
  const result = await snapshot(f);
  assert.equal(result.status, "snapshot_committed");
  assert.deepEqual([result.stats.storage, result.stats.r2, result.stats.kv], [
    1,
    1,
    1,
  ]);
  const decrypt = new age.Decrypter();
  decrypt.addIdentity(f.identity);
  const manifest = JSON.parse(
    await decrypt.decrypt(f.payloads.get(result.manifest), "text"),
  );
  for (const record of manifest.records) {
    const bytes = await decrypt.decrypt(
      f.payloads.get(record.destination.object),
    );
    assert.equal(digest(bytes), record.destination.sourceDigest);
  }
  assert.equal(manifest.captureConsistency.kvAtomic, false);
  assert.equal(
    f.writes.some((name) =>
      name.includes("/credentials/") || name.includes("/recovery/")
    ),
    false,
  );
  const second = await snapshot({ ...f, now: f.now + 2 * DAY });
  assert.equal(second.stats.reused, 2);
  assert.equal(second.stats.uploaded, 3); // Fresh KV, manifest, health.
  assert.ok(f.extensions.length >= 5);
});

test("recovery packs preserve v1 records, decrypt completely and reuse stable partitions", async () => {
  const f = await fixture(), decrypt = new age.Decrypter();
  decrypt.addIdentity(f.identity);
  const first = await snapshot({ ...f, recoveryPacks: true });
  const manifest = JSON.parse(
    await decrypt.decrypt(f.payloads.get(first.manifest), "text"),
  );
  assert.equal(manifest.format, "xfinder-age-backup-v1");
  assert.equal(manifest.recoveryPacks.length, 3);
  const covered = new Set();
  for (const pack of manifest.recoveryPacks) {
    const bytes = await decrypt.decrypt(f.payloads.get(pack.object));
    for (const part of pack.parts) {
      assert.equal(
        digest(bytes.subarray(part.offset, part.offset + part.length)),
        manifest.records[part.index].destination.sourceDigest,
      );
      covered.add(part.index);
    }
    assert.equal(f.files.get(pack.object).mode, "compliance");
  }
  assert.equal(covered.size, manifest.records.length);
  for (const record of manifest.records) {
    assert.equal(
      digest(await decrypt.decrypt(f.payloads.get(record.destination.object))),
      record.destination.sourceDigest,
    );
  }
  const priorWrites = f.writes.length;
  await snapshot({ ...f, recoveryPacks: true, now: f.now + 2 * DAY });
  assert.equal(
    f.writes.slice(priorWrites).filter((name) =>
      name.startsWith("staging/recovery-packs/")
    ).length,
    1,
  ); // Only fresh KV.
});

test("packed retention renews complete restore packs within quota without changing legacy locks", async () => {
  const f = await fixture(), decrypt = new age.Decrypter();
  decrypt.addIdentity(f.identity);
  const first = await snapshot({ ...f, recoveryPacks: true });
  const before = JSON.parse(
    await decrypt.decrypt(f.payloads.get(first.manifest), "text"),
  );
  const legacy = before.records.map((r) => ({
    object: r.destination.object,
    until: f.files.get(r.destination.object).until,
  }));
  const next = await snapshot({
    ...f,
    recoveryPacks: true,
    now: f.now + 2 * DAY,
  });
  const after = JSON.parse(
    await decrypt.decrypt(f.payloads.get(next.manifest), "text"),
  );
  assert.equal(after.retentionBasis, "complete-recovery-packs");
  assert.equal(
    f.extensions.some((name) => name.startsWith("staging/objects/")),
    false,
  );
  for (const item of legacy) {
    assert.ok(f.payloads.has(item.object));
    assert.equal(f.files.get(item.object).until, item.until);
  }
  for (const pack of after.recoveryPacks) {
    assert.ok(f.files.get(pack.object).until >= f.now + 32 * DAY);
  }
  assert.ok(f.extensions.length <= before.recoveryPacks.length + 3);
  for (const pack of after.recoveryPacks) {
    const bytes = await decrypt.decrypt(f.payloads.get(pack.object));
    for (const part of pack.parts) {
      assert.equal(
        digest(bytes.subarray(part.offset, part.offset + part.length)),
        after.records[part.index].destination.sourceDigest,
      );
    }
  }
});

test("database payloads are encrypted, retained and referenced without altering v1 object records", async () => {
  const f = await fixture(), decrypt = new age.Decrypter();
  decrypt.addIdentity(f.identity);
  const clear = Buffer.from("PGDMPsynthetic database archive"),
    expected = Buffer.from(clear);
  let inspections = 0, captures = 0;
  const database = {
    inspect: async () => {
      inspections++;
    },
    capture: async () => {
      captures++;
      return {
        dump: clear,
        context: {
          environment: "staging",
          projectRef: scope.projectRef,
          capturedAt: new Date(f.now).toISOString(),
          counts: [{ schema: "public", name: "synthetic", rows: "1" }],
          roles: [{ rolname: "synthetic", rolsuper: false }],
        },
      };
    },
  };
  const result = await snapshot({ ...f, database });
  const manifest = JSON.parse(
    await decrypt.decrypt(f.payloads.get(result.manifest), "text"),
  );
  assert.equal(inspections, 1);
  assert.equal(captures, 1);
  assert.equal(manifest.format, "xfinder-age-backup-v1");
  assert.equal(manifest.records.length, 3);
  assert.equal(manifest.database.format, "xfinder-postgres-backup-v1");
  assert.deepEqual(
    Buffer.from(
      await decrypt.decrypt(f.payloads.get(manifest.database.dump.object)),
    ),
    expected,
  );
  assert.equal(manifest.database.dump.digest, digest(expected));
  assert.ok(clear.every((byte) => byte === 0));
  assert.equal(f.files.get(manifest.database.dump.object).mode, "compliance");
  const health = JSON.parse(f.payloads.get("staging/health/success.json"));
  assert.equal(health.databaseTables, 1);
  assert.equal(health.databaseCapturedAt, new Date(f.now).toISOString());
});

test("inventory never captures database data; capture failure never publishes success", async () => {
  const f = await fixture();
  let calls = 0;
  const database = {
    inspect: async () => {},
    capture: async () => {
      calls++;
      throw Error("synthetic database unavailable");
    },
  };
  await snapshot({ ...f, database, mode: "inventory" });
  assert.equal(calls, 0);
  assert.equal(f.writes.length, 0);
  await assert.rejects(snapshot({ ...f, database }));
  assert.equal(calls, 1);
  assert.equal(
    f.writes.some((name) =>
      name.endsWith("/manifest.age") || name === "staging/health/success.json"
    ),
    false,
  );
});

test("packing refuses changed source bytes and never commits partial packs as success", async () => {
  const f = await fixture(), read = f.storage.read;
  let reads = 0;
  f.storage.read = async () =>
    ++reads >= 3 ? { bytes: Buffer.from("changed") } : read();
  await assert.rejects(
    snapshot({ ...f, recoveryPacks: true }),
    /recovery_pack_source_changed/,
  );
  assert.equal(
    f.writes.some((name) =>
      name.endsWith("/manifest.age") || name === "staging/health/success.json"
    ),
    false,
  );
});

test("reused packs remap member indexes after a preceding source is added", async () => {
  const f = await fixture(), decrypt = new age.Decrypter();
  decrypt.addIdentity(f.identity);
  const first = await snapshot({ ...f, recoveryPacks: true });
  const before = JSON.parse(
    await decrypt.decrypt(f.payloads.get(first.manifest), "text"),
  );
  const previousIndex = before.records.findIndex((record) =>
    record.kind === "r2"
  );
  const previousPack = before.recoveryPacks.find((pack) =>
    pack.parts.some((part) => part.index === previousIndex)
  );
  const list = f.storage.list;
  f.storage.list = async () => {
    const catalog = await list();
    catalog.objects.unshift({
      ...catalog.objects[0],
      id: "added",
      name: "added.png",
    });
    return catalog;
  };
  const second = await snapshot({
    ...f,
    recoveryPacks: true,
    now: f.now + DAY,
  });
  const after = JSON.parse(
    await decrypt.decrypt(f.payloads.get(second.manifest), "text"),
  );
  const index = after.records.findIndex((record) => record.kind === "r2");
  assert.equal(index, previousIndex + 1);
  const reused = after.recoveryPacks.find((pack) =>
    pack.object === previousPack.object
  );
  assert.equal(reused.parts[0].index, index);
  const bytes = await decrypt.decrypt(f.payloads.get(reused.object));
  assert.equal(digest(bytes), after.records[index].destination.sourceDigest);
});

test("additional archived credentials retain compliance without changing legacy credentialCopies", async () => {
  const f = await fixture(), object = "staging/credentials/synthetic-extra.age";
  f.files.set(object, {
    id: object,
    name: object,
    size: 10,
    mode: "compliance",
    until: f.now + DAY,
  });
  const result = await snapshot(f), decrypt = new age.Decrypter();
  decrypt.addIdentity(f.identity);
  const manifest = JSON.parse(
    await decrypt.decrypt(f.payloads.get(result.manifest), "text"),
  );
  assert.equal(manifest.credentialCopies.length, 2);
  assert.equal(manifest.additionalCredentialCopies[0].object, object);
  assert.ok(f.extensions.includes(object));
});
test("source failure retains uploaded blobs but never commits a manifest or health marker", async () => {
  const f = await fixture(), read = f.kv.read;
  let calls = 0;
  f.kv.read = async () => {
    if (++calls > 1) throw Error("synthetic provider failure");
    return read();
  };
  await assert.rejects(() => snapshot(f));
  assert.ok(f.writes.length > 0);
  assert.equal(
    f.writes.some((n) => n.includes("/snapshots/") || n.includes("/health/")),
    false,
  );
});
test("source changes during copy prevent a committed manifest", async () => {
  const f = await fixture(), read = f.storage.read;
  f.storage.read = async () => {
    const result = await read();
    if (f.catalogCalls() === 1) f.changeCatalog();
    return result;
  };
  await assert.rejects(() => snapshot(f), /storage_changed_during_backup/);
  assert.equal(
    f.writes.some((n) => n.includes("/snapshots/") || n.includes("/health/")),
    false,
  );
});
test("a destination that failed to apply compliance never receives a success heartbeat", async () => {
  const f = await fixture(), put = f.b2.put;
  f.b2.put = async (name, bytes, opts) => {
    const result = await put(name, bytes, opts);
    if (name.includes("/objects/")) f.files.get(name).mode = "governance";
    return result;
  };
  await assert.rejects(() => snapshot(f), /snapshot_retention_unverified/);
  assert.equal(f.writes.some((n) => n.includes("/health/")), false);
});
