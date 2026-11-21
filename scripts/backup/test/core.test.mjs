// deno-lint-ignore-file require-await
// Fixture providers intentionally expose asynchronous network-port contracts.
import { test } from "node:test";
import { Buffer } from "node:buffer";
import assert from "node:assert/strict";
import * as age from "age-encryption";
import { retrySourceRead } from "../providers.mjs";
import {
  b2Url,
  CAP,
  configFromEnv,
  DAY,
  digest,
  parseR2List,
  recordAttempt,
  requireSpace,
  snapshot,
  sourcePath,
} from "../core.mjs";
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
