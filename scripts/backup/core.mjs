import { createHash, randomUUID, X509Certificate } from "node:crypto";
import { Buffer } from "node:buffer";
export const CAP = 9_000_000_000;
export const DAY = 86400000;
export function requireSafe(ok, code) {
  if (!ok) {
    const e = new Error(code);
    e.safeCode = code;
    throw e;
  }
}
export const digest = (value) =>
  createHash("sha256").update(value).digest("hex");
export const normalizeEtag = (value) =>
  String(value).trim().replace(/^W\//, "").replace(/^"|"$/g, "");
export function requireSpace(used, extra) {
  requireSafe(
    Number.isSafeInteger(used) && Number.isSafeInteger(extra) && used >= 0 &&
      extra >= 0 && used + extra <= CAP,
    "free_capacity_limit",
  );
}
export function b2Url(value) {
  const u = new URL(value);
  requireSafe(
    u.protocol === "https:" && !u.username && !u.password &&
      (u.hostname.endsWith(".backblazeb2.com") ||
        u.hostname.endsWith(".backblaze.com")),
    "b2_origin_rejected",
  );
  return u;
}
export function objectName(kind, identity) {
  requireSafe(["storage", "r2", "kv"].includes(kind), "invalid_source_kind");
  return "staging/objects/" + kind + "/" + digest(JSON.stringify(identity)) +
    ".age";
}
export function sourcePath(key) {
  requireSafe(
    typeof key === "string" &&
      !key.split("/").some((p) => p === "." || p === ".."),
    "unsafe_source_path",
  );
  return key.split("/").map(encodeURIComponent).join("/");
}
export function configFromEnv(env) {
  requireSafe(
    env.XFINDER_ENVIRONMENT === "staging" &&
      env.BACKUP_ZERO_COST_VERIFIED === "true",
    "activation_not_verified",
  );
  const names = [
    "BACKUP_SCOPE_JSON",
    "STORAGE_READER_ID",
    "STORAGE_READER_KEY",
    "SITES_READER_ID",
    "SITES_READER_KEY",
    "B2_READ_KEY_ID",
    "B2_READ_KEY",
    "B2_WRITE_KEY_ID",
    "B2_WRITE_KEY",
    "AGE_RECIPIENT",
  ];
  const config = {};
  for (const name of names) {
    requireSafe(
      typeof env[name] === "string" && env[name].length > 0,
      "missing_configuration",
    );
    config[name] = env[name];
  }
  let scope;
  try {
    scope = JSON.parse(config.BACKUP_SCOPE_JSON);
  } catch {
    requireSafe(false, "invalid_scope_configuration");
  }
  requireSafe(
    scope && typeof scope === "object" && !Array.isArray(scope) &&
      [
        "environment",
        "projectRef",
        "cfAccount",
        "kvNamespace",
        "r2Bucket",
        "b2Account",
        "b2Bucket",
        "b2Name",
        "sitesExportUrl",
        "recoveryObject",
      ]
        .every((name) =>
          typeof scope[name] === "string" && scope[name].length > 0
        ),
    "invalid_scope_configuration",
  );
  requireSafe(
    scope.environment === "staging" &&
      /^[a-z0-9]{20}$/.test(scope.projectRef) &&
      /^[a-f0-9]{32}$/.test(scope.cfAccount) &&
      /^[a-f0-9]{32}$/.test(scope.kvNamespace),
    "invalid_scope_configuration",
  );
  requireSafe(
    typeof scope.r2Bucket === "string" && scope.r2Bucket.endsWith("-staging") &&
      /^[a-z0-9-]+$/.test(scope.r2Bucket),
    "non_staging_resource",
  );
  requireSafe(
    /^[a-z0-9]+$/.test(scope.b2Account) && /^[a-z0-9]+$/.test(scope.b2Bucket) &&
      /^[a-z0-9-]+$/.test(scope.b2Name) && /-staging(?:-|$)/.test(scope.b2Name),
    "invalid_b2_scope",
  );
  requireSafe(
    typeof scope.recoveryObject === "string" &&
      scope.recoveryObject.startsWith("staging/recovery/"),
    "invalid_recovery_scope",
  );
  sourcePath(scope.recoveryObject);
  config.scope = scope;
  const sites = new URL(scope.sitesExportUrl);
  requireSafe(
    sites.protocol === "https:" && !sites.username && !sites.password &&
      !sites.search && sites.pathname === "/" &&
      sites.hostname.endsWith(".workers.dev") &&
      sites.hostname.split(".")[0].endsWith("-staging"),
    "source_origin_rejected",
  );
  for (const prefix of ["STORAGE", "SITES"]) {
    requireSafe(
      /^[0-9a-f-]{36}$/.test(config[prefix + "_READER_ID"]) &&
        config[prefix + "_READER_KEY"].length >= 32,
      "invalid_reader_configuration",
    );
  }
  requireSafe(
    config.STORAGE_READER_ID !== config.SITES_READER_ID &&
      config.STORAGE_READER_KEY !== config.SITES_READER_KEY,
    "shared_source_reader_rejected",
  );
  requireSafe(
    config.B2_READ_KEY_ID !== config.B2_WRITE_KEY_ID,
    "shared_b2_key_rejected",
  );
  if (env.DATABASE_BACKUP_ENABLED === "true") {
    config.databaseUrl = env.DATABASE_READER_URL;
    config.databaseRole =
      validateDatabaseUrl(config.databaseUrl, scope.projectRef).role;
    config.databaseCa = validateDatabaseCa(env.DATABASE_SSL_CA);
  }
  return config;
}

export function validateDatabaseCa(value) {
  requireSafe(
    typeof value === "string" && value.length <= 16384 &&
      /^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*$/
        .test(value),
    "database_ca_invalid",
  );
  let certificate;
  try {
    certificate = new X509Certificate(value);
  } catch {
    requireSafe(false, "database_ca_invalid");
  }
  requireSafe(
    certificate.ca && Date.parse(certificate.validFrom) <= Date.now() &&
      Date.parse(certificate.validTo) > Date.now(),
    "database_ca_invalid",
  );
  return value;
}

export function validateDatabaseUrl(value, projectRef) {
  requireSafe(
    /^[a-z0-9]{20}$/.test(projectRef) && projectRef !== "ozryyalyaquujtfaudzi",
    "database_stage_required",
  );
  let url;
  try {
    url = new URL(value);
  } catch {
    requireSafe(false, "database_configuration_invalid");
  }
  let username, password;
  try {
    username = decodeURIComponent(url.username);
    password = decodeURIComponent(url.password);
  } catch {
    requireSafe(false, "database_configuration_invalid");
  }
  const pooler = url.hostname.endsWith(".pooler.supabase.com");
  const role = pooler ? username.slice(0, -(projectRef.length + 1)) : username;
  requireSafe(
    ["postgres:", "postgresql:"].includes(url.protocol) &&
      url.pathname === "/postgres" && !url.search && !url.hash &&
      (!url.port || url.port === "5432"),
    "database_configuration_invalid",
  );
  requireSafe(
    pooler
      ? /^aws-[0-9]+-[a-z0-9-]+\.pooler\.supabase\.com$/.test(url.hostname) &&
        username === role + "." + projectRef
      : url.hostname === "db." + projectRef + ".supabase.co",
    "database_origin_rejected",
  );
  requireSafe(
    /^xfinder_db_bak_stg_[0-9]{8}_[a-f0-9]{8}$/.test(role) &&
      password.length >= 48,
    "database_reader_rejected",
  );
  return { url, role };
}

export const DATABASE_SCHEMAS = [
  "public",
  "private",
  "auth",
  "storage",
  "supabase_migrations",
];
const DB_NAMES = DATABASE_SCHEMAS.map((name) => "'" + name + "'").join(",");
export const DATABASE_CATALOG_SQL = `select jsonb_build_object(
 'locale',(select jsonb_build_array(datcollate,datctype,datlocprovider,datlocale,pg_encoding_to_char(encoding),datcollversion) from pg_database where datname=current_database()),
 'extensions',(select jsonb_agg(jsonb_build_array(extname,extversion) order by extname) from pg_extension),
 'tables',(select jsonb_agg(jsonb_build_array(n.nspname,c.relname,c.relrowsecurity,c.relforcerowsecurity,pg_get_userbyid(c.relowner),
 has_table_privilege('anon',c.oid,'SELECT'),has_table_privilege('anon',c.oid,'INSERT'),has_table_privilege('anon',c.oid,'UPDATE'),has_table_privilege('anon',c.oid,'DELETE'),
 has_table_privilege('authenticated',c.oid,'SELECT'),has_table_privilege('authenticated',c.oid,'INSERT'),has_table_privilege('authenticated',c.oid,'UPDATE'),has_table_privilege('authenticated',c.oid,'DELETE'),has_table_privilege('service_role',c.oid,'SELECT')) order by n.nspname,c.relname)
 from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname in (${DB_NAMES}) and c.relkind in ('r','p')),
 'columns',(select jsonb_agg(jsonb_build_array(table_schema,table_name,column_name,data_type,is_nullable,column_default) order by table_schema,table_name,ordinal_position) from information_schema.columns where table_schema in (${DB_NAMES})),
 'policies',(select jsonb_agg(jsonb_build_array(schemaname,tablename,policyname,permissive,roles,cmd,qual,with_check) order by schemaname,tablename,policyname) from pg_policies where schemaname in (${DB_NAMES})),
 'functions',(select jsonb_agg(jsonb_build_array(n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),p.prosrc,p.prosecdef,p.proconfig,pg_get_userbyid(p.proowner),has_function_privilege('anon',p.oid,'EXECUTE'),has_function_privilege('authenticated',p.oid,'EXECUTE'),has_function_privilege('service_role',p.oid,'EXECUTE')) order by n.nspname,p.proname,pg_get_function_identity_arguments(p.oid)) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname in (${DB_NAMES})),
 'constraints',(select jsonb_agg(jsonb_build_array(n.nspname,c.relname,k.conname,pg_get_constraintdef(k.oid)) order by n.nspname,c.relname,k.conname) from pg_constraint k join pg_class c on c.oid=k.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname in (${DB_NAMES})),
 'migrations',(select jsonb_agg(version order by version) from supabase_migrations.schema_migrations)) as catalog`;
// Provider XML is parsed without DTDs, external entities, or recursive entity expansion.
export function xmlText(value) {
  requireSafe(!/<!DOCTYPE|<!ENTITY/i.test(value), "unsafe_xml");
  return value.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (_, s) => {
    if (s[0] === "#") {
      const n = s[1] === "x" ? parseInt(s.slice(2), 16) : Number(s.slice(1));
      requireSafe(
        n > 0 && n <= 0x10ffff && !(n >= 0xd800 && n <= 0xdfff),
        "invalid_xml_codepoint",
      );
      return String.fromCodePoint(n);
    }
    return { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" }[s];
  });
}
const tag = (xml, name) => {
  const m = xml.match(new RegExp("<" + name + ">([\\s\\S]*?)</" + name + ">"));
  requireSafe(m, "missing_s3_field");
  return xmlText(m[1]);
};
export function parseR2List(xml) {
  requireSafe(
    !/<!DOCTYPE|<!ENTITY/i.test(xml) && xml.includes("<ListBucketResult"),
    "invalid_s3_listing",
  );
  const objects = [...xml.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g)].map(
    (m) => ({
      key: tag(m[1], "Key"),
      size: Number(tag(m[1], "Size")),
      etag: normalizeEtag(tag(m[1], "ETag")),
      last_modified: tag(m[1], "LastModified"),
    }),
  );
  for (const item of objects) {
    requireSafe(
      Number.isSafeInteger(item.size) && item.size >= 0,
      "invalid_s3_size",
    );
  }
  const truncated = tag(xml, "IsTruncated");
  requireSafe(
    truncated === "true" || truncated === "false",
    "invalid_s3_cursor",
  );
  return {
    objects,
    next: truncated === "true" ? tag(xml, "NextContinuationToken") : null,
  };
}
export async function snapshot(
  {
    scope,
    storage,
    r2,
    kv,
    b2,
    encrypter,
    now = Date.now(),
    mode = "backup",
    recoveryPacks = false,
    database,
    log = () => {},
  },
) {
  requireSafe(["inventory", "backup"].includes(mode), "invalid_mode");
  const runId = new Date(now).toISOString().replace(/[:.]/g, "-") + "-" +
    randomUUID();
  const retainUntil = now + 31 * DAY, minimumUntil = now + 30 * DAY;
  const existing = await b2.inventory();
  let used = existing.bytes;
  requireSpace(used, 0);
  const catalog = await storage.list(),
    cloud = await r2.list(),
    keys = await kv.list();
  requireSafe(
    Array.isArray(catalog.buckets) && Array.isArray(catalog.objects),
    "invalid_storage_catalog",
  );
  const records = [
    ...catalog.objects.map((item) => ({
      kind: "storage",
      item,
      name: objectName("storage", [
        item.id,
        item.bucket,
        item.name,
        item.updated,
        item.size,
        item.etag,
      ]),
    })),
    ...cloud.map((item) => ({
      kind: "r2",
      item,
      name: objectName("r2", [
        item.key,
        item.size,
        item.etag,
        item.last_modified,
      ]),
    })),
    ...keys.map((item) => ({
      kind: "kv",
      item,
      name: objectName("kv", [runId, item.name]),
    })),
  ];
  const stats = {
    storage: 0,
    r2: 0,
    kv: 0,
    reused: 0,
    uploaded: 0,
    ciphertextSamples: 0,
  };
  const recovery = scope.recoveryObject;
  const extraCredentials = [...existing.files.keys()].filter((name) =>
    /^staging\/credentials\/[a-zA-Z0-9_-]+\.age$/.test(name) &&
    !b2.keyIds.some((id) => name === "staging/credentials/" + id + ".age")
  );
  const material = [
    recovery,
    ...b2.keyIds.map((id) => "staging/credentials/" + id + ".age"),
    ...extraCredentials,
  ];
  for (const name of material) {
    requireSafe(existing.files.has(name), "recovery_material_not_archived");
  }
  const estimate =
    records.filter((r) => !existing.files.has(r.name)).reduce((n, r) => {
      const size = r.kind === "kv" ? 32768 : Number(r.item.size);
      requireSafe(
        Number.isSafeInteger(size) && size >= 0 && size <= 64 * 1024 * 1024,
        "source_size_limit",
      );
      return n + size + 2048;
    }, 0) + 16 * 1024 * 1024 + (database ? 80 * 1024 * 1024 : 0);
  requireSpace(used, estimate);
  for (const bucket of catalog.buckets.filter((b) => !b.public)) {
    const item = catalog.objects.find((i) => i.bucket === bucket.id);
    if (item) {
      const probe = await storage.read(item);
      requireSafe(
        probe.bytes.length === Number(item.size),
        "private_storage_preflight_size",
      );
    }
  }
  if (cloud.length) {
    const probe = await r2.read(cloud[0]);
    requireSafe(probe.bytes.length === cloud[0].size, "r2_preflight_size");
  }
  if (keys.length) await kv.read(keys[0]);
  if (database) await database.inspect();
  const preflight = {
    environment: "staging",
    mode,
    records: records.length,
    storedBytes: used,
    projectedAdditionalBytes: estimate,
    paidUsageAuthorized: false,
  };
  if (mode === "inventory") {
    return { status: "inventory_verified", ...preflight };
  }
  const sources = { storage, r2, kv };
  const kvCapture = new Map();
  const out = new Array(records.length), samples = [];
  let next = 0, done = 0, failure;
  async function preserve(file) {
    requireSafe(file.mode === "compliance", "existing_object_unprotected");
    if (file.until < minimumUntil) {
      await b2.extend(file, retainUntil);
      file.until = retainUntil;
    }
  }
  async function upload(name, bytes, sourceDigest, slot) {
    requireSpace(used, bytes.length);
    used += bytes.length;
    const file = await b2.put(name, bytes, {
      until: retainUntil,
      sourceDigest,
      slot,
    });
    stats.uploaded++;
    return file;
  }
  for (const name of material) await preserve(existing.files.get(name));
  let databaseCopy;
  if (database) {
    const captured = await database.capture();
    let contextBytes;
    try {
      requireSafe(
        captured.dump instanceof Uint8Array && captured.dump.length > 5 &&
          captured.dump.length <= 63 * 1024 * 1024 &&
          Buffer.from(captured.dump.subarray(0, 5)).toString() === "PGDMP",
        "database_dump_invalid",
      );
      requireSafe(
        captured.context?.environment === "staging" &&
          captured.context.projectRef === scope.projectRef &&
          captured.context.counts?.length > 0 &&
          captured.context.roles?.every((role) =>
            !Object.keys(role).some((key) => /password|secret|token/i.test(key))
          ),
        "database_context_invalid",
      );
      requireSafe(
        Number.isFinite(Date.parse(captured.context.capturedAt)) &&
          Date.parse(captured.context.capturedAt) <= Date.now() + 300000,
        "database_capture_time_invalid",
      );
      contextBytes = Buffer.from(JSON.stringify(captured.context));
      requireSafe(
        contextBytes.length <= 16 * 1024 * 1024,
        "database_context_size_limit",
      );
      const dumpObject = "staging/database/" + runId + "/database.dump.age";
      const contextObject = "staging/database/" + runId + "/context.age";
      const dumpHash = digest(captured.dump),
        contextHash = digest(contextBytes);
      const dumpFile = await upload(
        dumpObject,
        await encrypter.encrypt(captured.dump),
        undefined,
        0,
      );
      const contextFile = await upload(
        contextObject,
        await encrypter.encrypt(contextBytes),
        undefined,
        0,
      );
      databaseCopy = {
        format: "xfinder-postgres-backup-v1",
        projectRef: scope.projectRef,
        capturedAt: captured.context.capturedAt,
        tables: captured.context.counts.length,
        dump: { object: dumpObject, size: dumpFile.size, digest: dumpHash },
        context: {
          object: contextObject,
          size: contextFile.size,
          digest: contextHash,
        },
      };
    } finally {
      captured.dump?.fill(0);
      contextBytes?.fill(0);
    }
  }
  await Promise.all(Array.from({ length: 4 }, (_, slot) =>
    (async () => {
      try {
        while (!failure) {
          const index = next++;
          if (index >= records.length) return;
          const record = records[index], old = existing.files.get(record.name);
          let destination;
          if (old) {
            await preserve(old);
            requireSafe(
              typeof old.sourceDigest === "string",
              "missing_source_integrity",
            );
            stats.reused++;
            destination = {
              object: record.name,
              fileId: old.id,
              size: old.size,
              sourceDigest: old.sourceDigest,
            };
          } else {
            const input = await sources[record.kind].read(record.item),
              bytes = input.bytes;
            requireSafe(
              bytes instanceof Uint8Array && bytes.length <= 64 * 1024 * 1024,
              "source_size_limit",
            );
            if (record.kind !== "kv") {
              requireSafe(
                bytes.length === Number(record.item.size),
                "source_size_changed",
              );
            }
            if (record.item.etag && input.etag) {
              requireSafe(
                normalizeEtag(record.item.etag) === normalizeEtag(input.etag),
                "source_etag_changed",
              );
            }
            const hash = digest(bytes),
              ciphertext = await encrypter.encrypt(bytes);
            if (record.kind === "kv" && recoveryPacks) {
              kvCapture.set(index, Buffer.from(bytes));
            }
            const file = await upload(record.name, ciphertext, hash, slot);
            destination = {
              object: record.name,
              fileId: file.id,
              size: ciphertext.length,
              sourceDigest: hash,
            };
            if (samples.length < 3 && ciphertext.length < 1024 * 1024) {
              samples.push({ name: record.name, hash: digest(ciphertext) });
            }
          }
          out[index] = { kind: record.kind, source: record.item, destination };
          stats[record.kind]++;
          done++;
          if (done % 1000 === 0) {
            log({ phase: "copy", completed: done, total: records.length });
          }
        }
      } catch (e) {
        failure ??= e;
      }
    })()));
  if (failure) throw failure;
  const packs = [];
  if (recoveryPacks) {
    // Stable hash partitions avoid repacking the whole collection on one edit.
    // The encrypted v1 records remain usable by legacy restore tools.
    const partitions = new Map();
    for (const [index, record] of out.entries()) {
      const partition = record.kind + "/" +
        record.destination.object.split("/").at(-1).slice(0, 2);
      if (!partitions.has(partition)) partitions.set(partition, []);
      partitions.get(partition).push({ index, record });
    }
    const groups = [];
    for (const entries of partitions.values()) {
      entries.sort((a, b) =>
        a.record.destination.object.localeCompare(b.record.destination.object)
      );
      let group = [], size = 0;
      for (const entry of entries) {
        const bytes = entry.record.kind === "kv"
          ? kvCapture.get(entry.index)?.length
          : Number(entry.record.source.size);
        requireSafe(
          Number.isSafeInteger(bytes) && bytes >= 0 && bytes < 64 * 1024 * 1024,
          "recovery_pack_source_size",
        );
        if (group.length && size + bytes > 32 * 1024 * 1024) {
          groups.push(group);
          group = [];
          size = 0;
        }
        group.push({ ...entry, bytes });
        size += bytes;
      }
      if (group.length) groups.push(group);
    }
    requireSafe(groups.length <= 1500, "recovery_pack_request_limit");
    const planned = groups.map((group) => {
      const identity = group.map((
        { record, bytes },
      ) => [record.destination.object, record.destination.sourceDigest, bytes]);
      return {
        group,
        object: "staging/recovery-packs/" + digest(JSON.stringify(identity)) +
          ".age",
      };
    });
    requireSpace(
      used,
      planned.filter((p) => !existing.files.has(p.object)).reduce(
        (sum, p) => sum + p.group.reduce((n, e) => n + e.bytes, 0) + 8192,
        0,
      ),
    );
    let packIndex = 0;
    await Promise.all(Array.from({ length: 2 }, (_, slot) =>
      (async () => {
        while (!failure) {
          const index = packIndex++;
          if (index >= planned.length) return;
          try {
            const { group, object } = planned[index];
            let offset = 0;
            const parts = group.map((entry) => {
              const part = { index: entry.index, offset, length: entry.bytes };
              offset += entry.bytes;
              return part;
            });
            const old = existing.files.get(object);
            let size;
            if (old) {
              await preserve(old);
              size = old.size;
            } else {
              const buffers = [];
              for (let start = 0; start < group.length; start += 4) {
                const batch = await Promise.all(
                  group.slice(start, start + 4).map(
                    async (
                      { index: recordIndex, record, bytes: expectedSize },
                    ) => {
                      const data = record.kind === "kv"
                        ? kvCapture.get(recordIndex)
                        : (await sources[record.kind].read(record.source))
                          .bytes;
                      requireSafe(
                        data.length === expectedSize &&
                          digest(data) === record.destination.sourceDigest,
                        "recovery_pack_source_changed",
                      );
                      return Buffer.from(data);
                    },
                  ),
                );
                buffers.push(...batch);
              }
              const clear = Buffer.concat(buffers);
              buffers.forEach((buffer) => buffer.fill(0));
              const encrypted = await encrypter.encrypt(clear);
              const packHash = digest(clear);
              clear.fill(0);
              size = (await upload(object, encrypted, packHash, slot)).size;
            }
            packs[index] = { object, size, parts };
            log({
              phase: "recovery_pack",
              completed: packs.filter(Boolean).length,
              total: planned.length,
            });
          } catch (error) {
            failure ||= error;
          }
        }
      })()));
    if (failure) throw failure;
  }
  requireSafe(
    JSON.stringify(catalog) === JSON.stringify(await storage.list()),
    "storage_changed_during_backup",
  );
  requireSafe(
    JSON.stringify(cloud) === JSON.stringify(await r2.list()),
    "r2_changed_during_backup",
  );
  for (const sample of samples) {
    requireSafe(
      digest(await b2.read(sample.name, 1024 * 1024)) === sample.hash,
      "ciphertext_sample_mismatch",
    );
    stats.ciphertextSamples++;
  }
  const completedAt = new Date().toISOString();
  const manifest = {
    format: "xfinder-age-backup-v1",
    environment: "staging",
    runId,
    startedAt: new Date(now).toISOString(),
    completedAt,
    source: {
      supabase: scope.projectRef,
      r2: scope.r2Bucket,
      kv: scope.kvNamespace,
    },
    buckets: catalog.buckets,
    records: out,
    ...(databaseCopy ? { database: databaseCopy } : {}),
    ...(recoveryPacks ? { recoveryPacks: packs } : {}),
    recovery: { object: recovery },
    credentialCopies: b2.keyIds.map((keyId) => ({
      keyId,
      object: "staging/credentials/" + keyId + ".age",
    })),
    ...(extraCredentials.length
      ? {
        additionalCredentialCopies: extraCredentials.map((object) => ({
          keyId: object.split("/").at(-1).slice(0, -4),
          object,
        })),
      }
      : {}),
    retentionUntil: new Date(minimumUntil).toISOString(),
    captureConsistency: {
      storageCatalogStable: true,
      r2ListingStable: true,
      kvAtomic: false,
    },
  };
  const manifestName = "staging/snapshots/" + runId + "/manifest.age";
  await upload(
    manifestName,
    await encrypter.encrypt(Buffer.from(JSON.stringify(manifest))),
    undefined,
    0,
  );
  const verified = await b2.inventory();
  requireSpace(verified.bytes, 0);
  for (
    const name of [
      ...material,
      ...out.map((r) => r.destination.object),
      ...packs.map((pack) => pack.object),
      manifestName,
      ...(databaseCopy
        ? [databaseCopy.dump.object, databaseCopy.context.object]
        : []),
    ]
  ) {
    const file = verified.files.get(name);
    requireSafe(
      file?.mode === "compliance" && file.until >= minimumUntil,
      "snapshot_retention_unverified",
    );
  }
  used = verified.bytes;
  const health = {
    format: "xfinder-backup-health-v1",
    environment: "staging",
    completedAt,
    records: records.length,
    storedBytes: used,
    capacityWarning: used >= 8_000_000_000,
    ...(databaseCopy
      ? {
        databaseCapturedAt: databaseCopy.capturedAt,
        databaseTables: databaseCopy.tables,
      }
      : {}),
  };
  // This contains only operational counters/time, so an independent watchdog needs no recovery key.
  const healthBytes = Buffer.from(JSON.stringify(health));
  requireSpace(used, healthBytes.length);
  await upload("staging/health/success.json", healthBytes, undefined, 0);
  return {
    status: "snapshot_committed",
    ...preflight,
    manifest: manifestName,
    completedAt,
    stats,
    storedBytes: used,
    capacityWarning: used >= 8_000_000_000,
    fullServiceRecoveryVerified: false,
  };
}

// Minimal operational telemetry; no paths, configuration or secrets are published.
export async function recordAttempt(b2, conclusion, now = Date.now()) {
  requireSafe(
    ["success", "failure"].includes(conclusion),
    "invalid_attempt_conclusion",
  );
  const bytes = Buffer.from(
    JSON.stringify({
      format: "xfinder-backup-attempt-v1",
      environment: "staging",
      completedAt: new Date(now).toISOString(),
      conclusion,
    }),
  );
  const existing = await b2.inventory();
  requireSpace(existing.bytes, bytes.length);
  await b2.put("staging/health/attempt.json", bytes, {
    until: now + 31 * DAY,
    slot: 0,
  });
}
