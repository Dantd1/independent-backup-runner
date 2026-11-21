import { AwsClient } from "aws4fetch";
import { createHash, createHmac } from "node:crypto";
import { Buffer } from "node:buffer";
import process from "node:process";
import postgres from "postgres";
import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { lookup } from "node:dns/promises";
import {
  b2Url,
  DATABASE_CATALOG_SQL,
  requireSafe,
  sourcePath,
  validateDatabaseUrl,
} from "./core.mjs";
export const DATABASE_IMAGE = "public.ecr.aws/supabase/postgres:17.6.1.166";
export const DATABASE_CLIENT_IMAGE =
  "postgres@sha256:a77aa70e641402a21411b92b721c58d10f23b50ae5fdd2333efd22d166e1e5f7";
const quoteIdentifier = (value) => '"' + value.replaceAll('"', '""') + '"';

export const DATABASE_WRITE_SCOPE_SQL = `with rights as (
 select n.nspname,c.relname,c.relkind,
 case when c.relkind='S' then has_sequence_privilege(current_user,c.oid,'USAGE,UPDATE')
 else has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') end as writable
 from pg_class c join pg_namespace n on n.oid=c.relnamespace
 where c.relkind in ('r','p','v','m','f','S') and n.nspname !~ '^pg_' and n.nspname<>'information_schema'
), classified as (
 select *,((nspname='net' and relname in ('http_request_queue','_http_response','http_request_queue_id_seq'))
 or (nspname='cron' and relname='job_run_details')) as managed from rights
)
select jsonb_build_object(
 'unsafe_tables',count(*) filter(where writable and relkind<>'S' and not managed),
 'unsafe_sequences',count(*) filter(where writable and relkind='S' and not managed),
 'managed_tables',count(*) filter(where writable and relkind<>'S' and managed),
 'managed_sequences',count(*) filter(where writable and relkind='S' and managed),
 'managed_functions',(select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace
   where n.nspname in ('net','cron') and has_schema_privilege(current_user,n.oid,'USAGE')
   and has_function_privilege(current_user,p.oid,'EXECUTE'))
) as scope from classified`;
export function assertDatabaseWriteScope(
  scope,
  { allowManagedPublicWrites = false } = {},
) {
  const fields = [
    "unsafe_tables",
    "unsafe_sequences",
    "managed_tables",
    "managed_sequences",
    "managed_functions",
  ];
  requireSafe(
    scope &&
      fields.every((key) =>
        Number.isSafeInteger(scope[key]) && scope[key] >= 0
      ),
    "database_scope_inspection_required",
  );
  requireSafe(
    scope.unsafe_tables === 0 && scope.unsafe_sequences === 0,
    "database_application_write_privileges_denied",
  );
  requireSafe(
    allowManagedPublicWrites ||
      fields.slice(2).every((key) => scope[key] === 0),
    "database_managed_public_writes_unapproved",
  );
}
export async function inspectDatabase(sql, projectRef, role, options = {}) {
  requireSafe(
    /^[a-z0-9]{20}$/.test(projectRef) && projectRef !== "ozryyalyaquujtfaudzi",
    "database_stage_required",
  );
  const [source] = await sql.unsafe(
    `select current_user as role,current_database() as database,
    current_setting('server_version_num')::integer as version,
    current_setting('transaction_read_only') as read_only,
    (select row_to_json(e) from private.xfinder_environment e where id=1) as marker,
    (select jsonb_build_object('super',rolsuper,'bypass',rolbypassrls,'createRole',rolcreaterole,'createDb',rolcreatedb,'replication',rolreplication,'expires',rolvaliduntil>clock_timestamp()) from pg_roles where rolname=current_user) as privileges,
    (select count(*)::integer from pg_proc p join pg_namespace n on n.oid=p.pronamespace
      where p.prosecdef and n.nspname not in ('pg_catalog','information_schema')
      and not(n.nspname='extensions' and p.proname='st_estimatedextent' and pg_get_function_identity_arguments(p.oid) in ('text, text','text, text, text','text, text, text, boolean'))
      and has_function_privilege(current_user,p.oid,'EXECUTE')) as unsafe_definers`,
  );
  requireSafe(
    projectRef !== "ozryyalyaquujtfaudzi" &&
      source.marker?.environment === "staging" &&
      source.marker.project_ref === projectRef,
    "database_environment_denied",
  );
  requireSafe(
    source.role === role &&
      /^xfinder_db_bak_stg_[0-9]{8}_[a-f0-9]{8}$/.test(role) &&
      source.database === "postgres" && source.version >= 170000 &&
      source.version < 180000,
    "database_identity_denied",
  );
  requireSafe(
    !source.privileges.super && source.privileges.bypass &&
      !source.privileges.createRole && !source.privileges.createDb &&
      !source.privileges.replication && source.privileges.expires &&
      source.read_only === "on" && source.unsafe_definers === 0,
    "database_privileges_denied",
  );
  const [rights] = await sql.unsafe(DATABASE_WRITE_SCOPE_SQL);
  assertDatabaseWriteScope(rights.scope, options);
  return { ...source, writeScope: rights.scope };
}

// The exported transaction remains open until pg_dump has consumed its snapshot.
export function captureDatabase(
  sql,
  projectRef,
  role,
  dump,
  { heartbeatMs = 30000, allowManagedPublicWrites = false } = {},
) {
  requireSafe(
    /^[a-z0-9]{20}$/.test(projectRef) && projectRef !== "ozryyalyaquujtfaudzi",
    "database_stage_required",
  );
  const abort = new AbortController();
  return sql.begin("isolation level repeatable read read only", async (tx) => {
    const progress = (phase) => console.log(JSON.stringify({ phase }));
    progress("database_inspection");
    await tx.unsafe(
      "set local row_security=off;set local search_path=pg_catalog;set local extra_float_digits=3",
    );
    await inspectDatabase(tx, projectRef, role, { allowManagedPublicWrites });
    const [snapshot] = await tx.unsafe(
      "select pg_export_snapshot() as snapshot,clock_timestamp()::text as captured_at",
    );
    progress("database_catalog");
    requireSafe(
      /^[0-9a-f-]+$/i.test(snapshot.snapshot),
      "database_snapshot_invalid",
    );
    const [{ catalog }] = await tx.unsafe(DATABASE_CATALOG_SQL);
    const tables = await tx.unsafe(
      `select n.nspname as schema,c.relname as name from pg_class c join pg_namespace n on n.oid=c.relnamespace where c.relkind in ('r','p') and n.nspname !~ '^pg_' and n.nspname not in ('information_schema','vault','net','cron','pgsodium') order by 1,2`,
    );
    const counts = [];
    progress("database_row_counts");
    for (let start = 0; start < tables.length; start += 20) {
      const batch = tables.slice(start, start + 20);
      const rows = await tx.unsafe(
        batch.map((table, index) =>
          `select ${index}::integer as item,count(*)::text as rows from ${
            quoteIdentifier(table.schema)
          }.${quoteIdentifier(table.name)}`
        ).join(" union all "),
      );
      counts.push(
        ...rows.map((row) => ({ ...batch[row.item], rows: row.rows })),
      );
    }
    const roles = await tx.unsafe(
      "select rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls from pg_roles where rolname !~ '^pg_' and rolname<>'postgres' order by rolname",
    );
    progress("database_role_metadata");
    const memberships = await tx.unsafe(
      "select parent.rolname as parent,member.rolname as member,m.admin_option,m.inherit_option,m.set_option from pg_auth_members m join pg_roles parent on parent.oid=m.roleid join pg_roles member on member.oid=m.member order by 1,2",
    );
    const extensionFunctions = await tx.unsafe(
      `select n.nspname,p.proname,pg_get_function_identity_arguments(p.oid) as arguments,pg_get_userbyid(p.proowner) as owner from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname in ('public','private','auth','storage','supabase_migrations') and exists(select 1 from pg_depend d where d.classid='pg_proc'::regclass and d.objid=p.oid and d.deptype='e')`,
    );
    progress("database_dump");
    // Keep the exporting transaction alive while a separate pg_dump connects.
    // Closing that transaction invalidates the snapshot; abort the dump as well.
    let busy = false, heartbeatFailure;
    const heartbeat = setInterval(() => {
      if (busy || abort.signal.aborted) return;
      busy = true;
      tx.unsafe("select 1").catch((error) => {
        heartbeatFailure = error;
        abort.abort();
      }).finally(() => {
        busy = false;
      });
    }, heartbeatMs);
    let bytes;
    try {
      bytes = await dump(snapshot.snapshot, abort.signal);
      if (heartbeatFailure) throw heartbeatFailure;
    } finally {
      clearInterval(heartbeat);
    }
    progress("database_dump_complete");
    return {
      dump: bytes,
      context: {
        format: "xfinder-postgres-context-v1",
        environment: "staging",
        projectRef,
        readerRole: role,
        capturedAt: new Date(snapshot.captured_at).toISOString(),
        catalog,
        counts,
        roles,
        memberships,
        extensionFunctions,
        excludedTableData: ["vault.*", "net.*", "cron.*", "pgsodium.*"],
        passwordsExportedAsRoles: false,
      },
    };
  }).catch((error) => {
    abort.abort();
    const codes = {
      "57014": "database_statement_timeout",
      "25P03": "database_idle_transaction_timeout",
      "42501": "database_permission_denied",
      "0A000": "database_feature_unsupported",
      "53300": "database_connection_limit",
      "CONNECTION_CLOSED": "database_connection_closed",
      "CONNECT_TIMEOUT": "database_connect_timeout",
      "CONNECTION_ENDED": "database_connection_ended",
    };
    if (!error.safeCode) {
      error.safeCode = codes[error.code] ?? "database_capture_failed";
    }
    throw error;
  });
}

async function dockerDump(url, snapshot, ca, signal, { probe = false } = {}) {
  const name = "xfinder-db-dump-" + randomUUID();
  let hostAddress;
  if (url.hostname.endsWith(".pooler.supabase.com")) {
    let timer;
    try {
      const answer = await Promise.race([
        lookup(url.hostname, { family: 4 }),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(Error("dns_timeout")), 10000);
        }),
      ]);
      hostAddress = answer.address;
    } catch {
      const error = Error("database_dns_unavailable");
      error.safeCode = "database_dns_unavailable";
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }
  const env = {
    ...process.env,
    PGHOST: url.hostname,
    ...(hostAddress ? { PGHOSTADDR: hostAddress } : {}),
    PGPORT: url.port || "5432",
    PGUSER: decodeURIComponent(url.username),
    PGPASSWORD: decodeURIComponent(url.password),
    PGDATABASE: "postgres",
    PGSSLMODE: "verify-full",
    // Supavisor documents GSSAPI negotiation as unsupported; TLS remains mandatory.
    PGGSSENCMODE: "disable",
    PGCONNECT_TIMEOUT: "20",
    PGSSLROOTCERT: "/tmp/database-root.crt",
    DATABASE_SSL_CA: ca,
    PGOPTIONS:
      "-c default_transaction_read_only=on -c statement_timeout=120000",
  };
  const args = [
    "run",
    "--rm",
    "--name",
    name,
    "--network",
    "host",
    "--read-only",
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,nodev,size=4m,mode=1777",
    "--user",
    "postgres",
    ...[
      "PGHOST",
      ...(hostAddress ? ["PGHOSTADDR"] : []),
      "PGPORT",
      "PGUSER",
      "PGPASSWORD",
      "PGDATABASE",
      "PGSSLMODE",
      "PGGSSENCMODE",
      "PGCONNECT_TIMEOUT",
      "PGSSLROOTCERT",
      "PGOPTIONS",
      "DATABASE_SSL_CA",
    ].flatMap((key) => ["--env", key]),
    "--entrypoint",
    "sh",
    DATABASE_CLIENT_IMAGE,
    "-c",
    'umask 077; printf "%s" "$DATABASE_SSL_CA" > "$PGSSLROOTCERT" && printf "xfinder-client-ready\\n" >&2 && exec "$@"',
    "postgres-client",
    ...(probe
      ? [
        "psql",
        "--no-password",
        "--no-psqlrc",
        "--tuples-only",
        "--no-align",
        "--command=select 1",
      ]
      : [
        "pg_dump",
        "--format=custom",
        "--compress=6",
        "--no-password",
        "--verbose",
        "--lock-wait-timeout=120s",
        "--snapshot=" + snapshot,
        ...["vault.*", "net.*", "cron.*", "pgsodium.*"].map((value) =>
          "--exclude-table-data=" + value
        ),
      ]),
  ];
  try {
    return await new Promise((resolve, reject) => {
      const child = spawn("docker", args, {
        env,
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
      });
      const stop = () => {
        failed = true;
        // Docker forwards SIGTERM to the client; SIGKILL closes our CLI promptly.
        // finally removes only this UUID-scoped container, including its client.
        child.kill("SIGKILL");
      };
      const chunks = [];
      let size = 0, failed = false, diagnostic = "";
      let clientStarted = false, clientConnected = false;
      let lastOperation = "startup";
      const seenOperations = new Set();
      let deadlineCode;
      const startupDeadline = setTimeout(() => {
        if (!clientStarted) {
          deadlineCode = "database_client_start_timeout";
          stop();
        }
      }, 30000);
      const connectDeadline = setTimeout(() => {
        if (!clientConnected) {
          deadlineCode = "database_client_connect_timeout";
          stop();
        }
      }, 60000);
      const timer = setTimeout(() => {
        deadlineCode = "database_dump_timeout";
        failed = true;
        child.kill("SIGKILL");
      }, 900000);
      signal?.addEventListener("abort", stop, { once: true });
      if (signal?.aborted) stop();
      child.stderr.on("data", (chunk) => {
        const part = chunk.toString();
        const operations = {
          "reading extensions": "extensions",
          "reading schemas": "schemas",
          "reading user-defined tables": "tables",
          "reading user-defined functions": "functions",
          "reading column info": "columns",
          "reading indexes": "indexes",
          "reading constraints": "constraints",
          "reading policies": "policies",
          "reading dependency data": "dependencies",
          "reading subscriptions": "subscriptions",
          "saving database definition": "database_definition",
          "dumping contents of table": "table_data",
        };
        for (const [pattern, operation] of Object.entries(operations)) {
          if (part.includes(pattern)) {
            lastOperation = operation;
            if (!seenOperations.has(operation)) {
              seenOperations.add(operation);
              console.log(
                JSON.stringify({ phase: "database_metadata_" + operation }),
              );
            }
          }
        }
        if (!clientStarted && part.includes("xfinder-client-ready")) {
          clientStarted = true;
          console.log(JSON.stringify({ phase: "database_client_started" }));
        }
        if (
          !clientConnected && /pg_dump: (reading|last built-in OID)/.test(part)
        ) {
          clientConnected = true;
          console.log(JSON.stringify({ phase: "database_client_connected" }));
        }
        diagnostic = (diagnostic + part).slice(-8192);
      });
      child.stdout.on("data", (chunk) => {
        if (probe && chunk.toString().trim() === "1") clientConnected = true;
        size += chunk.length;
        if (size > 63 * 1024 * 1024) {
          deadlineCode = "database_dump_size_limit";
          failed = true;
          child.kill("SIGKILL");
        } else chunks.push(chunk);
      });
      child.on("error", () => {
        failed = true;
      });
      child.on("close", (code) => {
        signal?.removeEventListener("abort", stop);
        clearTimeout(startupDeadline);
        clearTimeout(connectDeadline);
        clearTimeout(timer);
        if (failed || code !== 0) {
          chunks.forEach((chunk) => chunk.fill(0));
          const error = Error("database_dump_failed");
          error.safeCode = deadlineCode ??
            (/password authentication failed/i.test(diagnostic)
              ? "database_dump_authentication_failed"
              : /certificate|SSL error/i.test(diagnostic)
              ? "database_dump_tls_failed"
              : /too many connections|connection limit/i.test(diagnostic)
              ? "database_dump_connection_limit"
              : /permission denied/i.test(diagnostic)
              ? "database_dump_permission_denied"
              : /invalid snapshot|snapshot.*does not exist/i.test(diagnostic)
              ? "database_dump_snapshot_failed"
              : /timeout|timed out|connection refused|could not connect|network is unreachable/i
                  .test(diagnostic)
              ? "database_dump_connect_failed"
              : "database_dump_failed");
          diagnostic = "";
          console.error(
            JSON.stringify({
              phase: "database_client_failed",
              code: error.safeCode,
              clientStarted,
              clientConnected,
              lastOperation,
              capturedBytes: size,
            }),
          );
          reject(error);
        } else {
          const bytes = Buffer.concat(chunks);
          chunks.forEach((chunk) => chunk.fill(0));
          resolve(bytes);
        }
      });
    });
  } finally {
    // Only this random, validated container can be removed; no host files exist.
    requireSafe(
      /^xfinder-db-dump-[a-f0-9-]{36}$/.test(name),
      "database_cleanup_denied",
    );
    spawnSync("docker", ["rm", "--force", name], {
      windowsHide: true,
      stdio: "ignore",
      timeout: 15000,
    });
    env.PGPASSWORD = undefined;
  }
}

export function connectDatabase(c) {
  const { url, role } = validateDatabaseUrl(c.databaseUrl, c.scope.projectRef);
  const sql = postgres(c.databaseUrl, {
    max: 1,
    prepare: false,
    ssl: { rejectUnauthorized: true, ca: c.databaseCa },
    onnotice: () => {},
    connection: {
      options:
        "-c default_transaction_read_only=on -c statement_timeout=120000",
    },
  });
  return {
    inspect: () => inspectDatabase(sql, c.scope.projectRef, role, c),
    probe: async () => {
      console.log(JSON.stringify({ phase: "database_native_single_client" }));
      const single = await dockerDump(url, "", c.databaseCa, undefined, {
        probe: true,
      });
      requireSafe(single.toString().trim() === "1", "database_probe_invalid");
      await inspectDatabase(sql, c.scope.projectRef, role, c);
      console.log(JSON.stringify({ phase: "database_native_parallel_client" }));
      const parallel = await dockerDump(url, "", c.databaseCa, undefined, {
        probe: true,
      });
      requireSafe(parallel.toString().trim() === "1", "database_probe_invalid");
      return { status: "database_probe_passed" };
    },
    capture: () =>
      captureDatabase(
        sql,
        c.scope.projectRef,
        role,
        (snapshot, signal) => dockerDump(url, snapshot, c.databaseCa, signal),
        { allowManagedPublicWrites: c.allowManagedPublicWrites },
      ),
    close: () => sql.end({ timeout: 2 }),
  };
}
export function signedReadHeaders(id, secret, body, now = Date.now()) {
  const timestamp = String(now);
  return {
    "content-type": "application/json",
    "x-backup-key-id": id,
    "x-backup-time": timestamp,
    "x-backup-signature": createHmac("sha256", secret).update(
      timestamp + "\n" + body,
    ).digest("hex"),
  };
}
export async function boundedBytes(response, limit = 64 * 1024 * 1024) {
  requireSafe(response.ok, "provider_http_" + response.status);
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    requireSafe(size <= limit, "response_size_limit");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
// Exporter POSTs are authenticated read-only operations. Consume the body inside
// the retry boundary, and regenerate signed headers on every attempt.
export async function retrySourceRead(
  read,
  { pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) } = {},
) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const response = await read();
      if ([404, 429, 500, 502, 503, 504].includes(response.status)) {
        await response.body?.cancel();
        const error = Error("source temporarily unavailable");
        error.safeCode = response.status === 404
          ? "provider_http_404"
          : "source_read_unavailable";
        throw error;
      }
      const bytes = await boundedBytes(response);
      return new Response(bytes, {
        status: response.status,
        headers: response.headers,
      });
    } catch (error) {
      const transport = ["TimeoutError", "AbortError", "TypeError"].includes(
        error.name,
      );
      const transient = transport ||
        ["source_read_unavailable", "provider_http_404"].includes(
          error.safeCode,
        );
      if (!transient) throw error;
      if (attempt === 2) {
        if (error.safeCode === "provider_http_404") {
          requireSafe(false, "provider_http_404");
        }
        requireSafe(
          false,
          transport
            ? "source_read_transport_failed"
            : "source_read_unavailable",
        );
      }
      await pause(1000 * (attempt + 1));
    }
  }
}
export function connectProviders(c, { fetcher = fetch } = {}) {
  const {
    projectRef: STAGE,
    b2Bucket: B2_BUCKET,
    b2Name: B2_NAME,
  } = c.scope;
  const request = (url, options = {}) =>
    fetcher(url, {
      ...options,
      redirect: "error",
      signal: AbortSignal.timeout(45000),
    });
  const json = async (url, options = {}) =>
    JSON.parse(
      (await boundedBytes(await request(url, options))).toString("utf8"),
    );
  const auths = {};
  async function auth(role) {
    if (auths[role]) return auths[role];
    const id = c[role === "read" ? "B2_READ_KEY_ID" : "B2_WRITE_KEY_ID"],
      key = c[role === "read" ? "B2_READ_KEY" : "B2_WRITE_KEY"];
    const result = await json(
      "https://api.backblazeb2.com/b2api/v4/b2_authorize_account",
      {
        headers: {
          Authorization: "Basic " +
            Buffer.from(id + ":" + key).toString("base64"),
        },
      },
    );
    const api = result.apiInfo.storageApi, allowed = api.allowed;
    const capabilities = role === "read"
      ? [
        "listAllBucketNames",
        "listBuckets",
        "listFiles",
        "readFiles",
        "readFileRetentions",
      ]
      : ["writeFiles", "writeFileRetentions"];
    requireSafe(
      allowed.buckets?.length === 1 && allowed.buckets[0].id === B2_BUCKET &&
        allowed.namePrefix === "staging/" &&
        [...allowed.capabilities].sort().join(",") ===
          capabilities.sort().join(","),
      "b2_scope_mismatch",
    );
    requireSafe(
      result.applicationKeyExpirationTimestamp > Date.now(),
      "b2_key_expired",
    );
    auths[role] = { ...api, token: result.authorizationToken };
    return auths[role];
  }
  async function native(role, method, body) {
    const a = await auth(role);
    b2Url(a.apiUrl);
    return json(a.apiUrl + "/b2api/v4/" + method, {
      method: "POST",
      headers: { Authorization: a.token, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  }
  const uploads = new Map();
  const b2 = {
    keyIds: [
      c.B2_WRITE_KEY_ID,
      c.B2_READ_KEY_ID,
      c.STORAGE_READER_ID,
      c.SITES_READER_ID,
      ...(c.databaseRole ? [c.databaseRole] : []),
    ],
    async inventory() {
      await auth("write");
      const reader = await auth("read");
      b2Url(reader.s3ApiUrl);
      const aws = new AwsClient({
        accessKeyId: c.B2_READ_KEY_ID,
        secretAccessKey: c.B2_READ_KEY,
        service: "s3",
        region: "us-east-005",
      });
      const xml = (await boundedBytes(
        await aws.fetch(reader.s3ApiUrl + "/", {
          redirect: "error",
          signal: AbortSignal.timeout(45000),
        }),
        1024 * 1024,
      )).toString();
      const buckets = [...xml.matchAll(/<Name>([^<]+)<\/Name>/g)].map((m) =>
        m[1]
      );
      requireSafe(
        buckets.length === 1 && buckets[0] === B2_NAME,
        "unaccounted_b2_bucket",
      );
      const state = await native("read", "b2_list_buckets", {
        accountId: c.scope.b2Account,
        bucketId: B2_BUCKET,
      });
      requireSafe(
        state.buckets.length === 1 &&
          state.buckets[0].bucketType === "allPrivate",
        "b2_bucket_not_private",
      );
      const files = new Map(), cursors = new Set();
      let bytes = 0, next = {};
      for (let page = 0; page < 100; page++) {
        const result = await native("read", "b2_list_file_versions", {
          bucketId: B2_BUCKET,
          prefix: "staging/",
          maxFileCount: 10000,
          ...next,
        });
        for (const f of result.files) {
          if (f.action === "upload") {
            bytes += f.contentLength;
            if (!files.has(f.fileName)) {
              files.set(f.fileName, {
                id: f.fileId,
                name: f.fileName,
                size: f.contentLength,
                sourceDigest: f.fileInfo?.["xf-source-sha256"],
                mode: f.fileRetention?.value?.mode,
                until: f.fileRetention?.value?.retainUntilTimestamp,
              });
            }
          }
        }
        if (!result.nextFileName) return { bytes, files };
        const cursor = result.nextFileName + "|" + result.nextFileId;
        requireSafe(!cursors.has(cursor), "b2_cursor_repeated");
        cursors.add(cursor);
        next = {
          startFileName: result.nextFileName,
          startFileId: result.nextFileId,
        };
      }
      requireSafe(false, "b2_pagination_limit");
    },
    async extend(f, until) {
      await native("write", "b2_update_file_retention", {
        fileName: f.name,
        fileId: f.id,
        fileRetention: { mode: "compliance", retainUntilTimestamp: until },
      });
    },
    async put(name, bytes, { until, sourceDigest, slot }) {
      requireSafe(
        name.startsWith("staging/") && bytes.length <= 64 * 1024 * 1024 &&
          !name.startsWith("staging/credentials/") &&
          !name.startsWith("staging/recovery/"),
        "upload_scope_rejected",
      );
      let upload = uploads.get(slot);
      if (!upload) {
        upload = await native("write", "b2_get_upload_url", {
          bucketId: B2_BUCKET,
        });
        b2Url(upload.uploadUrl);
        uploads.set(slot, upload);
      }
      const sha1 = createHash("sha1").update(bytes).digest("hex");
      const result = await json(upload.uploadUrl, {
        method: "POST",
        headers: {
          Authorization: upload.authorizationToken,
          "Content-Type": "application/octet-stream",
          "Content-Length": String(bytes.length),
          "X-Bz-File-Name": encodeURIComponent(name),
          "X-Bz-Content-Sha1": sha1,
          "X-Bz-File-Retention-Mode": "compliance",
          "X-Bz-File-Retention-Retain-Until-Timestamp": String(until),
          ...(sourceDigest
            ? { "X-Bz-Info-xf-source-sha256": sourceDigest }
            : {}),
        },
        body: bytes,
      });
      requireSafe(
        result.fileName === name && result.contentLength === bytes.length &&
          result.contentSha1 === sha1,
        "upload_integrity_mismatch",
      );
      return { id: result.fileId, size: result.contentLength };
    },
    async read(name, limit) {
      const a = await auth("read");
      const url = a.downloadUrl + "/file/" + B2_NAME + "/" + sourcePath(name);
      b2Url(url);
      return boundedBytes(
        await request(url, { headers: { Authorization: a.token } }),
        limit,
      );
    },
  };
  const storageUrl =
    `https://${STAGE}.supabase.co/functions/v1/staging-backup-export`;
  const sitesUrl = c.scope.sitesExportUrl;
  function readExport(kind, operation, extra = {}) {
    const raw = JSON.stringify({ operation, ...extra });
    const storage = kind === "storage";
    return retrySourceRead(() =>
      request(storage ? storageUrl : sitesUrl, {
        method: "POST",
        headers: signedReadHeaders(
          storage ? c.STORAGE_READER_ID : c.SITES_READER_ID,
          storage ? c.STORAGE_READER_KEY : c.SITES_READER_KEY,
          raw,
        ),
        body: raw,
      })
    );
  }
  const verified = {};
  async function verify(kind) {
    if (verified[kind]) return;
    const meta = JSON.parse(
      (await boundedBytes(await readExport(kind, "metadata"), 16384))
        .toString(),
    );
    requireSafe(
      meta.environment === "staging" && meta.readOnly === true &&
        meta.keyId ===
          c[kind === "storage" ? "STORAGE_READER_ID" : "SITES_READER_ID"] &&
        Date.parse(meta.expiresAt) > Date.now(),
      "source_scope_mismatch",
    );
    if (kind === "sites") {
      requireSafe(
        meta.r2Bucket === c.scope.r2Bucket &&
          meta.kvNamespace === c.scope.kvNamespace,
        "source_scope_mismatch",
      );
    }
    verified[kind] = true;
  }
  async function catalog(kind, operation) {
    await verify(kind);
    return JSON.parse(
      (await boundedBytes(await readExport(kind, operation), 16 * 1024 * 1024))
        .toString(),
    );
  }
  const storage = {
    async list() {
      const result = await catalog("storage", "catalog");
      return result.catalog;
    },
    async read(item) {
      const response = await readExport("storage", "storage.get", {
        bucket: item.bucket,
        name: item.name,
      });
      return {
        bytes: await boundedBytes(response),
        etag: response.headers.get("etag"),
      };
    },
  };
  const r2 = {
    async list() {
      const result = await catalog("sites", "sites.catalog");
      return result.objects;
    },
    async read(item) {
      const response = await readExport("sites", "r2.get", { name: item.key });
      return {
        bytes: await boundedBytes(response),
        etag: response.headers.get("etag"),
      };
    },
  };
  const kv = {
    async list() {
      const result = await catalog("sites", "sites.catalog");
      return result.keys;
    },
    async read(item) {
      const response = await readExport("sites", "kv.get", { name: item.name });
      return { bytes: await boundedBytes(response) };
    },
  };
  const database = c.databaseUrl ? connectDatabase(c) : undefined;
  return {
    storage,
    r2,
    kv,
    b2,
    database,
    close: () => database?.close() || Promise.resolve(),
  };
}
