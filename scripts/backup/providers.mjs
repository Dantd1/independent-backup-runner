import { AwsClient } from "aws4fetch";
import postgres from "postgres";
import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";
import { b2Url, parseR2List, requireSafe, sourcePath } from "./core.mjs";
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
export function connectProviders(c, { fetcher = fetch } = {}) {
  const {
    projectRef: STAGE,
    cfAccount: CF_ACCOUNT,
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
    keyIds: [c.B2_WRITE_KEY_ID, c.B2_READ_KEY_ID],
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
  const db = postgres(c.BACKUP_DB_URL, {
    ssl: { rejectUnauthorized: true },
    max: 1,
    prepare: false,
    connect_timeout: 15,
    idle_timeout: 10,
    onnotice: () => {},
  });
  const storage = {
    list() {
      return db.begin("read only", async (tx) => {
        const [role] =
          await tx`select current_user as name, rolsuper, rolbypassrls, rolcreaterole,
            rolcreatedb, rolreplication,
            exists(select 1 from pg_catalog.pg_auth_members m where m.member=r.oid) as memberships
            from pg_catalog.pg_roles r where rolname=current_user`;
        requireSafe(
          role.name === c.scope.dbRole && !role.rolsuper &&
            !role.rolbypassrls &&
            !role.rolcreaterole && !role.rolcreatedb && !role.rolreplication &&
            !role.memberships,
          "database_role_rejected",
        );
        const [row] =
          await tx`select backup_export.storage_catalog() as catalog`;
        return row.catalog;
      });
    },
    async read(item) {
      const url = `https://${STAGE}.supabase.co/storage/v1/object/` +
        sourcePath(item.bucket + "/" + item.name);
      const result = await request(url, {
        headers: { apikey: c.STORAGE_API_KEY },
      });
      return {
        bytes: await boundedBytes(result),
        etag: result.headers.get("etag"),
      };
    },
  };
  const r2Aws = new AwsClient({
    accessKeyId: c.R2_ACCESS_KEY_ID,
    secretAccessKey: c.R2_SECRET_ACCESS_KEY,
    service: "s3",
    region: "auto",
  });
  const r2Base =
    `https://${CF_ACCOUNT}.r2.cloudflarestorage.com/${c.scope.r2Bucket}`;
  const r2 = {
    async list() {
      const objects = [], seen = new Set();
      let cursor;
      for (let page = 0; page < 100; page++) {
        const url = new URL(r2Base);
        url.searchParams.set("list-type", "2");
        url.searchParams.set("max-keys", "1000");
        if (cursor) url.searchParams.set("continuation-token", cursor);
        const result = parseR2List(
          (await boundedBytes(
            await r2Aws.fetch(url.toString(), {
              redirect: "error",
              signal: AbortSignal.timeout(45000),
            }),
          )).toString(),
        );
        objects.push(...result.objects);
        if (!result.next) return objects;
        requireSafe(!seen.has(result.next), "r2_cursor_repeated");
        seen.add(result.next);
        cursor = result.next;
      }
      requireSafe(false, "r2_pagination_limit");
    },
    async read(item) {
      const result = await r2Aws.fetch(r2Base + "/" + sourcePath(item.key), {
        redirect: "error",
        signal: AbortSignal.timeout(45000),
      });
      return {
        bytes: await boundedBytes(result),
        etag: result.headers.get("etag"),
      };
    },
  };
  const kvBase =
    `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT}/storage/kv/namespaces/${c.scope.kvNamespace}`;
  const kv = {
    async list() {
      const keys = [], seen = new Set();
      let cursor;
      for (let page = 0; page < 100; page++) {
        const url = new URL(kvBase + "/keys");
        url.searchParams.set("limit", "1000");
        if (cursor) url.searchParams.set("cursor", cursor);
        const result = await json(url.toString(), {
          headers: { Authorization: "Bearer " + c.KV_READ_TOKEN },
        });
        requireSafe(
          result.success && Array.isArray(result.result),
          "invalid_kv_listing",
        );
        keys.push(...result.result);
        if (!result.result_info?.cursor) return keys;
        cursor = result.result_info.cursor;
        requireSafe(!seen.has(cursor), "kv_cursor_repeated");
        seen.add(cursor);
      }
      requireSafe(false, "kv_pagination_limit");
    },
    async read(item) {
      const result = await request(
        kvBase + "/values/" + encodeURIComponent(item.name),
        { headers: { Authorization: "Bearer " + c.KV_READ_TOKEN } },
      );
      return { bytes: await boundedBytes(result) };
    },
  };
  return { storage, r2, kv, b2, close: () => db.end({ timeout: 5 }) };
}
