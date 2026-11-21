import { AwsClient } from "aws4fetch";
import { createHash, createHmac } from "node:crypto";
import { Buffer } from "node:buffer";
import { b2Url, requireSafe, sourcePath } from "./core.mjs";
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
      if ([429, 500, 502, 503, 504].includes(response.status)) {
        await response.body?.cancel();
        const error = Error("source temporarily unavailable");
        error.safeCode = "source_read_unavailable";
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
        error.safeCode === "source_read_unavailable";
      if (!transient) throw error;
      if (attempt === 2) {
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
  return { storage, r2, kv, b2, close: () => Promise.resolve() };
}
