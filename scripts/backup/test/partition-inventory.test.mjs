import { test } from "node:test";
import assert from "node:assert/strict";
import { connectProviders } from "../providers.mjs";

test("staging coexistence counts retained versions, admits only named peers and cannot borrow their capacity", async () => {
  const original = globalThis.fetch;
  let names = ["synthetic-staging", "synthetic-production"],
    uploads = 0,
    inventoryReads = 0;
  const readerCaps = [
    "listAllBucketNames",
    "listBuckets",
    "listFiles",
    "readFiles",
    "readFileRetentions",
  ];
  const writerCaps = ["writeFiles", "writeFileRetentions"];
  const fetcher = async (url, request = {}) => {
    url = url instanceof Request ? url.url : String(url);
    if (url.endsWith("b2_authorize_account")) {
      const read = Buffer.from(request.headers.Authorization.slice(6), "base64")
        .toString().startsWith("reader:");
      return Response.json({
        applicationKeyExpirationTimestamp: Date.now() + 86400000,
        authorizationToken: "synthetic",
        apiInfo: {
          storageApi: {
            apiUrl: "https://api005.backblazeb2.com",
            s3ApiUrl: "https://s3.us-east-005.backblazeb2.com",
            allowed: {
              buckets: [{ id: "own" }],
              namePrefix: "staging/",
              capabilities: read ? readerCaps : writerCaps,
            },
          },
        },
      });
    }
    if (url === "https://s3.us-east-005.backblazeb2.com/") {
      return new Response(
        "<ListAllMyBucketsResult><Buckets>" + names.map((name) =>
          "<Bucket><Name>" + name + "</Name></Bucket>"
        ).join("") + "</Buckets></ListAllMyBucketsResult>",
      );
    }
    if (url.endsWith("b2_list_buckets")) {
      return Response.json({
        buckets: [{ bucketId: "own", bucketType: "allPrivate" }],
      });
    }
    if (url.endsWith("b2_list_file_versions")) {
      inventoryReads++;
      assert.equal(JSON.parse(request.body).bucketId, "own");
      assert.equal(JSON.parse(request.body).prefix, "staging/");
      return Response.json({
        files: [{
          action: "upload",
          fileName: "staging/objects/a",
          fileId: "new",
          contentLength: 100,
        }, {
          action: "upload",
          fileName: "staging/objects/a",
          fileId: "retained",
          contentLength: 200,
        }],
        nextFileName: null,
      });
    }
    if (url.endsWith("b2_get_upload_url")) uploads++;
    throw Error("unexpected_request");
  };
  const config = {
    scope: {
      b2Bucket: "own",
      b2Name: "synthetic-staging",
      b2Account: "synthetic",
      accountPartitions: {
        version: 1,
        buckets: [
          { name: "synthetic-staging", storageCapBytes: 350 },
          { name: "synthetic-production", storageCapBytes: 800 },
        ],
        otherStorageReservedBytes: 100,
      },
    },
    B2_READ_KEY_ID: "reader",
    B2_READ_KEY: "synthetic",
    B2_WRITE_KEY_ID: "writer",
    B2_WRITE_KEY: "synthetic",
  };
  globalThis.fetch = fetcher;
  const provider = connectProviders(config, { fetcher });
  try {
    const own = await provider.b2.inventory();
    assert.equal(own.bytes, 300);
    assert.equal(own.files.size, 1);
    assert.equal(own.storageCapBytes, 350);
    await assert.rejects(
      provider.b2.put("staging/objects/b", Buffer.alloc(51), {
        until: Date.now() + 86400000,
        slot: 0,
      }),
      /partition_storage_exhausted/,
    );
    assert.equal(uploads, 0);
    names.push("unaccounted");
    const readsBefore = inventoryReads;
    await assert.rejects(provider.b2.inventory(), /unaccounted_b2_bucket/);
    assert.equal(inventoryReads, readsBefore);
    names = ["synthetic-staging", "synthetic-production"];
    const legacy = connectProviders({
      ...config,
      scope: { ...config.scope, accountPartitions: undefined },
    }, { fetcher });
    try {
      await assert.rejects(legacy.b2.inventory(), /unaccounted_b2_bucket/);
    } finally {
      await legacy.close();
    }
  } finally {
    await provider.close();
    globalThis.fetch = original;
  }
});
