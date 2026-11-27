import { test } from "node:test";
import assert from "node:assert/strict";
import { connectProviders, safeProviderPhase } from "../providers.mjs";
import { createRecurringAdapters } from "../recurring-adapters.mjs";

function fixture(mode = "upload", limits) {
  const calls = [], urls = [];
  let targets = 0, attempts = 0, pauses = 0;
  const config = {
    adaptersVersion: "isolated-v1",
    scope: {
      environment: "staging",
      projectRef: "synthetic",
      r2Bucket: "synthetic-staging",
      recoveryObject: "staging/recovery/synthetic.age",
      b2Bucket: "synthetic-bucket",
      b2Name: "synthetic-name",
    },
    B2_WRITE_KEY_ID: "synthetic-writer",
    B2_WRITE_KEY: "synthetic-key",
    B2_READ_KEY_ID: "synthetic-reader",
    B2_READ_KEY: "synthetic-key",
  };
  const raw = connectProviders(config, {
    pause: async () => {
      pauses++;
    },
    fetcher: async (url, request) => {
      if (url.endsWith("b2_authorize_account")) {
        calls.push("auth");
        if (mode === "auth") return new Response("synthetic", { status: 503 });
        return Response.json({
          applicationKeyExpirationTimestamp: Date.now() + 86400000,
          authorizationToken: "synthetic-auth",
          apiInfo: {
            storageApi: {
              apiUrl: "https://api005.backblazeb2.com",
              allowed: {
                buckets: [{ id: "synthetic-bucket" }],
                namePrefix: "staging/",
                capabilities: ["writeFiles", "writeFileRetentions"],
              },
            },
          },
        });
      }
      if (url.endsWith("b2_get_upload_url")) {
        calls.push("url");
        targets++;
        if (mode === "url" && targets === 1) {
          return new Response("synthetic", { status: 503 });
        }
        return Response.json({
          uploadUrl: "https://pod-" + targets + ".backblazeb2.com/upload",
          authorizationToken: "synthetic-upload",
        });
      }
      calls.push("upload");
      urls.push(url);
      attempts++;
      if (mode === "timeout") {
        throw new DOMException("synthetic-sensitive", "TimeoutError");
      }
      if (mode === "denied") {
        return new Response("synthetic", { status: 403 });
      }
      if (
        mode === "always" || mode === "upload" && attempts === 1
      ) return new Response("synthetic", { status: 503 });
      return Response.json({
        fileName: decodeURIComponent(request.headers["X-Bz-File-Name"]),
        contentLength: request.body.length,
        contentSha1: mode === "corrupt"
          ? "wrong"
          : request.headers["X-Bz-Content-Sha1"],
        fileId: "synthetic-file",
      });
    },
  });
  const adapted = createRecurringAdapters(raw, config, { limits });
  return { raw, adapted, calls, urls, pauses: () => pauses };
}
const put = (f) =>
  f.adapted.b2.put("staging/objects/synthetic.age", Buffer.from("abc"), {
    until: Date.now() + 86400000,
    slot: 0,
  });
test("sanitized B2 phases survive logging without allowing URLs or provider diagnostics", () => {
  assert.equal(safeProviderPhase("b2_upload_file"), "b2_upload_file");
  assert.equal(safeProviderPhase("b2_get_upload_url"), "b2_get_upload_url");
  assert.equal(safeProviderPhase("database_dump"), "database_dump");
  for (
    const value of [
      "https://synthetic.invalid/private",
      "private-token-123",
      "b2_unknown_phase",
      "x".repeat(100),
    ]
  ) {
    assert.equal(safeProviderPhase(value), undefined);
  }
});
test("explicit B2 503 refreshes upload URL once after reserving all retry resources", async () => {
  for (const mode of ["upload", "url"]) {
    const f = fixture(mode);
    try {
      assert.equal((await put(f)).id, "synthetic-file");
      assert.equal(f.calls.filter((c) => c === "url").length, 2);
      if (mode === "upload") assert.notEqual(f.urls[0], f.urls[1]);
      assert.equal(f.pauses(), 1);
      assert.equal(f.adapted.usage().uploadBytes, 6);
      assert.equal(f.adapted.usage().downloadBytes, 32768);
      assert.equal(f.adapted.usage().destinationWrites, 3);
    } finally {
      await f.adapted.close();
    }
  }
});
test("persistent upload 503 stops after one repeat and preserves sanitized phase", async () => {
  const f = fixture("always");
  try {
    await assert.rejects(
      put(f),
      (error) =>
        error.safeCode === "provider_http_503" &&
        error.safePhase === "b2_upload_file",
    );
    assert.equal(f.calls.filter((c) => c === "upload").length, 2);
    assert.equal(f.pauses(), 1);
  } finally {
    await f.adapted.close();
  }
});
test("retry quota denial happens before another URL or payload request", async () => {
  for (
    const limits of [{ uploadBytes: 3 }, { downloadBytes: 32767 }, {
      destinationWrites: 2,
    }]
  ) {
    const f = fixture("upload", limits);
    try {
      await assert.rejects(
        put(f),
        (error) => error.safePhase === "b2_upload_retry_budget",
      );
      assert.equal(f.calls.filter((c) => c === "url").length, 1);
      assert.equal(f.calls.filter((c) => c === "upload").length, 1);
      assert.equal(f.pauses(), 0);
    } finally {
      await f.adapted.close();
    }
  }
});
test("ambiguous timeout, authentication failure, corruption and legacy unbudgeted writes never retry", async () => {
  for (const mode of ["timeout", "denied", "corrupt", "auth"]) {
    const f = fixture(mode);
    try {
      await assert.rejects(put(f));
      assert.equal(f.pauses(), 0);
      assert(f.urls.length <= 1);
    } finally {
      await f.adapted.close();
    }
  }
  const f = fixture("upload");
  try {
    await assert.rejects(
      f.raw.b2.put("staging/objects/synthetic.age", Buffer.from("abc"), {
        until: Date.now() + 86400000,
        slot: 0,
      }),
    );
    assert.equal(f.urls.length, 1);
    assert.equal(f.pauses(), 0);
  } finally {
    await f.raw.close();
  }
});
