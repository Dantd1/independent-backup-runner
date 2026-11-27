import { test } from "node:test";
import assert from "node:assert/strict";
import { storagePartitionCap } from "../account-partitions.mjs";
import { requireSpace } from "../core.mjs";

test("two named buckets have disjoint ceilings within the account envelope", () => {
  const p = {
    version: 1,
    buckets: [{ name: "synthetic-staging", storageCapBytes: 4000000000 }, {
      name: "synthetic-production",
      storageCapBytes: 4000000000,
    }],
    otherStorageReservedBytes: 1000000000,
  };
  assert.equal(
    storagePartitionCap(p, "synthetic-staging", [
      "synthetic-staging",
      "synthetic-production",
    ]),
    4000000000,
  );
  assert.equal(
    storagePartitionCap(p, "synthetic-production", ["synthetic-production"]),
    4000000000,
  );
  assert.throws(
    () =>
      storagePartitionCap(p, "synthetic-staging", [
        "synthetic-staging",
        "unknown",
      ]),
    /unaccounted_b2_bucket/,
  );
  assert.throws(
    () =>
      storagePartitionCap(
        { ...p, otherStorageReservedBytes: 2000000000 },
        "synthetic-staging",
      ),
    /capacity_rejected/,
  );
  assert.throws(
    () => requireSpace(3999999999, 2, 4000000000),
    /free_capacity_limit/,
  );
  requireSpace(3999999999, 1, 4000000000);
});
