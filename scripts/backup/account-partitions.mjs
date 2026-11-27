const check = (ok, code) => {
  if (!ok) throw Object.assign(Error(code), { safeCode: code });
};

// Static storage ceilings avoid giving either environment the other's reader.
// All other account bytes must fit the explicit reserved envelope.
export function storagePartitionCap(policy, ownName, listedNames) {
  check(
    policy?.version === 1 && Array.isArray(policy.buckets) &&
      policy.buckets.length === 2 &&
      Number.isSafeInteger(policy.otherStorageReservedBytes) &&
      policy.otherStorageReservedBytes > 0,
    "account_partition_policy_required",
  );
  const names = new Set();
  let total = policy.otherStorageReservedBytes;
  for (const b of policy.buckets) {
    check(
      typeof b.name === "string" && /^[a-z0-9-]+$/.test(b.name) &&
        !names.has(b.name) && Number.isSafeInteger(b.storageCapBytes) &&
        b.storageCapBytes > 0,
      "account_partition_policy_rejected",
    );
    names.add(b.name);
    total += b.storageCapBytes;
  }
  check(
    Number.isSafeInteger(total) && total <= 9000000000 && names.has(ownName),
    "account_partition_capacity_rejected",
  );
  if (listedNames) {
    check(
      Array.isArray(listedNames) && listedNames.includes(ownName) &&
        listedNames.every((n) => names.has(n)),
      "unaccounted_b2_bucket",
    );
  }
  return policy.buckets.find((b) => b.name === ownName).storageCapBytes;
}
