import { Buffer } from "node:buffer";
import { randomUUID } from "node:crypto";
import {
  CONFIGURATION_FORMAT,
  CONFIGURATION_LIMIT,
  validateConfigurationPackage,
} from "./configuration.mjs";
const DAY = 86400000;
const check = (ok, code) => {
  if (!ok) throw Object.assign(Error(code), { safeCode: code });
};
async function phaseCall(phase, operation) {
  try {
    return await operation();
  } catch (error) {
    error.safePhase = phase;
    throw error;
  }
}
export async function probeConfigurationDestination({ b2, encrypter }) {
  const now = Date.now(), until = now + 31 * DAY;
  const before = await phaseCall(
    "configuration_probe_inventory",
    () => readConfigurationDestination(() => b2.inventory()),
  );
  check(before.bytes + 8192 < 9e9, "free_configuration_capacity_limit");
  const bytes = await encrypter.encrypt(
    Buffer.from(
      JSON.stringify({
        format: "xfinder-configuration-probe-v1",
        environment: "staging",
        atUTC: new Date(now).toISOString(),
      }),
    ),
  );
  check(bytes.length < 4096, "configuration_probe_size_limit");
  const object = "staging/diagnostics/configuration/" + randomUUID() + ".age";
  const file = await phaseCall(
    "configuration_probe_upload",
    () => b2.put(object, bytes, { until, slot: 0 }),
  );
  const recovered = await phaseCall(
    "configuration_probe_readback",
    () => readConfigurationDestination(() => b2.read(object, 4096)),
  );
  check(
    Buffer.from(recovered).equals(Buffer.from(bytes)),
    "configuration_probe_readback_failed",
  );
  const after = await phaseCall(
    "configuration_probe_retention",
    () => readConfigurationDestination(() => b2.inventory()),
  );
  check(
    after.files.get(object)?.mode === "compliance" &&
      after.files.get(object).until >= now + 30 * DAY,
    "configuration_probe_retention_failed",
  );
  return {
    status: "configuration_destination_probe_passed",
    environment: "staging",
    bytes: file.size,
    healthChanged: false,
    sourceApisContacted: false,
  };
}
export async function readConfigurationDestination(
  operation,
  pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      return await operation();
    } catch (error) {
      const retry = [
        "provider_http_500",
        "provider_http_502",
        "provider_http_503",
        "provider_http_504",
      ].includes(error.safeCode) ||
        ["AbortError", "TimeoutError", "TypeError"].includes(error.name);
      if (!retry || attempt === 2) throw error;
      await pause(500 * (attempt + 1));
    }
  }
}
export async function backupConfiguration(
  { source, b2, encrypter, now = Date.now(), commissioningUntil },
) {
  check(source && b2 && encrypter, "configuration_backup_not_enabled");
  check(
    Date.parse(source.scope.readersExpireAt) > now,
    "configuration_readers_expired",
  );
  // This clock is independent of data snapshots; never overwrite it on a skipped run.
  let previous;
  try {
    previous = JSON.parse(
      Buffer.from(
        await readConfigurationDestination(() =>
          b2.read("staging/health/configuration-success.json", 4096)
        ),
      ).toString(),
    );
  } catch (error) {
    check(
      error.safeCode === "provider_http_404",
      "configuration_cadence_unavailable",
    );
  }
  if (previous) {
    const captured = Date.parse(previous.capturedAt),
      completed = Date.parse(previous.completedAt);
    check(
      previous.format === "xfinder-configuration-health-v1" &&
        previous.environment === "staging" &&
        Number.isFinite(captured) && Number.isFinite(completed) &&
        captured <= completed && completed <= now + 300000,
      "configuration_cadence_marker_invalid",
    );
    const commissionTime = Date.parse(commissioningUntil ?? "");
    const commissioning = Number.isFinite(commissionTime) &&
      commissionTime > now && commissionTime <= now + 3600000;
    if (now - captured < 12 * 3600000 && !commissioning) {
      return {
        status: "configuration_snapshot_fresh",
        environment: "staging",
        due: false,
      };
    }
  }
  const inventory = await readConfigurationDestination(() => b2.inventory());
  check(
    Number.isSafeInteger(inventory.bytes) && inventory.bytes >= 0 &&
      inventory.bytes + CONFIGURATION_LIMIT + 8192 <= 9e9,
    "free_configuration_capacity_limit",
  );
  const until = now + 31 * DAY, minimum = now + 30 * DAY;
  for (const object of source.scope.escrowObjects) {
    const f = inventory.files.get(object);
    check(f?.mode === "compliance", "configuration_reader_not_escrowed");
    if (f.until < minimum) await b2.extend(f, until);
  }
  const captured = await source.capture();
  try {
    const summary = validateConfigurationPackage(captured.data, source.scope);
    check(
      captured.bytes.length <= CONFIGURATION_LIMIT,
      "configuration_package_limit",
    );
    const object = "staging/configuration-snapshots/" +
      new Date(now).toISOString().replace(/[:.]/g, "-") + "-" + randomUUID() +
      "/configuration.age";
    const encrypted = await encrypter.encrypt(captured.bytes);
    check(
      encrypted.length <= CONFIGURATION_LIMIT + 4096,
      "configuration_ciphertext_limit",
    );
    const file = await phaseCall(
      "configuration_upload",
      () => b2.put(object, encrypted, { until, slot: 0 }),
    );
    check(file.size === encrypted.length, "configuration_upload_size_mismatch");
    const readback = await phaseCall(
      "configuration_readback",
      () =>
        readConfigurationDestination(() =>
          b2.read(object, CONFIGURATION_LIMIT + 4096)
        ),
    );
    check(
      Buffer.from(readback).equals(Buffer.from(encrypted)),
      "configuration_ciphertext_readback_failed",
    );
    const verified = await phaseCall(
        "configuration_retention",
        () => readConfigurationDestination(() => b2.inventory()),
      ),
      stored = verified.files.get(object);
    check(
      stored?.mode === "compliance" && stored.until >= minimum &&
        verified.bytes <= 9e9,
      "configuration_retention_unverified",
    );
    const completedAt = new Date().toISOString();
    const health = {
      format: "xfinder-configuration-health-v1",
      environment: "staging",
      capturedAt: captured.data.capturedAt,
      completedAt,
      bytes: file.size,
      readersExpireAt: source.scope.readersExpireAt,
      capturePolicyVersion: 2,
      ...summary,
    };
    check(verified.bytes + 4096 <= 9e9, "free_configuration_capacity_limit");
    await phaseCall("configuration_publish_health", () =>
      b2.put(
        "staging/health/configuration-success.json",
        Buffer.from(JSON.stringify(health)),
        { until, slot: 0 },
      ));
    return {
      status: "configuration_snapshot_committed",
      environment: "staging",
      object,
      fileId: file.id,
      bytes: file.size,
      capturedAt: captured.data.capturedAt,
      completedAt,
      retentionUntil: new Date(minimum).toISOString(),
      summary,
      readerEscrows: source.scope.escrowObjects,
      format: CONFIGURATION_FORMAT,
      ciphertextReadbackVerified: true,
      sourceWrites: false,
      productionChanged: false,
    };
  } finally {
    captured.bytes.fill(0);
  }
}
