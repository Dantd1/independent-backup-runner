import { requireSafe, sourcePath } from "./core.mjs";

export const RECURRING_ADAPTER_VERSION = "isolated-v1";
const MIB = 1024 * 1024;
const etag = (value) =>
  String(value ?? "").replace(/^W\//, "").replace(/^"|"$/g, "");

// The recurrent snapshot keeps its complete v1 catalog and reusable recovery
// packs. The representative candidate archive must never become its health.
export function createRecurringAdapters(raw, config, { limits = {} } = {}) {
  requireSafe(
    config?.scope?.environment === "staging" &&
      config.adaptersVersion === RECURRING_ADAPTER_VERSION &&
      config.scope.r2Bucket?.endsWith("-staging") &&
      config.scope.recoveryObject?.startsWith("staging/recovery/"),
    "recurring_adapter_scope_rejected",
  );
  const cap = {
    sourceBytes: 2 * 1024 * MIB,
    sourceReads: 40000,
    uploadBytes: 128 * MIB,
    downloadBytes: 64 * MIB,
    destinationReads: 1800,
    destinationWrites: 1800,
    ...limits,
  };
  for (const [key, value] of Object.entries(cap)) {
    requireSafe(
      Number.isSafeInteger(value) && value > 0,
      "recurring_adapter_limit_required",
    );
    requireSafe(
      Object.hasOwn({
        sourceBytes: 1,
        sourceReads: 1,
        uploadBytes: 1,
        downloadBytes: 1,
        destinationReads: 1,
        destinationWrites: 1,
      }, key),
      "recurring_adapter_limit_unknown",
    );
  }
  let closed = false;
  const usage = {
    sourceBytes: 0,
    sourceReads: 0,
    uploadBytes: 0,
    downloadBytes: 0,
    destinationReads: 0,
    destinationWrites: 0,
  };
  const active = () => requireSafe(!closed, "recurring_adapter_closed");
  function reserve(kind, amount) {
    active();
    requireSafe(
      Number.isSafeInteger(amount) && amount >= 0 &&
        usage[kind] + amount <= cap[kind],
      "recurring_adapter_" +
        kind.replace(/[A-Z]/g, (x) => "_" + x.toLowerCase()) +
        "_limit",
    );
    usage[kind] += amount;
  }
  function name(value) {
    requireSafe(
      typeof value === "string" && value.startsWith("staging/") &&
        !value.startsWith("staging/candidate-integrated-v1/"),
      "recurring_destination_scope_rejected",
    );
    sourcePath(value);
  }
  function item(kind, value) {
    requireSafe(
      value && typeof value === "object",
      "recurring_source_item_rejected",
    );
    const key = kind === "r2" ? value.key : value.name;
    requireSafe(
      typeof key === "string" && key.length > 0 && key.length <= 4096 &&
        !/[\u0000-\u001f\\]/.test(key),
      "recurring_source_item_rejected",
    );
    sourcePath(key);
    if (kind === "storage") {
      requireSafe(
        typeof value.bucket === "string" &&
          /^[a-zA-Z0-9_-]+$/.test(value.bucket),
        "recurring_source_bucket_rejected",
      );
    }
    if (kind !== "kv") {
      requireSafe(
        Number.isSafeInteger(Number(value.size)) &&
          Number(value.size) >= 0 && Number(value.size) <= 64 * MIB,
        "recurring_source_size_rejected",
      );
    }
  }
  const sources = Object.fromEntries(
    ["storage", "r2", "kv"].map((kind) => [kind, {
      async list() {
        active();
        const result = await raw[kind].list();
        const items = kind === "storage" ? result?.objects : result;
        requireSafe(
          Array.isArray(items) && items.length <= 100000 &&
            (kind !== "storage" || Array.isArray(result.buckets)),
          "recurring_catalog_rejected",
        );
        const seen = new Set();
        for (const entry of items) {
          item(kind, entry);
          const id = JSON.stringify(
            kind === "storage"
              ? [entry.bucket, entry.name]
              : [entry.key || entry.name],
          );
          requireSafe(!seen.has(id), "recurring_duplicate_source_record");
          seen.add(id);
        }
        return result;
      },
      async read(entry) {
        active();
        item(kind, entry);
        reserve("sourceReads", 1);
        const upper = kind === "kv" ? 64 * MIB : Number(entry.size);
        // Reserve before reading so parallel workers cannot bypass the ceiling.
        reserve("sourceBytes", upper);
        const result = await raw[kind].read(entry);
        try {
          requireSafe(
            result?.bytes instanceof Uint8Array && result.bytes.length <= upper,
            "recurring_source_size_changed",
          );
          requireSafe(
            kind === "kv" || result.bytes.length === Number(entry.size),
            "recurring_source_size_changed",
          );
          requireSafe(
            kind === "kv" || !entry.etag ||
              etag(entry.etag) === etag(result.etag),
            "recurring_source_version_changed",
          );
          usage.sourceBytes -= upper - result.bytes.length;
          return result;
        } catch (error) {
          result?.bytes?.fill(0);
          throw error;
        }
      },
    }]),
  );
  const b2 = {
    keyIds: raw.b2.keyIds,
    async inventory() {
      active();
      reserve("destinationReads", 120);
      const result = await raw.b2.inventory();
      requireSafe(
        result?.files instanceof Map && Number.isSafeInteger(result.bytes) &&
          result.bytes >= 0 && result.bytes < 9_000_000_000,
        "recurring_inventory_rejected",
      );
      for (const key of result.files.keys()) {
        // Other isolated tests can coexist in inventory; they are never used
        // as recurrent recovery records or as the success marker.
        requireSafe(
          typeof key === "string" && key.startsWith("staging/"),
          "recurring_inventory_scope_rejected",
        );
      }
      return result;
    },
    async put(key, bytes, options) {
      active();
      name(key);
      requireSafe(
        bytes instanceof Uint8Array,
        "recurring_destination_bytes_required",
      );
      reserve("uploadBytes", bytes.length);
      reserve("destinationWrites", 1);
      return await raw.b2.put(key, bytes, options);
    },
    async read(key, limit) {
      active();
      name(key);
      requireSafe(
        Number.isSafeInteger(limit) && limit > 0 && limit <= 64 * MIB,
        "recurring_download_limit_required",
      );
      reserve("downloadBytes", limit);
      reserve("destinationReads", 1);
      const result = await raw.b2.read(key, limit);
      requireSafe(
        result instanceof Uint8Array && result.length <= limit,
        "recurring_download_size_rejected",
      );
      usage.downloadBytes -= limit - result.length;
      return result;
    },
    async extend(file, until) {
      active();
      requireSafe(
        file?.mode === "compliance" && Number.isFinite(file.until) &&
          Number.isFinite(until) && until >= file.until,
        "recurring_retention_regression",
      );
      reserve("destinationWrites", 1);
      return await raw.b2.extend(file, until);
    },
  };
  const database = raw.database
    ? {
      inspect: () => {
        active();
        return raw.database.inspect();
      },
      probe: () => {
        active();
        return raw.database.probe();
      },
      async capture() {
        active();
        const captured = await raw.database.capture();
        try {
          requireSafe(
            captured.dump instanceof Uint8Array && captured.dump.length >= 5 &&
              captured.dump.length <= 32 * MIB &&
              Buffer.from(captured.dump.subarray(0, 5)).toString() === "PGDMP",
            "recurring_database_dump_rejected",
          );
          requireSafe(
            captured.context?.environment === "staging" &&
              captured.context.projectRef === config.scope.projectRef &&
              Array.isArray(captured.context.counts) &&
              captured.context.counts.length > 0,
            "recurring_database_scope_rejected",
          );
          const time = Date.parse(captured.context.capturedAt);
          requireSafe(
            Number.isFinite(time) && time <= Date.now() + 300000 &&
              Date.now() - time < 24 * 3600000,
            "recurring_database_time_rejected",
          );
          return captured;
        } catch (error) {
          captured?.dump?.fill(0);
          throw error;
        }
      },
    }
    : undefined;
  return {
    ...sources,
    b2,
    database,
    configuration: raw.configuration,
    adapterVersion: RECURRING_ADAPTER_VERSION,
    preflight({ projectedAdditionalBytes }) {
      active();
      requireSafe(
        projectedAdditionalBytes <= cap.uploadBytes,
        "recurring_upload_forecast_limit",
      );
    },
    usage: () => ({ ...usage }),
    async close() {
      closed = true;
      await raw.close();
    },
  };
}
