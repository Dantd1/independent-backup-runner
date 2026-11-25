import * as age from "age-encryption";
import process from "node:process";
import { appendFileSync } from "node:fs";
import {
  checkBackupCadence,
  configFromEnv,
  recordAttempt,
  requireSafe,
  scheduleObservation,
  snapshot,
} from "./core.mjs";
import { connectProviders } from "./providers.mjs";
import {
  backupConfiguration,
  probeConfigurationDestination,
} from "./configuration-backup.mjs";
let providers;
try {
  console.log(JSON.stringify({
    telemetry: "backup_schedule",
    ...scheduleObservation(
      process.env.GITHUB_EVENT_NAME,
      process.env.BACKUP_TRIGGER_CRON,
    ),
  }));
  const config = configFromEnv(process.env);
  providers = await connectProviders(config);
  if (process.argv[2] === "schedule-check") {
    const decision = await checkBackupCadence(
      providers.b2,
      Date.now(),
      !!config.databaseRole,
    );
    requireSafe(!!process.env.GITHUB_OUTPUT, "schedule_output_required");
    appendFileSync(process.env.GITHUB_OUTPUT, `due=${decision.due}\n`);
    console.log(JSON.stringify({ telemetry: "backup_cadence", ...decision }));
  } else {
    const cipher = new age.Encrypter();
    cipher.addRecipient(config.AGE_RECIPIENT);
    if (process.argv[2] === "database-probe") {
      requireSafe(!!providers.database, "database_configuration_required");
    }
    const result = process.argv[2] === "configuration-destination-probe"
      ? await probeConfigurationDestination({
        b2: providers.b2,
        encrypter: cipher,
      })
      : process.argv[2] === "configuration-backup"
      ? await backupConfiguration({
        source: providers.configuration,
        b2: providers.b2,
        encrypter: cipher,
        commissioningUntil: process.env.CONFIGURATION_COMMISSION_UNTIL,
      })
      : process.argv[2] === "database-probe"
      ? await providers.database.probe()
      : await snapshot({
        ...providers,
        scope: config.scope,
        encrypter: cipher,
        log: ({ phase, completed, total }) => {
          if (
            ["copy", "recovery_pack"].includes(phase) &&
            Number.isSafeInteger(completed) && Number.isSafeInteger(total)
          ) {
            console.log(JSON.stringify({ phase, completed, total }));
          }
        },
        mode: process.argv[2] === "backup-packed" ? "backup" : process.argv[2],
        recoveryPacks: process.argv[2] === "backup-packed" ||
          process.env.BACKUP_RECOVERY_PACKS_ENABLED === "true",
      });
    if (["backup", "backup-packed"].includes(process.argv[2])) {
      await recordAttempt(providers.b2, "success").catch(() => {
        console.warn(
          JSON.stringify({
            telemetry: "attempt_unavailable",
            environment: "staging",
          }),
        );
      });
    }
    // Public runners must not expose resource identifiers, inventory, or object paths.
    console.log(
      JSON.stringify({
        status: result.status,
        environment: "staging",
        capacityWarning: result.capacityWarning ?? false,
        paidUsageAuthorized: false,
      }),
    );
  }
} catch (e) {
  if (providers && ["backup", "backup-packed"].includes(process.argv[2])) {
    await recordAttempt(providers.b2, "failure").catch(() => {
      console.warn(
        JSON.stringify({
          telemetry: "attempt_unavailable",
          environment: "staging",
        }),
      );
    });
  }
  // Never print provider errors: they can contain URLs, credentials, SQL, or paths.
  const safe =
    typeof e.safeCode === "string" && /^[a-z_]+(?:_\d{3})?$/.test(e.safeCode)
      ? e.safeCode
      : ["TimeoutError", "AbortError"].includes(e.name)
      ? "provider_transport_timeout"
      : e.name === "TypeError"
      ? "provider_transport_or_type_error"
      : "unexpected_error_details_suppressed";
  console.error(
    JSON.stringify({
      status: "failed",
      environment: "staging",
      code: safe,
      phase: /^[a-z_]+$/.test(e.safePhase ?? "") ? e.safePhase : undefined,
      paidUsageAuthorized: false,
    }),
  );
  process.exitCode = 1;
} finally {
  if (providers) await providers.close().catch(() => {});
}
