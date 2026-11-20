import * as age from "age-encryption";
import process from "node:process";
import { configFromEnv, snapshot } from "./core.mjs";
import { connectProviders } from "./providers.mjs";
let providers;
try {
  const config = configFromEnv(process.env);
  providers = await connectProviders(config);
  const cipher = new age.Encrypter();
  cipher.addRecipient(config.AGE_RECIPIENT);
  const result = await snapshot({
    ...providers,
    scope: config.scope,
    encrypter: cipher,
    mode: process.argv[2],
  });
  // Public runners must not expose resource identifiers, inventory, or object paths.
  console.log(
    JSON.stringify({
      status: result.status,
      environment: "staging",
      capacityWarning: result.capacityWarning ?? false,
      paidUsageAuthorized: false,
    }),
  );
} catch (e) {
  // Never print provider errors: they can contain URLs, credentials, SQL, or paths.
  const safe =
    typeof e.safeCode === "string" && /^[a-z_]+(?:_\d{3})?$/.test(e.safeCode)
      ? e.safeCode
      : "unexpected_error_details_suppressed";
  console.error(
    JSON.stringify({
      status: "failed",
      environment: "staging",
      code: safe,
      paidUsageAuthorized: false,
    }),
  );
  process.exitCode = 1;
} finally {
  if (providers) await providers.close().catch(() => {});
}
