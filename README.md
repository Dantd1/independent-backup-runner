# Independent encrypted backup runner

Portable Node 22 package for staging-only Supabase Storage, Cloudflare R2/KV and
private Backblaze B2. No Windows, DPAPI, browser session, provider master key,
or recovery private key is required. This package contains no live resource
identifiers. Configuration is supplied at execution time.

`npm ci --ignore-scripts` and `npm test` run synthetic tests without
credentials. `node run.mjs inventory` verifies configuration, source reads,
protection and capacity without destination writes. `node run.mjs backup`
creates an age encrypted manifest only after copying and source-stability
checks. Public logs contain status/error codes only, not inventory, paths,
configuration or secrets.

## Activation requirements

Do not enable a scheduler until provider billing restrictions, source scopes,
credential registry records, encrypted credential recovery and the independent
watchdog have been validated. `BACKUP_ZERO_COST_VERIFIED=true` records that
external review; it does **not** enforce a platform billing limit by itself.

Use standard Linux runners only. Public GitHub repository publication needs
approval. Private runners consume the owner's included compute and can be billed
after it is exhausted. Do not upload artifacts or enable package caches. Keep
the schedule disabled until the dedicated environment is configured. Scheduled
execution does not provide an exact-time SLA.

## Secret configuration

All values below belong in a protected execution environment, not in this repo:

- `BACKUP_SCOPE_JSON`: JSON containing `environment` (`staging`), `projectRef`,
  `cfAccount`, `r2Bucket` (ending in `-staging`), `kvNamespace`, `b2Account`,
  `b2Bucket`, `b2Name` (containing `-staging`), `sitesExportUrl` (dedicated
  staging Workers HTTPS endpoint) and `recoveryObject`.
- `STORAGE_READER_ID` / `STORAGE_READER_KEY`: expiring HMAC reader for the
  dedicated staging Storage export endpoint. No direct database or project key.
- `SITES_READER_ID` / `SITES_READER_KEY`: separate expiring HMAC reader for a
  dedicated read-only exporter bound only to staging R2 and KV.
  Both exporters verify signatures over the exact request body and timestamp,
  allow a 60-second clock window, reject browser origins, and expose no mutation
  operation. Repeated signed reads inside that window are idempotent.
  Administrative source credentials remain inside their providers.
- `B2_READ_KEY_ID` / `B2_READ_KEY`: exact bucket/prefix `staging/`, capabilities
  `readFiles,listFiles,readFileRetentions,listBuckets,listAllBucketNames`.
- `B2_WRITE_KEY_ID` / `B2_WRITE_KEY`: exact bucket/prefix `staging/`,
  capabilities `writeFiles,writeFileRetentions`. No delete, bypass or bucket
  administration.
- `AGE_RECIPIENT`: encryption recipient only. Never install a private identity
  or the owner's recovery passphrase in an automated runner.
- `XFINDER_ENVIRONMENT=staging` and `BACKUP_ZERO_COST_VERIFIED=true`: explicit
  gates.

Before first execution, the encrypted recovery identity and all four credential
archives must already exist at the configured recovery object and
`staging/credentials/<issuer-key-id>.age`. Credential issuance/rotation and
portable recovery are separate, mandatory operator procedures. The runner never
overwrites those archives or captures existing source secrets without rotation.

## Protection and limits

Unchanged Storage/R2 blobs are reused. KV has no object version and is captured
afresh. Retention is extended to cover every new manifest; compliance retention
is verified before publishing the private `staging/health/success.json` marker.
Only this sanitized timestamp/counter marker is unencrypted. Backups and source
paths are encrypted. No source mutation or destination deletion is implemented.
Histories remain until a separately controlled collector is installed.

Backup mode also attempts a minimal `staging/health/attempt.json` record after
success or a caught copy failure. It contains only format, environment, time and
conclusion; no paths or configuration. Inventory mode never writes it. A failed
attempt-report write does not hide the original copy result. The report obeys
the capacity guard and compliance retention. Failures before the runner starts
or while the destination is unavailable are detected by an independent observer
through the age of the last successful marker, rather than relying on GitHub's
public API or on an error notification sent by the failed workflow itself.

The runner stops before exceeding 9 GB of managed retained data. A second B2
bucket is rejected until account-wide accounting is configured. Provider free
caps remain mandatory; this inventory covers the managed prefix, not arbitrary
objects uploaded by other actors. A warning flag appears at 8 GB. An independent
watchdog must check the latest successful marker and capacity; writing the
marker does not implement delivery of alerts or detect a stopped scheduler by
itself.

Storage catalog and R2 listings are compared before/after. KV capture is not
atomic and this does not constitute a consistent database/file transaction.
Individual objects are limited to 64 MiB. Sample ciphertext verification does
not prove full decryption, bootstrap, or the complete service recovery time.
