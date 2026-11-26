# Independent encrypted backup runner

## Reversible recurrent adapter gate

`BACKUP_ADAPTERS_VERSION=isolated-v1` installs bounded staging provider adapters
around the existing HMAC, native PostgreSQL and restricted B2 transports. It
preserves the complete catalog, encrypted database context, v1 manifests,
incremental recovery packs, 30-day retention and the twelve-hour cadence guard.
The representative candidate test archive is rejected as a recurrent write or
health source. This integration does not install the candidate batch archive
format, change provider endpoints or publish live allowlist identifiers.

Per-run ceilings: 128 MiB ciphertext uploads (forecast checked before writes),
64 MiB B2 body reads, 32 MiB compressed database dump, 2 GiB source bodies,
40,000 source reads, 1,800 destination read/write reservations each (an inventory
reserves 120 reads for its bounded pagination/auth). These are conservative
adapter-operation reservations, not claims of authoritative daily B2 billing
counts. Provider zero-cost caps remain the final account-wide boundary; check
the current allowance before commissioning. Source bodies must match catalog
size/ETag; a mismatch or quota failure cannot publish success. Incomplete writes
remain encrypted and do not replace the previous health marker.

The success health keeps its v1 schema and adds the nonsecret adapter version
and `fileCoverage=complete_catalog`. The existing independent monitor can
recognize it by the completion/database timestamps without new access or a
Worker deployment. Recognition does not certify restore or RPO/RTO.

Rollback: unset `BACKUP_ADAPTERS_VERSION`; preserve all other gates, secrets,
health and recovery packs. Do not disable packed mode or delete archives. A
manual commissioning copy is distinct from the subsequent automatic twelve-hour
cadence; it establishes the next due time through the unchanged health guard.

Portable Node 22 package for staging-only Supabase Storage, Cloudflare R2/KV and
private Backblaze B2. No Windows, DPAPI, browser session, provider master key,
or recovery private key is required. Live access configuration and credentials
are supplied at execution time.

`npm ci --ignore-scripts` and `npm test` run synthetic tests without
credentials. `node run.mjs inventory` verifies configuration, source reads,
protection and capacity without destination writes. `node run.mjs backup`
creates an age encrypted manifest only after copying and source-stability
checks. Public logs contain status/error codes only, not inventory, paths,
configuration or secrets.

`node run.mjs backup-packed` additionally creates encrypted recovery packs. The
v1 per-object records remain present for older recovery tools. Packs use stable
hash partitions, normally at most 32 MiB of plaintext per pack, and are reused
and protected by the same retention/capacity guards. Their membership, offsets
and integrity information exist only inside the encrypted manifest. Source bytes
are checked against the original records before packing, and the source
inventories are compared again before committing success. A maximum of 1,500
packs bounds the number of requests for a complete restore.

Packed snapshots renew compliance on the complete recovery packs and their
manifest/escrow/database files. Legacy individual objects remain present and
their existing locks are never reduced or removed, but are not extended for
these newer snapshots. `retentionBasis=complete-recovery-packs` makes this
explicit: the 30-day recovery guarantee requires a pack-aware restorer. Every
record must be covered exactly once and every pack must have verified retention
before success. This avoids thousands of daily legacy retention API calls beyond
the provider's zero-cost cap. Do not disable packed mode without rechecking the
individual-object retention quota.

Scheduled mode keeps its existing behavior unless the separately reviewed
`BACKUP_RECOVERY_PACKS_ENABLED=true` variable is installed. Trial packed mode
does not change the schedule or free provider caps. Additional ciphertext counts
toward the 9 GB account guard. Full restoration must use the packs instead of
downloading every legacy object where the account has daily request limits.

## Activation requirements

### Optional platform configuration

`configuration-backup` captures sanitized Supabase service settings and selected
Cloudflare Access applications/policies/IdPs, Worker settings/schedules, DNS/TLS
and routes. It never reads application data, private signing keys or secret values
for this package, and never applies configuration to source services. Shared zone
settings are dependencies to restore separately, not permission to reapply them.

Supply `CONFIGURATION_BACKUP_ENABLED=true`, `CONFIGURATION_SCOPE_JSON`,
`CONFIGURATION_SUPABASE_TOKEN` and `CONFIGURATION_CLOUDFLARE_TOKEN` only in the
protected environment. The Supabase token must be project-scoped with Read in
Auth Config, Data API Config, Database Config, Realtime Config and Storage Config.
Cloudflare requires read-only Access/IdP, Workers metadata, DNS, routes and zone
settings on selected resources. Account permissions can read beyond staging;
the collector validates explicit staging application IDs/domains/Worker markers
and filters shared routes. It does not install an administrative account token.

Scope includes three `{id,domain}` apps, three staging Worker names, explicit
IdP IDs, two `{id,name,dnsNames}` zones, two encrypted `escrowObjects` under
`staging/credentials/`, and `readersExpireAt`; project/account must match the
existing backup scope. Secret readers must be independently escrowed first.
No real scope, credential or customer configuration belongs in this repository.

Configuration copies have their own minimum twelve-hour marker, bounded GET-only
source calls, a 512 KiB plaintext limit, encrypted readback and verified 30-day
compliance. They fail closed at the existing 9 GB capacity guard. Missing secrets,
escrow, capacity, source configuration or retention prevent publishing success.
`staging/health/configuration-success.json` holds only time/count/expiry metadata.
Access service-token selectors are public references and remain intact when
credential fields are removed. Actual secret values require separate escrow.

Manual commissioning uses `configuration-backup`. The workflow variable
`CONFIGURATION_BACKUP_SCHEDULE_ENABLED` stays false until independent recovery
has passed; it then includes configuration after due data backups. An independent
scheduler must also dispatch configuration-only runs when its separate clock is
due. No exact-minute SLA or complete platform recovery is implied.

Synthetic tests cover redaction without widening policies, staging-only scope,
GET-only transport, missing recovery material, retention/readback/capacity and the
twelve-hour skip. Logs must contain only aggregate status/error codes.

Capture policy v2 preserves password/security-policy settings while removing
credential material. Capture age starts at the first source read. A commissioning
repeat requires an explicit manual boolean plus a protected expiry window of at
most one hour; ordinary scheduled dispatches cannot use this override. Remove
the commissioning variable before enabling recurrence. Earlier commissioning
snapshots remain immutable history and must not be mistaken for v2 coverage.

Optional database capture uses `DATABASE_BACKUP_ENABLED=true` only after its
dedicated reader, `DATABASE_READER_URL`, trusted public `DATABASE_SSL_CA`,
encrypted credential escrow and independent database-age monitoring have been
validated. It uses the pinned PostgreSQL Docker client, a consistent read-only
snapshot, RAM-only custom dump and encrypted context. Vault/key/queue/scheduler
data are excluded. Managed tables require a privileged full-read role; its wider
technical read scope must be explicitly accepted. No administrative URI is
accepted. An absent database gate preserves the existing file-only behavior and
schedule.

Native Supabase logins can inherit managed pg_net/pg_cron capabilities from
PUBLIC. A default READ ONLY setting prevents accidental writes but is not an
immutable permission boundary. `DATABASE_MANAGED_PUBLIC_WRITES_ACCEPTED=true`
requires the owner's explicit staging-only acceptance of this provider scope.
Absent that acceptance, database capture fails closed. Even with acceptance,
non-read privileges on other application tables/views/foreign tables/sequences
are rejected. The executor never uses the inherited native mutation APIs.

`node run.mjs database-probe` tests a native client alone and alongside the
snapshot connection, without writing a snapshot or attempt marker. Budget for
pooler backend headroom as well as the two active clients. Snapshot heartbeats
preserve the exporting transaction while pg_dump runs. Native startup/connect
are bounded at 30/60 seconds and the complete dump at 15 minutes; client failure
never commits backup success. The client image is pinned by digest; TLS remains
verify-full, GSSAPI is disabled for Supavisor, and DNS resolution preserves TLS
hostname verification. A timed-out CLI is killed and its unique container removed.

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
  dedicated read-only exporter bound only to staging R2 and KV. Both exporters
  verify signatures over the exact request body and timestamp, allow a 60-second
  clock window, reject browser origins, and expose no mutation operation.
  Repeated signed reads inside that window are idempotent. Administrative source
  credentials remain inside their providers.
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

The workflow separates manual database rehearsals (`DATABASE_BACKUP_ENABLED`)
from recurring database capture (`DATABASE_BACKUP_SCHEDULE_ENABLED`). Enable the
schedule gate only after the actual encrypted dump, isolated restore and
independent database-age monitoring have passed. The database schedule gate
remains separate from the manual rehearsal gate.

The cron `8,23,38,53 * * * *` explicitly uses `Etc/UTC` and provides 96 daily retry opportunities. Before
pulling the database image or reading source data, each scheduled job downloads
only the bounded 4 KiB staging health marker. A copy is due twelve hours after
the last database capture (or file completion while database capture is disabled).
Fresh markers skip the image pull and backup entirely. Missing, malformed,
production, future or invalid database markers fail closed. Manual `cadence-check`
tests this decision without writing a backup/attempt marker. Explicit manual
backup/recovery operations remain possible. Whole-job concurrency serializes
the freshness check and copy, so delayed queued jobs recheck the latest marker.

This replaces the fixed 00:23/12:23 Sao Paulo copy windows: the next copy is
anchored to the last successful database capture, not wall-clock slots. It adds
at most 96 small marker reads/authentications daily, using existing scoped keys,
the public standard Linux runner and unchanged hard free caps. Source reads,
retention renewal and encrypted uploads occur only when due, normally twice daily.

The runner logs only matched expression, UTC start, inferred latest matching
date/delay and the cadence decision. GitHub does not provide the authoritative
scheduled date. Old combined/separate expressions remain accepted for queued
events, and all scheduled jobs use the same freshness guard after publication.
Manual dispatch does not prove automatic cadence. Retry opportunities reduce
dependence on one event but cannot guarantee exact twelve-hour starts if GitHub
stops delivering all events. Keep independent monitoring and compare real capture
timestamps before claiming operational cadence or RPO/RTO.

The `scheduled-backup` dispatch mode is for an independent clock. It obeys the
same automatic activation/database gates, whole-job concurrency and real B2 age
check as the native schedule. A dispatch acknowledgement is not a completed copy.
It does not require a new application or database credential in this repository.
