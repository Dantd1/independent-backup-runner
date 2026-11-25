import { Buffer } from "node:buffer";

export const CONFIGURATION_FORMAT = "xfinder-platform-configuration-v2";
export const CONFIGURATION_LIMIT = 512 * 1024;
const check = (ok, code) => {
  if (!ok) throw Object.assign(Error(code), { safeCode: code });
};
const sensitive =
  /(?:^|_)(?:secrets?|password|passwd|pass|authorization|fingerprint|private_key|private_jwk|access_token|refresh_token|id_token|api_key|application_key|signing_keys|password_hash)$|^(?:token|clientSecret|applicationKey|apiKey|privateKey|privateJwk|jwtSecret|accessToken|refreshToken)$/i;
const secretValue =
  /(?:sb_secret_|sbp_|GOCSPX-|AGE-SECRET-KEY-|-----BEGIN .*PRIVATE KEY)/;
export function sanitizeConfiguration(value) {
  if (Array.isArray(value)) return value.map(sanitizeConfiguration);
  if (value && typeof value === "object") {
    if (["secret_text", "secret_key"].includes(value.type)) {
      return { name: value.name, type: value.type, valueAvailable: false };
    }
    check(
      !(value.kty && ("d" in value || "k" in value)),
      "configuration_private_jwk_denied",
    );
    return Object.fromEntries(
      Object.entries(value).filter(([key]) =>
        !sensitive.test(key) && key !== "__proto__" && key !== "constructor"
      ).map(([key, item]) => [key, sanitizeConfiguration(item)]),
    );
  }
  check(
    typeof value !== "string" || !secretValue.test(value),
    "configuration_unclassified_secret_denied",
  );
  return value;
}
const stagingHost = (host) =>
  typeof host === "string" &&
  /^(?:staging\.|[a-z0-9*-]+-staging\.)[a-z0-9.-]+$/.test(host);
export function validateConfigurationScope(scope, base) {
  check(
    base?.environment === "staging" && scope?.environment === "staging" &&
      scope.projectRef === base.projectRef &&
      scope.accountId === base.cfAccount &&
      /^[a-z0-9]{20}$/.test(scope.projectRef) &&
      /^[a-f0-9]{32}$/.test(scope.accountId),
    "configuration_scope_denied",
  );
  check(
    Array.isArray(scope.apps) && scope.apps.length === 3 &&
      scope.apps.every((a) =>
        /^[a-f0-9-]{36}$/.test(a.id) && stagingHost(a.domain)
      ) &&
      new Set(scope.apps.map((a) => a.id)).size === scope.apps.length &&
      Array.isArray(scope.workers) && scope.workers.length === 3 &&
      scope.workers.every((w) => /^[a-z0-9-]+-staging$/.test(w)) &&
      new Set(scope.workers).size === scope.workers.length &&
      Array.isArray(scope.identityProviders) &&
      scope.identityProviders.length > 0 &&
      scope.identityProviders.length <= 3 &&
      scope.identityProviders.every((id) => /^[a-f0-9-]{36}$/.test(id)) &&
      Array.isArray(scope.zones) && scope.zones.length === 2 &&
      scope.zones.every((z) =>
        /^[a-f0-9]{32}$/.test(z.id) && /^[a-z0-9.-]+$/.test(z.name) &&
        Array.isArray(z.dnsNames) && z.dnsNames.length <= 10 &&
        z.dnsNames.every((n) =>
          typeof n === "string" && (n === z.name || n.endsWith("." + z.name))
        )
      ) &&
      Array.isArray(scope.escrowObjects) && scope.escrowObjects.length === 2 &&
      scope.escrowObjects.every((o) =>
        /^staging\/credentials\/[a-zA-Z0-9_-]+\.age$/.test(o)
      ) &&
      Number.isFinite(Date.parse(scope.readersExpireAt)),
    "configuration_resources_denied",
  );
  return scope;
}
export function validateConfigurationPackage(data, scope) {
  check(
    data?.format === CONFIGURATION_FORMAT && data.environment === "staging" &&
      data.projectRef === scope.projectRef &&
      data.accountId === scope.accountId &&
      Number.isFinite(Date.parse(data.capturedAt)) &&
      data.credentialValuesIncluded === false &&
      data.sourceWrites === false && data.crossProviderAtomicSnapshot === false,
    "configuration_package_denied",
  );
  check(
    data.supabase && Object.keys(data.supabase).sort().join(",") ===
        ["auth", "database", "postgrest", "realtime", "storage"].sort().join(
          ",",
        ) &&
      data.apps?.length === scope.apps.length &&
      data.workers?.length === scope.workers.length &&
      data.identityProviders?.length === scope.identityProviders.length &&
      data.zones?.length === scope.zones.length &&
      scope.apps.every((a) =>
        data.apps.some((x) =>
          x.id === a.id && x.domain === a.domain && x.policies?.length > 0
        )
      ) &&
      scope.workers.every((name) =>
        data.workers.some((w) => w.name === name)
      ) &&
      scope.identityProviders.every((id) =>
        data.identityProviders.some((x) => x.id === id)
      ) &&
      scope.zones.every((z) =>
        data.zones.some((x) => x.id === z.id && x.name === z.name)
      ),
    "configuration_package_incomplete",
  );
  // Never accept a recovered package containing credential fields, even if signed/encrypted.
  check(
    JSON.stringify(sanitizeConfiguration(data)) === JSON.stringify(data),
    "configuration_package_secrets_denied",
  );
  return {
    supabaseGroups: 5,
    accessApplications: data.apps.length,
    accessPolicies: data.apps.reduce((n, a) => n + a.policies.length, 0),
    workers: data.workers.length,
    identityProviders: data.identityProviders.length,
    zones: data.zones.length,
    secretsRecovered: false,
    platformRestored: false,
  };
}
export function connectConfigurationSource(
  { scope, base, supabaseToken, cloudflareToken, fetcher = fetch },
) {
  validateConfigurationScope(scope, base);
  check(
    typeof supabaseToken === "string" && supabaseToken.startsWith("sbp_fc") &&
      typeof cloudflareToken === "string" && cloudflareToken.length >= 32,
    "configuration_scoped_credentials_required",
  );
  let requests = 0;
  async function get(provider, suffix, query = {}) {
    check(++requests <= 100, "configuration_request_limit");
    const u = new URL(
      provider === "supabase"
        ? `https://api.supabase.com/v1/projects/${scope.projectRef}/${suffix}`
        : `https://api.cloudflare.com/client/v4/${suffix}`,
    );
    for (const [k, v] of Object.entries(query)) {
      u.searchParams.set(k, String(v));
    }
    const r = await fetcher(u, {
      method: "GET",
      headers: {
        Authorization: "Bearer " +
          (provider === "supabase" ? supabaseToken : cloudflareToken),
      },
      redirect: "error",
      signal: AbortSignal.timeout(30000),
    });
    check(r.ok, "configuration_source_http_" + r.status);
    const bytes = Buffer.from(await r.arrayBuffer());
    try {
      check(bytes.length <= 2 * 1024 * 1024, "configuration_response_limit");
      const j = JSON.parse(bytes.toString("utf8"));
      if (provider === "supabase") return sanitizeConfiguration(j);
      check(
        j.success === true &&
          (!j.result_info?.total_pages || j.result_info.total_pages <= 1),
        "configuration_pagination_required",
      );
      return sanitizeConfiguration(j.result);
    } finally {
      bytes.fill(0);
    }
  }
  return {
    scope,
    async capture() {
      requests = 0;
      const captureStartedAt = new Date().toISOString();
      const account = `accounts/${scope.accountId}`;
      const supabase = {};
      for (
        const [name, endpoint] of Object.entries({
          auth: "config/auth",
          database: "config/database/postgres",
          postgrest: "postgrest",
          realtime: "config/realtime",
          storage: "config/storage",
        })
      ) {
        supabase[name] = await get("supabase", endpoint);
      }
      const apps = [];
      for (const expected of scope.apps) {
        const a = await get(
          "cloudflare",
          `${account}/access/apps/${expected.id}`,
        );
        check(
          a.id === expected.id && a.domain === expected.domain &&
            (a.destinations || []).every((d) =>
              d.type === "public" && stagingHost(d.uri)
            ),
          "configuration_application_scope_denied",
        );
        const policies = await get(
          "cloudflare",
          `${account}/access/apps/${expected.id}/policies`,
          { per_page: 100 },
        );
        apps.push({ ...a, policies });
      }
      const identityProviders = [];
      for (const id of scope.identityProviders) {
        const p = await get(
          "cloudflare",
          `${account}/access/identity_providers/${id}`,
        );
        check(p.id === id, "configuration_identity_scope_denied");
        identityProviders.push(p);
      }
      const workers = [];
      for (const name of scope.workers) {
        const settings = await get(
          "cloudflare",
          `${account}/workers/scripts/${name}/settings`,
        );
        check(
          settings.bindings?.some((b) =>
            ["ENVIRONMENT", "XFINDER_ENVIRONMENT"].includes(b.name) &&
            b.text === "staging"
          ),
          "configuration_worker_scope_denied",
        );
        const schedules = await get(
          "cloudflare",
          `${account}/workers/scripts/${name}/schedules`,
        );
        workers.push({ name, settings, schedules });
      }
      const zones = [];
      for (const z of scope.zones) {
        const dns = [];
        for (const name of z.dnsNames) {
          const found = await get("cloudflare", `zones/${z.id}/dns_records`, {
            name,
            per_page: 100,
          });
          check(
            Array.isArray(found) && found.every((d) => d.name === name),
            "configuration_dns_scope_denied",
          );
          dns.push(...found);
        }
        const allRoutes = await get(
          "cloudflare",
          `zones/${z.id}/workers/routes`,
        );
        const settings = {};
        for (const name of ["ssl", "min_tls_version", "always_use_https"]) {
          settings[name] = await get(
            "cloudflare",
            `zones/${z.id}/settings/${name}`,
          );
        }
        zones.push({
          id: z.id,
          name: z.name,
          sharedConfigurationReadOnly: true,
          dns,
          settings,
          routes: allRoutes.filter((r) => scope.workers.includes(r.script)),
        });
      }
      const data = sanitizeConfiguration({
        format: CONFIGURATION_FORMAT,
        environment: "staging",
        projectRef: scope.projectRef,
        accountId: scope.accountId,
        capturedAt: captureStartedAt,
        sourceReadsCompletedAt: new Date().toISOString(),
        supabase,
        apps,
        identityProviders,
        workers,
        zones,
        credentialValuesIncluded: false,
        sourceWrites: false,
        crossProviderAtomicSnapshot: false,
      });
      const summary = validateConfigurationPackage(data, scope);
      const bytes = Buffer.from(JSON.stringify(data));
      check(bytes.length <= CONFIGURATION_LIMIT, "configuration_package_limit");
      return { data, bytes, summary, requests };
    },
  };
}
