import { createHmac } from 'node:crypto';
import { ResourceManagementClient } from '@azure/arm-resources';
import { getCredential, onSignOut } from './auth';
import { describeAzureError, graphQuery } from './azure';
import { loadState, updateState } from './store';
import { parseResourceId, sameResourceId } from '../shared/resourceId';
import { APP_TAG } from '../shared/deploy';
import type {
  CreateSnapshotStorageRequest,
  PolicySnapshot,
  SnapshotStorageAccountInfo,
  SnapshotStorageConfig,
} from '../shared/types';

export const DEFAULT_SNAPSHOT_CONTAINER = 'ez-azfw-snapshots';
export const SNAPSHOT_TAG_NAME = 'ez-azfw-ruleman-snapshots';
export const SNAPSHOT_CONTAINER_TAG = 'ez-azfw-ruleman-container';
export const DEFAULT_SOFT_DELETE_DAYS = 30;

const ARM_STORAGE_API_VERSION = '2023-05-01';
const BLOB_REST_VERSION = '2023-11-03';
const ARM_TIMEOUT_MS = 60_000;
const POLL_MS = 3000;

const STORAGE_ACCOUNT_QUERY = `
resources
| where type =~ 'microsoft.storage/storageaccounts'
| extend skuName = tostring(sku.name),
         kind = tostring(kind)
| join kind=leftouter (
    resourcecontainers
    | where type =~ 'microsoft.resources/subscriptions'
    | project subscriptionId, subscriptionName = name
  ) on subscriptionId
| project id, name, subscriptionId, subscriptionName, resourceGroup, location, skuName, kind, tags
| order by subscriptionName asc, name asc`;

interface CachedKey {
  key: string;
  fetchedAt: number;
}

const keyCache = new Map<string, CachedKey>();
onSignOut(() => keyCache.clear());

const isGrsSku = (skuName: string | undefined): boolean =>
  /^(Standard|Premium)_(GRS|RAGRS|GZRS|RAGZRS)$/i.test(skuName ?? '');

function toTags(v: unknown): Record<string, string> {
  if (!v || typeof v !== 'object') return {};
  const out: Record<string, string> = {};
  for (const [k, val] of Object.entries(v)) {
    if (val != null) out[k] = String(val);
  }
  return out;
}

export function validateStorageAccountName(name: string): string | undefined {
  const trimmed = name.trim();
  if (!trimmed) return 'Storage account name is required.';
  if (trimmed.length < 3 || trimmed.length > 24) {
    return `Storage account name must be 3-24 characters (it's ${trimmed.length}).`;
  }
  if (!/^[a-z0-9]+$/.test(trimmed)) {
    return 'Storage account name can only contain lowercase letters and numbers.';
  }
  return undefined;
}

export function validateContainerName(name: string): string | undefined {
  const trimmed = name.trim();
  if (!trimmed) return 'Container name is required.';
  if (trimmed.length < 3 || trimmed.length > 63) {
    return `Container name must be 3-63 characters (it's ${trimmed.length}).`;
  }
  if (
    !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(trimmed) ||
    trimmed.includes('--')
  ) {
    return 'Container name must start and end with a lowercase letter or digit and cannot contain consecutive hyphens.';
  }
  return undefined;
}

async function armToken(): Promise<string> {
  const t = await getCredential().getToken(
    'https://management.azure.com/.default',
  );
  if (!t?.token) throw new Error('Azure did not return an access token.');
  return t.token;
}

async function armRequest<T>(
  path: string,
  init: RequestInit = {},
): Promise<{ status: number; headers: Headers; data: T }> {
  const token = await armToken();
  const url = path.startsWith('https://')
    ? path
    : `https://management.azure.com${path}`;
  const res = await fetch(url, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...(init.headers as Record<string, string> | undefined),
    },
    signal: AbortSignal.timeout(ARM_TIMEOUT_MS),
  });
  const text = await res.text();
  let parsed: unknown;
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = { message: text };
  }
  if (!res.ok) {
    const errObj =
      (parsed as { error?: { code?: string; message?: string } })?.error ??
      (parsed as { code?: string; message?: string });
    throw Object.assign(
      new Error(errObj?.message || `Azure Storage error (HTTP ${res.status}).`),
      {
        statusCode: res.status,
        code: errObj?.code,
      },
    );
  }
  return { status: res.status, headers: res.headers, data: parsed as T };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function listSnapshotStorageAccounts(): Promise<
  SnapshotStorageAccountInfo[]
> {
  const rows = await graphQuery<Record<string, unknown>>(STORAGE_ACCOUNT_QUERY);
  const accounts = rows.map((row) => {
    const tags = toTags(row.tags);
    const skuName = String(row.skuName ?? 'Standard_LRS');
    const isAppTagged =
      tags[SNAPSHOT_TAG_NAME]?.toLowerCase() === 'true' || undefined;
    return {
      id: String(row.id),
      name: String(row.name),
      subscriptionId: String(row.subscriptionId),
      subscriptionName:
        typeof row.subscriptionName === 'string' && row.subscriptionName
          ? row.subscriptionName
          : undefined,
      resourceGroup: String(row.resourceGroup),
      location: String(row.location),
      skuName,
      kind: typeof row.kind === 'string' ? row.kind : undefined,
      isGRS: isGrsSku(skuName),
      isAppTagged,
      containerName: tags[SNAPSHOT_CONTAINER_TAG] || DEFAULT_SNAPSHOT_CONTAINER,
    };
  });
  return accounts.sort(
    (a, b) =>
      Number(!!b.isAppTagged) - Number(!!a.isAppTagged) ||
      Number(b.isGRS) - Number(a.isGRS) ||
      a.name.localeCompare(b.name),
  );
}

/**
 * Resolves the active snapshot storage configuration. If none is saved locally yet,
 * automatically discovers a storage account in the tenant tagged with `ez-azfw-ruleman-snapshots = true`.
 */
export async function getSnapshotStorageConfig(): Promise<SnapshotStorageConfig | null> {
  const saved = loadState().snapshotStorage;
  if (saved?.storageAccountId) return saved;
  try {
    const accounts = await listSnapshotStorageAccounts();
    const tagged = accounts.find((a) => a.isAppTagged);
    if (tagged) {
      const cfg: SnapshotStorageConfig = {
        storageAccountId: tagged.id,
        storageAccountName: tagged.name,
        subscriptionId: tagged.subscriptionId,
        resourceGroup: tagged.resourceGroup,
        location: tagged.location,
        skuName: tagged.skuName,
        containerName: tagged.containerName || DEFAULT_SNAPSHOT_CONTAINER,
      };
      updateState((s) => {
        s.snapshotStorage = cfg;
      });
      return cfg;
    }
  } catch {
    // Discovery is best-effort; caller sees null and prompts the user to select or create storage.
  }
  return null;
}

/**
 * Configures blob soft delete, container soft delete, versioning, app tags, and the
 * snapshot blob container on a storage account.
 */
async function ensureStorageConfigured(
  storageAccountId: string,
  containerName: string,
  softDeleteDays = DEFAULT_SOFT_DELETE_DAYS,
): Promise<{ location: string; skuName: string }> {
  const { subscriptionId, resourceGroup, name } =
    parseResourceId(storageAccountId);
  const basePath = `/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.Storage/storageAccounts/${name}`;

  const acct = await armRequest<{
    location?: string;
    sku?: { name?: string };
    tags?: Record<string, string>;
  }>(`${basePath}?api-version=${ARM_STORAGE_API_VERSION}`);

  // 1. Enable blob soft delete, container soft delete, and blob versioning on the blob service.
  await armRequest(
    `${basePath}/blobServices/default?api-version=${ARM_STORAGE_API_VERSION}`,
    {
      method: 'PUT',
      body: JSON.stringify({
        properties: {
          isVersioningEnabled: true,
          deleteRetentionPolicy: {
            enabled: true,
            days: softDeleteDays,
          },
          containerDeleteRetentionPolicy: {
            enabled: true,
            days: softDeleteDays,
          },
        },
      }),
    },
  );

  // 2. Ensure the blob container exists (private access).
  await armRequest(
    `${basePath}/blobServices/default/containers/${containerName}?api-version=${ARM_STORAGE_API_VERSION}`,
    {
      method: 'PUT',
      body: JSON.stringify({
        properties: {
          publicAccess: 'None',
        },
      }),
    },
  );

  // 3. Tag the storage account so teammates' devices auto-discover it.
  const nextTags: Record<string, string> = {
    ...acct.data.tags,
    [SNAPSHOT_TAG_NAME]: 'true',
    [SNAPSHOT_CONTAINER_TAG]: containerName,
  };
  await armRequest(`${basePath}?api-version=${ARM_STORAGE_API_VERSION}`, {
    method: 'PATCH',
    body: JSON.stringify({ tags: nextTags }),
  }).catch(() => undefined);

  return {
    location: acct.data.location ?? '',
    skuName: acct.data.sku?.name ?? 'Standard_GRS',
  };
}

export async function setSnapshotStorageAccount(
  storageAccountId: string,
  containerName = DEFAULT_SNAPSHOT_CONTAINER,
): Promise<SnapshotStorageConfig> {
  const cleanContainer = containerName.trim() || DEFAULT_SNAPSHOT_CONTAINER;
  const containerErr = validateContainerName(cleanContainer);
  if (containerErr) throw new Error(containerErr);

  const { subscriptionId, resourceGroup, name } =
    parseResourceId(storageAccountId);
  const { location, skuName } = await ensureStorageConfigured(
    storageAccountId,
    cleanContainer,
  );
  const config: SnapshotStorageConfig = {
    storageAccountId,
    storageAccountName: name,
    subscriptionId,
    resourceGroup,
    location,
    skuName,
    containerName: cleanContainer,
  };
  updateState((s) => {
    s.snapshotStorage = config;
  });
  return config;
}

export async function createSnapshotStorageAccount(
  req: CreateSnapshotStorageRequest,
): Promise<SnapshotStorageConfig> {
  const accountName = req.storageAccountName.trim().toLowerCase();
  const nameErr = validateStorageAccountName(accountName);
  if (nameErr) throw new Error(nameErr);

  const containerName = (
    req.containerName?.trim() || DEFAULT_SNAPSHOT_CONTAINER
  ).toLowerCase();
  const containerErr = validateContainerName(containerName);
  if (containerErr) throw new Error(containerErr);

  const skuName = req.skuName || 'Standard_GRS';
  const softDeleteDays = req.softDeleteDays ?? DEFAULT_SOFT_DELETE_DAYS;
  const credential = getCredential();
  const rm = new ResourceManagementClient(credential, req.subscriptionId);

  // Ensure Microsoft.Storage provider is registered.
  try {
    const provider = await rm.providers.get('Microsoft.Storage');
    if (provider.registrationState?.toLowerCase() !== 'registered') {
      await rm.providers.register('Microsoft.Storage');
    }
  } catch {
    // Continue and let storage creation report any permission issues.
  }

  if (req.createResourceGroup) {
    await rm.resourceGroups.createOrUpdate(req.resourceGroup, {
      location: req.location,
      tags: { createdBy: APP_TAG },
    });
  }

  const basePath = `/subscriptions/${req.subscriptionId}/resourceGroups/${req.resourceGroup}/providers/Microsoft.Storage/storageAccounts/${accountName}`;

  const createRes = await armRequest<{
    properties?: { provisioningState?: string };
  }>(`${basePath}?api-version=${ARM_STORAGE_API_VERSION}`, {
    method: 'PUT',
    body: JSON.stringify({
      sku: { name: skuName },
      kind: 'StorageV2',
      location: req.location,
      tags: {
        createdBy: APP_TAG,
        [SNAPSHOT_TAG_NAME]: 'true',
        [SNAPSHOT_CONTAINER_TAG]: containerName,
      },
      properties: {
        accessTier: 'Hot',
        supportsHttpsTrafficOnly: true,
        minimumTlsVersion: 'TLS1_2',
        allowBlobPublicAccess: false,
      },
    }),
  });

  // Poll until the storage account finishes provisioning (~15-30 seconds).
  if (
    createRes.status === 202 ||
    createRes.data?.properties?.provisioningState?.toLowerCase() !== 'succeeded'
  ) {
    const started = Date.now();
    while (Date.now() - started < 180_000) {
      await sleep(POLL_MS);
      try {
        const check = await armRequest<{
          properties?: { provisioningState?: string };
        }>(`${basePath}?api-version=${ARM_STORAGE_API_VERSION}`);
        const state = check.data?.properties?.provisioningState?.toLowerCase();
        if (state === 'succeeded') break;
        if (state === 'failed' || state === 'canceled') {
          throw new Error(
            `Storage account provisioning ended in state ${check.data?.properties?.provisioningState}.`,
          );
        }
      } catch (err) {
        if ((err as { statusCode?: number }).statusCode === 404) continue;
        throw err;
      }
    }
  }

  const storageAccountId = `/subscriptions/${req.subscriptionId}/resourceGroups/${req.resourceGroup}/providers/Microsoft.Storage/storageAccounts/${accountName}`;
  await ensureStorageConfigured(
    storageAccountId,
    containerName,
    softDeleteDays,
  );

  const config: SnapshotStorageConfig = {
    storageAccountId,
    storageAccountName: accountName,
    subscriptionId: req.subscriptionId,
    resourceGroup: req.resourceGroup,
    location: req.location,
    skuName,
    containerName,
  };
  updateState((s) => {
    s.snapshotStorage = config;
  });
  return config;
}

async function getStorageAccountKey(
  config: SnapshotStorageConfig,
): Promise<string> {
  const k = config.storageAccountId.toLowerCase();
  const cached = keyCache.get(k);
  if (cached && Date.now() - cached.fetchedAt < 15 * 60_000) {
    return cached.key;
  }
  const { subscriptionId, resourceGroup, name } = parseResourceId(
    config.storageAccountId,
  );
  const res = await armRequest<{
    keys?: { keyName?: string; value?: string }[];
  }>(
    `/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.Storage/storageAccounts/${name}/listKeys?api-version=${ARM_STORAGE_API_VERSION}`,
    { method: 'POST' },
  );
  const key = res.data.keys?.[0]?.value;
  if (!key) {
    throw new Error(
      `Could not retrieve access keys for storage account ${name}. Check that you have Storage Account Key Operator or Contributor permissions.`,
    );
  }
  keyCache.set(k, { key, fetchedAt: Date.now() });
  return key;
}

function buildSharedKeyAuthHeader(opts: {
  accountName: string;
  accountKey: string;
  method: string;
  contentLength?: number;
  contentType?: string;
  dateUtc: string;
  blobType?: string;
  canonicalizedResource: string;
}): string {
  const len =
    opts.contentLength && opts.contentLength > 0
      ? String(opts.contentLength)
      : '';
  const canonicalizedHeaders = [
    opts.blobType ? `x-ms-blob-type:${opts.blobType}` : null,
    `x-ms-date:${opts.dateUtc}`,
    `x-ms-version:${BLOB_REST_VERSION}`,
  ]
    .filter((h): h is string => !!h)
    .sort()
    .join('\n');

  const stringToSign = [
    opts.method.toUpperCase(),
    '', // Content-Encoding
    '', // Content-Language
    len, // Content-Length
    '', // Content-MD5
    opts.contentType ?? '', // Content-Type
    '', // Date
    '', // If-Modified-Since
    '', // If-Match
    '', // If-None-Match
    '', // If-Unmodified-Since
    '', // Range
    canonicalizedHeaders,
    opts.canonicalizedResource,
  ].join('\n');

  const signature = createHmac('sha256', Buffer.from(opts.accountKey, 'base64'))
    .update(stringToSign, 'utf8')
    .digest('base64');

  return `SharedKey ${opts.accountName}:${signature}`;
}

function snapshotBlobName(snapshot: PolicySnapshot): string {
  const safePolicy = snapshot.policyName
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-');
  const safeTime = snapshot.time.replace(/[:.]/g, '-');
  return `${safePolicy}/${safeTime}-${snapshot.id}.json`;
}

async function putBlobJson(
  config: SnapshotStorageConfig,
  blobName: string,
  bodyText: string,
): Promise<void> {
  const accountName = config.storageAccountName;
  const accountKey = await getStorageAccountKey(config);
  const dateUtc = new Date().toUTCString();
  const bodyBytes = Buffer.from(bodyText, 'utf8');
  const encodedPath = blobName
    .split('/')
    .map((part) => encodeURIComponent(part))
    .join('/');
  const canonicalizedResource = `/${accountName}/${config.containerName}/${encodedPath}`;
  const contentType = 'application/json; charset=utf-8';
  const authHeader = buildSharedKeyAuthHeader({
    accountName,
    accountKey,
    method: 'PUT',
    contentLength: bodyBytes.byteLength,
    contentType,
    dateUtc,
    blobType: 'BlockBlob',
    canonicalizedResource,
  });

  const url = `https://${accountName}.blob.core.windows.net/${config.containerName}/${encodedPath}`;
  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      Authorization: authHeader,
      'Content-Type': contentType,
      'Content-Length': String(bodyBytes.byteLength),
      'x-ms-blob-type': 'BlockBlob',
      'x-ms-date': dateUtc,
      'x-ms-version': BLOB_REST_VERSION,
    },
    body: bodyBytes,
    signal: AbortSignal.timeout(ARM_TIMEOUT_MS),
  });
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    throw new Error(
      `Failed to upload snapshot to Azure Blob Storage (HTTP ${res.status}): ${errText.slice(0, 240)}`,
    );
  }
}

async function getBlobText(
  config: SnapshotStorageConfig,
  blobName: string,
): Promise<string> {
  const accountName = config.storageAccountName;
  const accountKey = await getStorageAccountKey(config);
  const dateUtc = new Date().toUTCString();
  const encodedPath = blobName
    .split('/')
    .map((part) => encodeURIComponent(part))
    .join('/');
  const canonicalizedResource = `/${accountName}/${config.containerName}/${encodedPath}`;
  const authHeader = buildSharedKeyAuthHeader({
    accountName,
    accountKey,
    method: 'GET',
    dateUtc,
    canonicalizedResource,
  });
  const url = `https://${accountName}.blob.core.windows.net/${config.containerName}/${encodedPath}`;
  const res = await fetch(url, {
    method: 'GET',
    headers: {
      Authorization: authHeader,
      'x-ms-date': dateUtc,
      'x-ms-version': BLOB_REST_VERSION,
    },
    signal: AbortSignal.timeout(ARM_TIMEOUT_MS),
  });
  if (!res.ok) {
    throw new Error(
      `Failed to read snapshot blob ${blobName} (HTTP ${res.status}).`,
    );
  }
  return res.text();
}

function parseBlobNamesFromXml(xml: string): string[] {
  const names: string[] = [];
  const blobRegex = /<Blob>[\s\S]*?<Name>([\s\S]*?)<\/Name>[\s\S]*?<\/Blob>/g;
  let m: RegExpExecArray | null;
  while ((m = blobRegex.exec(xml)) !== null) {
    const decoded = m[1]
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'");
    if (decoded.endsWith('.json')) names.push(decoded);
  }
  return names;
}

async function listBlobNames(config: SnapshotStorageConfig): Promise<string[]> {
  const accountName = config.storageAccountName;
  const accountKey = await getStorageAccountKey(config);
  const dateUtc = new Date().toUTCString();
  const canonicalizedResource = `/${accountName}/${config.containerName}\ncomp:list\nrestype:container`;
  const authHeader = buildSharedKeyAuthHeader({
    accountName,
    accountKey,
    method: 'GET',
    dateUtc,
    canonicalizedResource,
  });

  const url = `https://${accountName}.blob.core.windows.net/${config.containerName}?restype=container&comp=list`;
  const res = await fetch(url, {
    method: 'GET',
    headers: {
      Authorization: authHeader,
      'x-ms-date': dateUtc,
      'x-ms-version': BLOB_REST_VERSION,
    },
    signal: AbortSignal.timeout(ARM_TIMEOUT_MS),
  });
  if (res.status === 404) {
    // Container was removed; recreate it on the fly.
    await ensureStorageConfigured(
      config.storageAccountId,
      config.containerName,
    );
    return [];
  }
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    throw new Error(
      `Failed to list snapshots from Azure Blob Storage (HTTP ${res.status}): ${errText.slice(0, 240)}`,
    );
  }
  const xml = await res.text();
  return parseBlobNamesFromXml(xml);
}

/**
 * Uploads a single cumulative commit snapshot to the centralized Azure Blob Storage container.
 * Throws if centralized snapshot storage is not configured.
 */
export async function saveSnapshotToCentralStorage(
  snapshot: PolicySnapshot,
): Promise<void> {
  const config = await getSnapshotStorageConfig();
  if (!config) {
    throw new Error(
      'Centralized snapshot storage is not configured. Configure an Azure GRS Blob Storage account in the Snapshots tab before committing changes.',
    );
  }
  const blobName = snapshotBlobName(snapshot);
  await putBlobJson(config, blobName, JSON.stringify(snapshot, null, 2));
}

/**
 * Loads all snapshots from the centralized Azure Blob Storage container, sorted newest first.
 * Throws if centralized snapshot storage is not configured.
 */
export async function listSnapshotsFromCentralStorage(): Promise<
  PolicySnapshot[]
> {
  const config = await getSnapshotStorageConfig();
  if (!config) {
    throw new Error(
      'Centralized snapshot storage is not configured. Select or create an Azure Blob Storage account to view and store shared snapshots.',
    );
  }
  const names = await listBlobNames(config);
  // Sort descending by blob name so we fetch newest first.
  const sortedNames = [...names]
    .sort((a, b) => b.localeCompare(a))
    .slice(0, 200);
  const snapshots: PolicySnapshot[] = [];

  // Fetch in small batches to keep latency low without overwhelming the socket pool.
  const batchSize = 8;
  for (let i = 0; i < sortedNames.length; i += batchSize) {
    const chunk = sortedNames.slice(i, i + batchSize);
    const loaded = await Promise.all(
      chunk.map(async (name) => {
        try {
          const text = await getBlobText(config, name);
          const parsed = JSON.parse(text) as PolicySnapshot;
          if (
            parsed &&
            typeof parsed.id === 'string' &&
            typeof parsed.policyId === 'string' &&
            Array.isArray(parsed.groups)
          ) {
            return parsed;
          }
        } catch (err) {
          console.error(
            `[snapshotStorage] Couldn't parse snapshot blob ${name}:`,
            describeAzureError(err),
          );
        }
        return null;
      }),
    );
    for (const item of loaded) {
      if (item) snapshots.push(item);
    }
  }

  return snapshots.sort((a, b) => b.time.localeCompare(a.time));
}

export async function getSnapshotFromCentralStorage(
  snapshotId: string,
): Promise<PolicySnapshot | undefined> {
  const all = await listSnapshotsFromCentralStorage();
  return all.find((s) => s.id === snapshotId);
}

/**
 * Checks whether centralized storage is configured and reachable before allowing a commit.
 */
export async function requireSnapshotStorageConfigured(): Promise<SnapshotStorageConfig> {
  const config = await getSnapshotStorageConfig();
  if (
    !config ||
    !sameResourceId(config.storageAccountId, config.storageAccountId)
  ) {
    throw new Error(
      'Centralized snapshot storage is required before committing changes. Open the Snapshots tab to select or create a shared Azure GRS Blob Storage account.',
    );
  }
  return config;
}
