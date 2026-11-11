import { createHash } from 'node:crypto';
import { ResourceManagementClient } from '@azure/arm-resources';
import { getCredential, getPrincipal, getStorageToken } from './auth';
import { describeAzureError, graphQuery } from './azure';
import { loadState, updateState } from './store';
import { parseResourceId } from '../shared/resourceId';
import { APP_TAG } from '../shared/deploy';
import { isThreatIntelMode } from '../shared/policyMode';
import { armRequest } from './arm';
import type {
  CommitHistoryEntry,
  CommitRecord,
  CreateSnapshotStorageRequest,
  PolicySnapshot,
  SnapshotStorageAccountInfo,
  SnapshotStorageConfig,
  SnapshotStorageSetup,
} from '../shared/types';

export const DEFAULT_SNAPSHOT_CONTAINER = 'ez-azfw-snapshots';
/** Commit history lives beside the snapshots, in the same account, so one setup and one role cover both. */
export const DEFAULT_HISTORY_CONTAINER = 'ez-azfw-history';
// Keep discovery keys stable across app renames so existing shared storage is still found.
export const SNAPSHOT_TAG_NAME = 'ez-azfw-ruleman-snapshots';
export const SNAPSHOT_CONTAINER_TAG = 'ez-azfw-ruleman-container';
export const HISTORY_CONTAINER_TAG = 'ez-azfw-ruleman-history-container';
export const DEFAULT_SOFT_DELETE_DAYS = 30;

const ARM_STORAGE_API_VERSION = '2023-05-01';
const ARM_AUTHORIZATION_API_VERSION = '2022-04-01';
const BLOB_REST_VERSION = '2023-11-03';
const ARM_TIMEOUT_MS = 60_000;
const POLL_MS = 3000;
const MAX_LISTED_SNAPSHOTS = 200;
const MAX_LISTED_COMMITS = 500;

const BLOB_DATA_CONTRIBUTOR_NAME = 'Storage Blob Data Contributor';
const BLOB_DATA_CONTRIBUTOR_ROLE_ID = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe';

// Kept deliberately plain (no extend/join over built-in columns), since Resource Graph rejects
// queries it can't parse with an unhelpful BadRequest. Names and SKUs are derived in code.
const STORAGE_ACCOUNT_QUERY = `
resources
| where type =~ 'microsoft.storage/storageaccounts'
| project id, name, subscriptionId, resourceGroup, location, sku, kind, tags`;

const SUBSCRIPTION_NAME_QUERY = `
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| project subscriptionId, subscriptionName = name`;

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

/** Snapshots and commit history must live in separate containers, so each can be listed and managed on its own. */
export function validateContainerChoice(
  snapshotContainer: string,
  historyContainer: string,
): string | undefined {
  if (
    snapshotContainer.trim().toLowerCase() ===
    historyContainer.trim().toLowerCase()
  )
    return 'Commit history must use a different blob container than snapshots.';
  const snapshotErr = validateContainerName(snapshotContainer);
  if (snapshotErr) return `Snapshot container: ${snapshotErr}`;
  const historyErr = validateContainerName(historyContainer);
  if (historyErr) return `Commit history container: ${historyErr}`;
  return undefined;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function listSnapshotStorageAccounts(): Promise<
  SnapshotStorageAccountInfo[]
> {
  const rows = await graphQuery<Record<string, unknown>>(STORAGE_ACCOUNT_QUERY);
  // Subscription names are only a convenience; the list still works without them.
  const subscriptionNames = new Map<string, string>();
  try {
    for (const s of await graphQuery<Record<string, unknown>>(
      SUBSCRIPTION_NAME_QUERY,
    )) {
      if (typeof s.subscriptionName === 'string')
        subscriptionNames.set(String(s.subscriptionId), s.subscriptionName);
    }
  } catch {
    // Fall back to no names.
  }
  const accounts = rows.map((row) => {
    const tags = toTags(row.tags);
    const skuName =
      (row.sku as { name?: unknown } | null | undefined)?.name != null
        ? String((row.sku as { name?: unknown }).name)
        : 'Standard_LRS';
    const isAppTagged =
      tags[SNAPSHOT_TAG_NAME]?.toLowerCase() === 'true' || undefined;
    return {
      id: String(row.id),
      name: String(row.name),
      subscriptionId: String(row.subscriptionId),
      subscriptionName: subscriptionNames.get(String(row.subscriptionId)),
      resourceGroup: String(row.resourceGroup),
      location: String(row.location),
      skuName,
      kind: typeof row.kind === 'string' ? row.kind : undefined,
      isGRS: isGrsSku(skuName),
      isAppTagged,
      containerName: tags[SNAPSHOT_CONTAINER_TAG] || DEFAULT_SNAPSHOT_CONTAINER,
      historyContainerName:
        tags[HISTORY_CONTAINER_TAG] || DEFAULT_HISTORY_CONTAINER,
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
 * Throws when discovery fails, so the caller can tell that apart from "nothing configured".
 */
export async function getSnapshotStorageConfig(): Promise<SnapshotStorageConfig | null> {
  const saved = loadState().snapshotStorage;
  if (saved?.storageAccountId) return saved;
  const accounts = await listSnapshotStorageAccounts();
  const tagged = accounts.find((a) => a.isAppTagged);
  if (!tagged) return null;
  const cfg: SnapshotStorageConfig = {
    storageAccountId: tagged.id,
    storageAccountName: tagged.name,
    subscriptionId: tagged.subscriptionId,
    resourceGroup: tagged.resourceGroup,
    location: tagged.location,
    skuName: tagged.skuName,
    containerName: tagged.containerName || DEFAULT_SNAPSHOT_CONTAINER,
    historyContainerName: tagged.historyContainerName,
  };
  updateState((s) => {
    s.snapshotStorage = cfg;
  });
  return cfg;
}

/** Creates a private blob container if it doesn't exist (management plane, no blob role needed). */
async function ensureContainer(
  storageAccountId: string,
  containerName: string,
): Promise<void> {
  const { subscriptionId, resourceGroup, name } =
    parseResourceId(storageAccountId);
  await armRequest(
    `/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.Storage/storageAccounts/${name}/blobServices/default/containers/${containerName}?api-version=${ARM_STORAGE_API_VERSION}`,
    {
      method: 'PUT',
      body: JSON.stringify({ properties: { publicAccess: 'None' } }),
    },
  );
}

/**
 * Configures blob soft delete, container soft delete, versioning, app tags, and the
 * snapshot and commit-history blob containers on a storage account.
 */
async function ensureStorageConfigured(
  storageAccountId: string,
  containerName: string,
  historyContainerName: string,
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

  // 2. Ensure the snapshot and commit-history blob containers exist (private access).
  await ensureContainer(storageAccountId, containerName);
  await ensureContainer(storageAccountId, historyContainerName);

  // 3. Tag the storage account so teammates' devices auto-discover it.
  const nextTags: Record<string, string> = {
    ...acct.data.tags,
    [SNAPSHOT_TAG_NAME]: 'true',
    [SNAPSHOT_CONTAINER_TAG]: containerName,
    [HISTORY_CONTAINER_TAG]: historyContainerName,
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
  historyContainerName = DEFAULT_HISTORY_CONTAINER,
): Promise<SnapshotStorageConfig> {
  const cleanContainer = containerName.trim() || DEFAULT_SNAPSHOT_CONTAINER;
  const cleanHistory = historyContainerName.trim() || DEFAULT_HISTORY_CONTAINER;
  const containerErr = validateContainerChoice(cleanContainer, cleanHistory);
  if (containerErr) throw new Error(containerErr);

  const { subscriptionId, resourceGroup, name } =
    parseResourceId(storageAccountId);
  const { location, skuName } = await ensureStorageConfigured(
    storageAccountId,
    cleanContainer,
    cleanHistory,
  );
  const config: SnapshotStorageConfig = {
    storageAccountId,
    storageAccountName: name,
    subscriptionId,
    resourceGroup,
    location,
    skuName,
    containerName: cleanContainer,
    historyContainerName: cleanHistory,
  };
  updateState((s) => {
    s.snapshotStorage = config;
  });
  return config;
}

/** Stable per (account, user), so granting twice is harmless. */
function roleAssignmentName(scope: string, principalId: string): string {
  const h = createHash('sha256')
    .update(
      `${scope.toLowerCase()}|${principalId}|${BLOB_DATA_CONTRIBUTOR_ROLE_ID}`,
    )
    .digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

/** Gives the signed-in user blob read/write access to a storage account they just created. */
async function grantBlobDataContributor(
  storageAccountId: string,
): Promise<void> {
  const { subscriptionId } = parseResourceId(storageAccountId);
  const principal = await getPrincipal();
  const name = roleAssignmentName(storageAccountId, principal.objectId);
  try {
    await armRequest(
      `${storageAccountId}/providers/Microsoft.Authorization/roleAssignments/${name}?api-version=${ARM_AUTHORIZATION_API_VERSION}`,
      {
        method: 'PUT',
        body: JSON.stringify({
          properties: {
            roleDefinitionId: `/subscriptions/${subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/${BLOB_DATA_CONTRIBUTOR_ROLE_ID}`,
            principalId: principal.objectId,
            principalType: principal.type,
          },
        }),
      },
    );
  } catch (err) {
    // Already granted (possibly under another assignment name).
    const e = err as { statusCode?: number; code?: string };
    if (e.statusCode === 409 || e.code === 'RoleAssignmentExists') return;
    throw err;
  }
}

export async function createSnapshotStorageAccount(
  req: CreateSnapshotStorageRequest,
): Promise<SnapshotStorageSetup> {
  const accountName = req.storageAccountName.trim().toLowerCase();
  const nameErr = validateStorageAccountName(accountName);
  if (nameErr) throw new Error(nameErr);

  const containerName = (
    req.containerName?.trim() || DEFAULT_SNAPSHOT_CONTAINER
  ).toLowerCase();
  const historyContainerName = (
    req.historyContainerName?.trim() || DEFAULT_HISTORY_CONTAINER
  ).toLowerCase();
  const containerErr = validateContainerChoice(
    containerName,
    historyContainerName,
  );
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
        [HISTORY_CONTAINER_TAG]: historyContainerName,
      },
      properties: {
        accessTier: 'Hot',
        supportsHttpsTrafficOnly: true,
        minimumTlsVersion: 'TLS1_2',
        allowBlobPublicAccess: false,
        // Anonymous access stays off; this keeps the endpoint reachable (with Entra sign-in and
        // the blob data role) instead of inheriting whatever networking default applies.
        publicNetworkAccess: 'Enabled',
        networkAcls: { defaultAction: 'Allow', bypass: 'AzureServices' },
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
    historyContainerName,
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
    historyContainerName,
  };
  updateState((s) => {
    s.snapshotStorage = config;
  });

  // Creating the account doesn't grant blob data access, even to its owner.
  try {
    await grantBlobDataContributor(storageAccountId);
    return { ...config, roleAssigned: true };
  } catch (err) {
    console.error(
      `[snapshotStorage] Couldn't assign ${BLOB_DATA_CONTRIBUTOR_NAME} on ${accountName}:`,
      err,
    );
    return {
      ...config,
      roleAssigned: false,
      roleAssignmentError: `Assign yourself the "${BLOB_DATA_CONTRIBUTOR_NAME}" role on ${accountName} before you can view or save snapshots.`,
    };
  }
}

/** Reads the account's network settings to say whether networking is what's refusing the request. */
async function describeNetworking(
  config: SnapshotStorageConfig,
): Promise<string> {
  try {
    const { data } = await armRequest<{
      properties?: {
        publicNetworkAccess?: string;
        networkAcls?: { defaultAction?: string };
      };
    }>(`${config.storageAccountId}?api-version=${ARM_STORAGE_API_VERSION}`);
    const access = data.properties?.publicNetworkAccess ?? 'Enabled';
    const action = data.properties?.networkAcls?.defaultAction ?? 'Allow';
    if (
      access.toLowerCase() === 'disabled' ||
      action.toLowerCase() === 'deny'
    ) {
      return `The storage account's networking blocks this computer (public network access: ${access}, firewall default action: ${action}). In the Azure portal open the account's Networking page and allow your IP address (or an allowed network), then try again.`;
    }
    return `The account's networking allows public access (public network access: ${access}, firewall default action: ${action}), so check for a private endpoint, an Azure Policy or a Conditional Access rule that blocks storage access from this computer.`;
  } catch {
    return "This can happen when the account's networking (firewall, disabled public network access, or a private endpoint) doesn't allow this computer.";
  }
}

/**
 * Explains a failed blob request using Azure's own error code, since a 401/403 has several very
 * different causes (missing data role, storage firewall, rejected token) that need different fixes.
 */
async function blobFailure(
  res: Response,
  config: SnapshotStorageConfig,
  action: string,
): Promise<Error> {
  const { status } = res;
  const body = await res.text().catch(() => '');
  const code =
    res.headers.get('x-ms-error-code') ??
    /<Code>([^<]+)<\/Code>/.exec(body)?.[1] ??
    '';
  const message = (/<Message>([^<]*)/.exec(body)?.[1] ?? '')
    .split(/\r?\n/)[0]
    .trim();
  const where = `${config.storageAccountName}/${config.containerName}`;
  const reported = `(HTTP ${status}${code ? `, ${code}` : ''})`;
  console.error(
    `[snapshotStorage] Blob request failed: ${action} in ${where} ${reported} ${message}`,
  );

  let text: string;
  if (code === 'AuthorizationPermissionMismatch') {
    text = `Your account isn't allowed to ${action} in ${where}. Assign yourself the "${BLOB_DATA_CONTRIBUTOR_NAME}" role on the storage account ${reported}.`;
  } else if (status === 403) {
    // AuthorizationFailure and similar: the identity may be fine, but the request was refused.
    text = `Azure Storage refused the request to ${action} in ${where} ${reported}. ${await describeNetworking(config)} ${message}`;
  } else if (status === 401) {
    text = `Azure Storage rejected your sign-in token when trying to ${action} in ${where} ${reported}. Sign out and in again. ${message}`;
  } else {
    text = `Failed to ${action} in ${where} ${reported}. ${message}`;
  }
  return Object.assign(new Error(text.trim()), {
    statusCode: status,
    code: code || 'BlobRequestFailed',
  });
}

/** Calls the Blob service with the signed-in user's Entra token (no account keys). */
async function blobFetch(
  config: SnapshotStorageConfig,
  blobPath: string,
  init: { method: string; query?: Record<string, string>; body?: string },
): Promise<Response> {
  const token = await getStorageToken();
  const query = init.query ? `?${new URLSearchParams(init.query)}` : '';
  const url = `https://${config.storageAccountName}.blob.core.windows.net/${config.containerName}${blobPath}${query}`;
  return fetch(url, {
    method: init.method,
    headers: {
      Authorization: `Bearer ${token}`,
      'x-ms-version': BLOB_REST_VERSION,
      ...(init.body
        ? {
            'Content-Type': 'application/json; charset=utf-8',
            'x-ms-blob-type': 'BlockBlob',
          }
        : {}),
    },
    body: init.body,
    signal: AbortSignal.timeout(ARM_TIMEOUT_MS),
  });
}

function snapshotBlobName(snapshot: PolicySnapshot): string {
  const safePolicy = snapshot.policyName
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-');
  const safeTime = snapshot.time.replace(/[:.]/g, '-');
  return `${safePolicy}/${safeTime}-${snapshot.id}.json`;
}

const encodeBlobPath = (blobName: string): string =>
  `/${blobName
    .split('/')
    .map((part) => encodeURIComponent(part))
    .join('/')}`;

async function putBlobJson(
  config: SnapshotStorageConfig,
  blobName: string,
  bodyText: string,
  what = 'upload the snapshot',
): Promise<void> {
  const put = () =>
    blobFetch(config, encodeBlobPath(blobName), {
      method: 'PUT',
      body: bodyText,
    });
  let res = await put();
  if (res.status === 404) {
    // The container is missing (e.g. an account set up before the history container existed).
    await ensureContainer(config.storageAccountId, config.containerName);
    res = await put();
  }
  if (!res.ok) {
    throw await blobFailure(res, config, what);
  }
}

/** Returns the blob's text, or undefined when it no longer exists. */
async function getBlobText(
  config: SnapshotStorageConfig,
  blobName: string,
): Promise<string | undefined> {
  const res = await blobFetch(config, encodeBlobPath(blobName), {
    method: 'GET',
  });
  if (res.status === 404) return undefined;
  if (!res.ok) {
    throw await blobFailure(res, config, `read ${blobName}`);
  }
  return res.text();
}

function parseBlobPage(xml: string): { names: string[]; next?: string } {
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
  const next = /<NextMarker>([^<]+)<\/NextMarker>/.exec(xml)?.[1];
  return { names, next };
}

/** Lists the snapshot blobs, following Azure's continuation markers. */
async function listBlobNames(
  config: SnapshotStorageConfig,
  maxResults?: number,
): Promise<string[]> {
  const names: string[] = [];
  let marker: string | undefined;
  do {
    const res = await blobFetch(config, '', {
      method: 'GET',
      query: {
        restype: 'container',
        comp: 'list',
        ...(maxResults ? { maxresults: String(maxResults) } : {}),
        ...(marker ? { marker } : {}),
      },
    });
    if (res.status === 404) {
      // Container was removed; recreate it on the fly.
      await ensureContainer(config.storageAccountId, config.containerName);
      return [];
    }
    if (!res.ok) {
      throw await blobFailure(res, config, 'list the blobs');
    }
    const page = parseBlobPage(await res.text());
    names.push(...page.names);
    marker = maxResults ? undefined : page.next;
  } while (marker);
  return names;
}

/** Blob names are `policy/<time>-<id>.json`; the time prefix sorts newest first across policies. */
const blobTime = (name: string): string =>
  name.slice(name.lastIndexOf('/') + 1);

function isSnapshot(value: unknown): value is PolicySnapshot {
  const s = value as PolicySnapshot | null;
  return (
    !!s &&
    typeof s.id === 'string' &&
    typeof s.policyId === 'string' &&
    typeof s.policyName === 'string' &&
    typeof s.time === 'string' &&
    (s.threatIntelMode === undefined || isThreatIntelMode(s.threatIntelMode)) &&
    Array.isArray(s.groups) &&
    s.groups.every(
      (g) =>
        !!g &&
        typeof g.name === 'string' &&
        Array.isArray(g.ruleCollections) &&
        g.ruleCollections.every((c) => !!c && Array.isArray(c.rules)),
    )
  );
}

/** Loads one snapshot blob; undefined when it's gone or isn't a valid snapshot. */
async function loadSnapshotBlob(
  config: SnapshotStorageConfig,
  name: string,
): Promise<PolicySnapshot | undefined> {
  const text = await getBlobText(config, name);
  if (text === undefined) return undefined;
  try {
    const parsed: unknown = JSON.parse(text);
    if (isSnapshot(parsed)) return parsed;
    console.error(`[snapshotStorage] Skipping ${name}: not a valid snapshot.`);
  } catch (err) {
    console.error(
      `[snapshotStorage] Couldn't parse snapshot blob ${name}:`,
      describeAzureError(err),
    );
  }
  return undefined;
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
  // Newest first across all policies, so the cap never hides a policy's latest snapshot.
  const sortedNames = [...names]
    .sort((a, b) => blobTime(b).localeCompare(blobTime(a)))
    .slice(0, MAX_LISTED_SNAPSHOTS);
  const snapshots: PolicySnapshot[] = [];

  // Fetch in small batches to keep latency low without overwhelming the socket pool.
  const batchSize = 8;
  for (let i = 0; i < sortedNames.length; i += batchSize) {
    const chunk = sortedNames.slice(i, i + batchSize);
    const loaded = await Promise.all(
      chunk.map((name) => loadSnapshotBlob(config, name)),
    );
    for (const item of loaded) {
      if (item) snapshots.push(item);
    }
  }

  return snapshots.sort((a, b) => b.time.localeCompare(a.time));
}

/** Finds a snapshot by ID directly (the ID is part of its blob name), without the list cap. */
export async function getSnapshotFromCentralStorage(
  snapshotId: string,
): Promise<PolicySnapshot | undefined> {
  const config = await getSnapshotStorageConfig();
  if (!config) {
    throw new Error(
      'Centralized snapshot storage is not configured. Select or create an Azure Blob Storage account to view and store shared snapshots.',
    );
  }
  const name = (await listBlobNames(config)).find((n) =>
    n.endsWith(`-${snapshotId}.json`),
  );
  return name ? loadSnapshotBlob(config, name) : undefined;
}

/**
 * Checks that centralized storage is configured and that the signed-in user can read its blobs,
 * so a commit never starts when its snapshot couldn't be saved.
 */
export async function requireSnapshotStorageConfigured(): Promise<SnapshotStorageConfig> {
  const config = await getSnapshotStorageConfig();
  if (!config) {
    throw new Error(
      'Centralized snapshot storage is required before committing changes. Open the Snapshots tab to select or create a shared Azure GRS Blob Storage account.',
    );
  }
  await listBlobNames(config, 1);
  return config;
}

/** The config pointed at the commit-history container; refuses to share the snapshot container. */
function historyConfig(config: SnapshotStorageConfig): SnapshotStorageConfig {
  const containerName =
    config.historyContainerName || DEFAULT_HISTORY_CONTAINER;
  const problem = validateContainerChoice(config.containerName, containerName);
  if (problem) {
    throw new Error(
      `${problem} Open the Snapshots tab, choose Change storage, and pick a separate container for the commit history.`,
    );
  }
  return { ...config, containerName };
}

const commitBlobName = (record: CommitRecord): string =>
  `${record.time.replace(/[:.]/g, '-')}-${record.id}.json`;

function isCommitRecord(value: unknown): value is CommitRecord {
  const r = value as CommitRecord | null;
  return (
    !!r &&
    typeof r.id === 'string' &&
    typeof r.time === 'string' &&
    typeof r.description === 'string' &&
    Array.isArray(r.results) &&
    r.results.every(
      (x) => !!x && typeof x.groupId === 'string' && typeof x.ok === 'boolean',
    )
  );
}

/** Saves a finished commit to the shared history, so teammates can see who changed what. */
export async function saveCommitToCentralHistory(
  record: CommitRecord,
): Promise<void> {
  const config = await getSnapshotStorageConfig();
  if (!config) {
    throw new Error(
      'Centralized storage is not configured. Select or create a shared Azure Blob Storage account in the Snapshots tab to keep a shared commit history.',
    );
  }
  // Transient notices about this device's upload attempts aren't part of the shared record.
  const { snapshotError: _s, historyError: _h, ...saved } = record;
  await putBlobJson(
    historyConfig(config),
    commitBlobName(record),
    JSON.stringify(saved, null, 2),
    'save the commit to the shared history',
  );
}

/**
 * Loads the shared commit history, newest first. Commits from this device that never reached
 * shared storage (`local`) are included and flagged, so nothing recorded here goes missing.
 */
export async function listCommitHistoryFromCentralStorage(
  local: CommitRecord[],
): Promise<CommitHistoryEntry[]> {
  const config = await getSnapshotStorageConfig();
  if (!config) {
    throw new Error(
      'Centralized storage is not configured. Select or create a shared Azure Blob Storage account in the Snapshots tab to see the shared commit history.',
    );
  }
  const history = historyConfig(config);
  const names = (await listBlobNames(history))
    .sort((a, b) => blobTime(b).localeCompare(blobTime(a)))
    .slice(0, MAX_LISTED_COMMITS);
  const central: CommitRecord[] = [];
  const batchSize = 8;
  for (let i = 0; i < names.length; i += batchSize) {
    const loaded = await Promise.all(
      names.slice(i, i + batchSize).map(async (name) => {
        const text = await getBlobText(history, name);
        if (text === undefined) return undefined;
        try {
          const parsed: unknown = JSON.parse(text);
          if (isCommitRecord(parsed)) return parsed;
          console.error(
            `[commitHistory] Skipping ${name}: not a commit record.`,
          );
        } catch (err) {
          console.error(
            `[commitHistory] Couldn't parse ${name}:`,
            describeAzureError(err),
          );
        }
        return undefined;
      }),
    );
    for (const record of loaded) if (record) central.push(record);
  }
  const shared = new Set(central.map((r) => r.id));
  const onlyHere = local
    .filter((r) => !shared.has(r.id))
    .map((r): CommitHistoryEntry => ({ ...r, localOnly: true }));
  return [...central, ...onlyHere].sort((a, b) => b.time.localeCompare(a.time));
}
