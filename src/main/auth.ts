import { app, BrowserWindow, session, shell } from 'electron';
import {
  InteractionRequiredAuthError,
  PublicClientApplication,
  type AccountInfo as MsalAccount,
  type AuthenticationResult,
} from '@azure/msal-node';
import {
  AzureCliCredential,
  type AccessToken,
  type TokenCredential,
} from '@azure/identity';
import { loadState, updateState, type SavedSession } from './store';
import {
  EncryptedCachePlugin,
  canPersistTokens,
  deleteTokenCache,
} from './tokenCache';
import type {
  AccountInfo,
  AuthMethod,
  TenantInfo,
  TenantStatus,
} from '../shared/types';

const ARM_SCOPES = ['https://management.azure.com/.default'];
const STORAGE_SCOPES = ['https://storage.azure.com/.default'];
const ARM = 'https://management.azure.com';
const LOGIN = 'https://login.microsoftonline.com';
const TENANTS_URL = `${ARM}/tenants?api-version=2022-12-01`;
const GRAPH_URL = `${ARM}/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01`;
const PROBE_QUERY =
  "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId";
const MAX_PROBED_TENANTS = 30;
const REFRESH_MARGIN_MS = 5 * 60_000;
const SIGNED_OUT = 'You are signed out. Sign in to Azure to continue.';

// Sign-in uses the Azure CLI's public client ID (as @azure/identity does by default), so anyone
// can sign in without an app registration or admin consent in their directory. This is a
// deliberate trade-off: tokens for this ID can be exchanged for other Microsoft first-party APIs,
// so the refresh token is only ever stored encrypted (tokenCache.ts) and never leaves this
// process. A publisher with its own Entra app registration can set EZAZFW_CLIENT_ID instead.
// (Not AZURE_CLIENT_ID: other tools set that for their own app registrations or service principals.)
const DEFAULT_CLIENT_ID = '04b07795-8ddb-461a-bbee-02f9e1bf7b46';

const TENANT =
  /^([0-9a-f-]{36}|[a-z0-9-]+(\.[a-z0-9-]+)+|organizations|common)$/i;
const GENERIC_AUTHORITIES = ['organizations', 'common'];
/** Own browser session for the sign-in window, kept apart from the app's pages. */
const SIGN_IN_PARTITION = 'persist:signin';

const PAGE = (title: string, body: string) =>
  `<!doctype html><meta charset="utf-8"><title>EZ AzFW Manager</title><body style="font-family:Segoe UI,system-ui,sans-serif;background:#0F1B2D;color:#E4EAF3;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div><h1 style="font-size:22px;margin:0 0 8px">${title}</h1><p style="color:#93A4BD;margin:0">${body}</p></div></body>`;

/*
 * How sign-in works (verified against personal and work accounts):
 * 1. One interactive sign-in through the generic "organizations" endpoint identifies the account.
 *    For personal Microsoft accounts this yields a "pass-through" token that Azure Resource Graph
 *    rejects, but it can list the account's directories.
 * 2. For each directory, the refresh token from that sign-in is redeemed silently against the
 *    directory's own authority. forceRefresh is required: MSAL's cache lookup otherwise returns
 *    the cached pass-through token regardless of the requested authority.
 * 3. Directory tokens are cached here per directory and refreshed shortly before they expire.
 * This is the Azure CLI's approach and needs no extra browser prompts in the normal case.
 *
 * Staying signed in: MSAL's cache (with the refresh token) is saved encrypted by tokenCache.ts,
 * and the store remembers which account to use. At startup restoreSession() repeats steps 1-3
 * silently; if anything needs interaction, the user just sees the sign-in screen.
 */
let method: AuthMethod | null = null;
let pca: PublicClientApplication | null = null;
let cachePlugin: EncryptedCachePlugin | null = null;
let msalAccount: MsalAccount | null = null;
let cli: AzureCliCredential | null = null;
const tenantTokens = new Map<string, AccessToken>();
/** Azure Storage (blob data) tokens per directory, kept apart from the ARM tokens. */
const storageTokens = new Map<string, AccessToken>();
let account: AccountInfo | null = null;
let activeTenant: string | undefined;
let pendingSignIn: AbortController | null = null;
let restoring: Promise<AccountInfo | null> | null = null;
let credential: TokenCredential | null = null;
/** Bumped whenever the signed-in state is cleared, so work started before it can't write back. */
let generation = 0;
/** Pending token-cache writes of the last closed sign-in; the cache file is deleted after them. */
let closingCache: Promise<void> = Promise.resolve();
const resetListeners = new Set<() => void>();
let signInWindow: BrowserWindow | null = null;

const key = (tenantId: string) => tenantId.toLowerCase();

function createPca(): PublicClientApplication {
  cachePlugin = new EncryptedCachePlugin();
  return new PublicClientApplication({
    auth: {
      clientId: process.env.EZAZFW_CLIENT_ID || DEFAULT_CLIENT_ID,
      authority: `${LOGIN}/organizations`,
    },
    cache: { cachePlugin },
  });
}

class SignInRequired extends Error {
  name = 'AuthenticationRequiredError';
}

function decodeClaims(token: string): Record<string, unknown> {
  try {
    return JSON.parse(
      Buffer.from(token.split('.')[1], 'base64url').toString('utf8'),
    );
  } catch {
    return {};
  }
}

function usernameFrom(
  claims: Record<string, unknown>,
  fallback?: string,
): string | undefined {
  const raw = (claims.email ??
    claims.upn ??
    claims.unique_name ??
    claims.preferred_username ??
    fallback) as string | undefined;
  // Personal accounts show up as "live.com#name@outlook.com".
  return raw?.replace(/^[^#]+#/, '');
}

const toAccessToken = (r: AuthenticationResult): AccessToken => ({
  token: r.accessToken,
  expiresOnTimestamp: r.expiresOn?.getTime() ?? Date.now() + 30 * 60_000,
});

function abortable<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return promise;
  let onAbort = () => {};
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => reject(new Error('Sign-in was cancelled.'));
    if (signal.aborted) onAbort();
    else signal.addEventListener('abort', onAbort, { once: true });
  });
  return Promise.race([promise, aborted]).finally(() =>
    signal.removeEventListener('abort', onAbort),
  );
}

const isLoopback = (target: string): boolean => {
  try {
    const { protocol, hostname } = new URL(target);
    return (
      protocol === 'http:' &&
      (hostname === 'localhost' || hostname === '127.0.0.1')
    );
  } catch {
    return false;
  }
};

function closeSignInWindow(): void {
  const win = signInWindow;
  signInWindow = null;
  if (win && !win.isDestroyed()) win.close();
}

/**
 * Shows Microsoft's sign-in page in an app window rather than the system browser, so the account
 * picker appears instead of whichever browser profile happens to be the default. MSAL's localhost
 * listener still receives the redirect; the window closes once it gets there. Closing the window
 * early calls onCancel.
 */
function openSignInWindow(url: string, onCancel: () => void): void {
  closeSignInWindow();
  const ses = session.fromPartition(SIGN_IN_PARTITION);
  ses.setPermissionRequestHandler((_wc, _permission, callback) =>
    callback(false),
  );
  const win = new BrowserWindow({
    parent: BrowserWindow.getFocusedWindow() ?? undefined,
    width: 520,
    height: 720,
    minimizable: false,
    autoHideMenuBar: true,
    title: 'Sign in to Azure',
    backgroundColor: '#FFFFFF',
    webPreferences: {
      session: ses,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      devTools: !app.isPackaged,
    },
  });
  signInWindow = win;
  let finished = false;

  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  // Sign-in may pass through federated identity providers (any HTTPS site), then ends at MSAL's
  // localhost listener. Nothing else may load here.
  const guard = (event: Electron.Event, target: string) => {
    if (!target.startsWith('https://') && !isLoopback(target))
      event.preventDefault();
  };
  win.webContents.on('will-navigate', guard);
  win.webContents.on('will-redirect', guard);
  win.webContents.on('did-navigate', (_e, target) => {
    if (!isLoopback(target)) return;
    // MSAL's listener has the response now; there's nothing left to show.
    finished = true;
    win.close();
  });
  win.on('closed', () => {
    if (signInWindow === win) signInWindow = null;
    if (!finished) onCancel();
  });
  // Rejections here are aborted loads (redirects, window closed); the window shows real errors.
  win.loadURL(url).catch(() => undefined);
}

async function interactive(
  authority: string,
  signal?: AbortSignal,
  scopes: string[] = ARM_SCOPES,
): Promise<AuthenticationResult> {
  if (!pca) throw new Error(SIGNED_OUT);
  const inWindow = method === 'window';
  const closed = new AbortController();
  const cancel = signal
    ? AbortSignal.any([signal, closed.signal])
    : closed.signal;
  try {
    return await abortable(
      pca.acquireTokenInteractive({
        scopes,
        authority,
        account: msalAccount ?? undefined,
        loginHint: msalAccount?.username,
        // First sign-in: always let the user pick (or add) the account to use.
        prompt: msalAccount ? undefined : 'select_account',
        openBrowser: async (url) => {
          // Only ever open Microsoft sign-in URLs.
          if (!url.startsWith(`${LOGIN}/`))
            throw new Error('Unexpected sign-in URL.');
          if (inWindow) openSignInWindow(url, () => closed.abort());
          else await shell.openExternal(url);
        },
        successTemplate: PAGE(
          'Signed in to EZ AzFW Manager',
          'You can close this tab and return to the app.',
        ),
        errorTemplate: PAGE(
          "Sign-in didn't complete",
          'Return to EZ AzFW Manager and try again.',
        ),
      }),
      cancel,
    );
  } finally {
    if (inWindow) closeSignInWindow();
  }
}

/**
 * Returns a token for a directory: cached if still fresh, otherwise freshly obtained (from the
 * Azure CLI, or silently redeemed with MSAL). With allowInteractive, browser sign-in falls back to
 * one browser prompt for that directory only.
 */
async function tokenFor(
  tenantId: string,
  opts: { allowInteractive?: boolean; signal?: AbortSignal } = {},
): Promise<AccessToken> {
  const cached = tenantTokens.get(key(tenantId));
  if (cached && cached.expiresOnTimestamp - Date.now() > REFRESH_MARGIN_MS)
    return cached;

  const started = generation;
  const token =
    method === 'cli'
      ? await cliToken(tenantId, opts.signal)
      : await msalToken(tenantId, opts);
  // Signed out (or in as someone else) meanwhile: this token belongs to the old sign-in.
  if (generation !== started) throw new Error(SIGNED_OUT);
  tenantTokens.set(key(tenantId), token);
  const tid = decodeClaims(token.token).tid as string | undefined;
  if (tid) tenantTokens.set(key(tid), token);
  return token;
}

async function cliToken(
  tenantId: string | undefined,
  signal?: AbortSignal,
): Promise<AccessToken> {
  if (!cli) throw new Error(SIGNED_OUT);
  const t = await cli.getToken(ARM_SCOPES, {
    tenantId,
    abortSignal: signal,
    enableCae: false,
  });
  if (!t) throw new Error('Azure did not return an access token.');
  return t;
}

async function msalToken(
  tenantId: string,
  opts: { allowInteractive?: boolean; signal?: AbortSignal },
): Promise<AccessToken> {
  if (!pca || !msalAccount) throw new Error(SIGNED_OUT);
  const authority = `${LOGIN}/${tenantId}`;
  try {
    return toAccessToken(
      await pca.acquireTokenSilent({
        account: msalAccount,
        scopes: ARM_SCOPES,
        authority,
        forceRefresh: true,
      }),
    );
  } catch (err) {
    if (!(err instanceof InteractionRequiredAuthError)) throw err;
    if (!opts.allowInteractive)
      throw new SignInRequired('This directory needs you to sign in again.');
    return toAccessToken(await interactive(authority, opts.signal));
  }
}

/** Every Azure SDK call goes through this: tokens for the active directory only. */
function activeCredential(): TokenCredential {
  return {
    getToken: async () => {
      if (!activeTenant) throw new Error('Choose a directory to continue.');
      return tokenFor(activeTenant);
    },
  };
}
async function armFetch(
  url: string,
  token: AccessToken,
  init?: RequestInit,
): Promise<Response> {
  return fetch(url, {
    ...init,
    headers: {
      Authorization: `Bearer ${token.token}`,
      'Content-Type': 'application/json',
    },
    signal: AbortSignal.timeout(30_000),
  });
}

async function listTenants(token: AccessToken): Promise<TenantInfo[]> {
  const tenants: TenantInfo[] = [];
  let url: string | undefined = TENANTS_URL;
  while (url) {
    const res = await armFetch(url, token);
    if (!res.ok) throw new Error(`Listing directories failed (${res.status}).`);
    const body = (await res.json()) as {
      value?: {
        tenantId: string;
        displayName?: string;
        defaultDomain?: string;
      }[];
      nextLink?: string;
    };
    for (const t of body.value ?? []) {
      tenants.push({
        tenantId: t.tenantId,
        displayName: t.displayName,
        defaultDomain: t.defaultDomain,
      });
    }
    url = body.nextLink;
  }
  return tenants.sort((a, b) =>
    (a.displayName ?? a.tenantId).localeCompare(b.displayName ?? b.tenantId),
  );
}

/** Checks a directory the way the app uses it: a Resource Graph query counting subscriptions. */
async function probe(
  tenantId: string,
): Promise<{ status: TenantStatus; subscriptionCount?: number }> {
  let token: AccessToken;
  try {
    token = await tokenFor(tenantId);
  } catch (err) {
    return {
      status:
        (err as Error).name === 'AuthenticationRequiredError'
          ? 'needs-sign-in'
          : 'unavailable',
    };
  }
  try {
    const res = await armFetch(GRAPH_URL, token, {
      method: 'POST',
      body: JSON.stringify({
        query: PROBE_QUERY,
        options: { resultFormat: 'objectArray', top: 1000 },
      }),
    });
    if (res.status === 401) return { status: 'needs-sign-in' };
    // Resource Graph answers 403 when the account can't see any subscription in the directory.
    if (res.status === 403) return { status: 'ready', subscriptionCount: 0 };
    if (!res.ok) return { status: 'unavailable' };
    const body = (await res.json()) as { totalRecords?: number };
    return { status: 'ready', subscriptionCount: body.totalRecords ?? 0 };
  } catch {
    return { status: 'unavailable' };
  }
}

async function probeAll(tenants: TenantInfo[]): Promise<TenantInfo[]> {
  const out = [...tenants];
  const limit = Math.min(out.length, MAX_PROBED_TENANTS);
  let next = 0;
  const worker = async () => {
    while (next < limit) {
      const i = next++;
      out[i] = { ...out[i], ...(await probe(out[i].tenantId)) };
    }
  };
  await Promise.all(Array.from({ length: Math.min(4, limit) }, worker));
  return out;
}

function mergeTenant(tenants: TenantInfo[], info: TenantInfo): TenantInfo[] {
  const existing = tenants.find((t) => key(t.tenantId) === key(info.tenantId));
  return [
    ...tenants.filter((t) => key(t.tenantId) !== key(info.tenantId)),
    { ...existing, ...info },
  ].sort((a, b) =>
    (a.displayName ?? a.tenantId).localeCompare(b.displayName ?? b.tenantId),
  );
}

function remember(): void {
  if (!account?.username || !activeTenant) return;
  const t = account.tenants?.find(
    (x) => key(x.tenantId) === key(activeTenant!),
  );
  updateState((s) => {
    s.lastSignIn = {
      username: account!.username!,
      tenantId: activeTenant!,
      tenantName: t?.displayName ?? t?.defaultDomain,
    };
  });
}

function reset(): void {
  for (const l of resetListeners) l();
}

/** Makes a directory active; may open the browser once if that directory insists on it. */
async function activate(
  tenantId: string,
  signal?: AbortSignal,
  allowInteractive = true,
): Promise<TenantInfo> {
  const started = generation;
  const token = await tokenFor(tenantId, { allowInteractive, signal });
  const resolved =
    (decodeClaims(token.token).tid as string | undefined) ?? tenantId;
  const result = await probe(resolved);
  if (generation !== started) throw new Error(SIGNED_OUT);
  if (result.status !== 'ready') {
    throw new Error(
      result.status === 'needs-sign-in'
        ? 'Azure did not accept your sign-in for this directory. Check that your account has access to it.'
        : "Couldn't reach this directory. Check the directory ID or domain and your network connection.",
    );
  }
  activeTenant = resolved;
  return { tenantId: resolved, ...result };
}

export async function signIn(
  signInMethod: AuthMethod,
  tenantId?: string,
): Promise<AccountInfo> {
  if (tenantId && !TENANT.test(tenantId)) {
    throw new Error(
      'Enter a directory ID (GUID) or a domain such as contoso.onmicrosoft.com.',
    );
  }
  pendingSignIn?.abort();
  const abort = new AbortController();
  pendingSignIn = abort;

  // A new sign-in replaces any saved one (and its tokens).
  await forgetSession();
  method = signInMethod;
  const requested = tenantId || process.env.EZAZFW_TENANT_ID || undefined;
  const specific =
    requested && !GENERIC_AUTHORITIES.includes(requested.toLowerCase())
      ? requested
      : undefined;

  try {
    // Superseded by another sign-in while the previous one was being cleared.
    if (abort.signal.aborted) throw new Error('Sign-in was cancelled.');
    let first: AccessToken;
    let name: string | undefined;
    let user: string | undefined;
    if (signInMethod === 'cli') {
      first = await startCli(specific, abort.signal);
    } else {
      pca = createPca();
      const result = await interactive(
        `${LOGIN}/${specific ?? 'organizations'}`,
        abort.signal,
      );
      msalAccount = result.account;
      first = toAccessToken(result);
      name = result.account?.name;
      user = result.account?.username;
    }
    return await finishSignIn(first, { specific, name, user }, abort.signal);
  } catch (err) {
    if (pendingSignIn === abort) clearState();
    if (abort.signal.aborted) throw new Error('Sign-in was cancelled.');
    throw err;
  } finally {
    if (pendingSignIn === abort) pendingSignIn = null;
  }
}

/** Starts an Azure CLI sign-in and returns its first token. */
async function startCli(
  tenantId: string | undefined,
  signal: AbortSignal,
): Promise<AccessToken> {
  cli = new AzureCliCredential({ tenantId, additionallyAllowedTenants: ['*'] });
  try {
    return await cliToken(undefined, signal);
  } catch (err) {
    if (signal.aborted) throw err;
    throw new Error(
      `Azure CLI sign-in failed. Run "az login" first, or use browser sign-in. (${(err as Error).message})`,
    );
  }
}

/**
 * Signs back in silently with the sign-in saved last time, if there is one and it still works.
 * Never opens the browser; resolves null when the user needs to sign in.
 */
export function restoreSession(): Promise<AccountInfo | null> {
  if (account) return Promise.resolve(account);
  restoring ??= restore().finally(() => {
    restoring = null;
  });
  return restoring;
}

async function restore(): Promise<AccountInfo | null> {
  const saved: SavedSession | undefined = loadState().session;
  if (!saved) return null;
  if (saved.method !== 'cli' && (!saved.homeAccountId || !canPersistTokens()))
    return null;

  pendingSignIn?.abort();
  const abort = new AbortController();
  pendingSignIn = abort;
  clearState();
  method = saved.method;
  const specific = saved.tenantId;

  try {
    let first: AccessToken;
    let name: string | undefined;
    let user: string | undefined;
    if (saved.method === 'cli') {
      first = await startCli(specific, abort.signal);
    } else {
      pca = createPca();
      const cached = await pca
        .getTokenCache()
        .getAccountByHomeId(saved.homeAccountId!);
      if (!cached) throw new SignInRequired('No saved sign-in was found.');
      msalAccount = cached;
      const result = await abortable(
        pca.acquireTokenSilent({
          account: cached,
          scopes: ARM_SCOPES,
          authority: `${LOGIN}/${specific ?? 'organizations'}`,
        }),
        abort.signal,
      );
      first = toAccessToken(result);
      name = result.account?.name ?? cached.name;
      user = result.account?.username ?? cached.username;
    }
    return await finishSignIn(
      first,
      { specific, name, user, allowInteractive: false },
      abort.signal,
    );
  } catch (err) {
    // Expected when the saved sign-in expired, was revoked, or the device is offline.
    console.info(
      "[auth] Couldn't restore the previous sign-in:",
      (err as Error).message,
    );
    if (pendingSignIn === abort) clearState();
    return null;
  } finally {
    if (pendingSignIn === abort) pendingSignIn = null;
  }
}

/** Shared tail of sign-in and restore: lists directories, picks the active one, saves the session. */
async function finishSignIn(
  first: AccessToken,
  opts: {
    specific?: string;
    name?: string;
    user?: string;
    allowInteractive?: boolean;
  },
  signal: AbortSignal,
): Promise<AccountInfo> {
  const { specific, name, user, allowInteractive = true } = opts;
  const signInMethod = method!;
  const claims = decodeClaims(first.token);
  let tenantsListed = true;
  let tenants = await listTenants(first).catch((err: Error) => {
    console.warn('[auth] Listing directories failed:', err.message);
    tenantsListed = false;
    return [] as TenantInfo[];
  });
  tenants = await probeAll(tenants);

  if (specific) {
    tenants = mergeTenant(
      tenants,
      await activate(specific, signal, allowInteractive),
    );
  } else {
    // Prefer the directory used last time, then the only directory that has subscriptions.
    const last = loadState().lastSignIn;
    const username = usernameFrom(claims, user);
    const ready = tenants.filter((t) => t.status === 'ready');
    const remembered =
      last && username && last.username.toLowerCase() === username.toLowerCase()
        ? ready.find((t) => key(t.tenantId) === key(last.tenantId))
        : undefined;
    const withSubs = ready.filter((t) => (t.subscriptionCount ?? 0) > 0);
    activeTenant =
      remembered?.tenantId ??
      (withSubs.length === 1 ? withSubs[0].tenantId : undefined);
  }
  if (signal.aborted) throw new Error('Sign-in was cancelled.');

  // Non-secret diagnostics only (no tokens).
  console.info('[auth] Signed in', {
    method: signInMethod,
    signInTenant: claims.tid,
    directories: tenants.map((t) => ({
      id: t.tenantId,
      status: t.status,
      subscriptions: t.subscriptionCount,
    })),
    activeTenant,
  });

  credential = activeCredential();
  account = {
    method: signInMethod,
    username: usernameFrom(claims, user),
    displayName: (claims.name as string | undefined) ?? name,
    tenantId: activeTenant,
    tenants,
    tenantsListed,
  };
  updateState((s) => {
    s.session = {
      method: signInMethod,
      homeAccountId: msalAccount?.homeAccountId,
      tenantId: specific,
    };
  });
  remember();
  reset();
  return account;
}

/** Switches the directory (ID or domain) that every Azure call uses. */
export async function switchTenant(tenantId: string): Promise<AccountInfo> {
  if (!method || !account) throw new Error(SIGNED_OUT);
  tenantId = tenantId.trim();
  if (
    !TENANT.test(tenantId) ||
    GENERIC_AUTHORITIES.includes(tenantId.toLowerCase())
  ) {
    throw new Error(
      'Enter a directory ID (GUID) or a domain such as contoso.onmicrosoft.com.',
    );
  }
  const known = account.tenants?.find(
    (t) =>
      key(t.tenantId) === key(tenantId) ||
      t.defaultDomain?.toLowerCase() === tenantId.toLowerCase(),
  );
  // activate() only changes the active directory once it has succeeded.
  const info = await activate(known?.tenantId ?? tenantId);
  if (!account) throw new Error(SIGNED_OUT);
  account = {
    ...account,
    tenantId: info.tenantId,
    tenants: mergeTenant(account.tenants ?? [], info),
  };
  remember();
  reset();
  return account;
}

export function cancelSignIn(): void {
  pendingSignIn?.abort();
}

export function getAccount(): AccountInfo | null {
  return account;
}

function clearState(): void {
  generation++;
  method = null;
  pca = null;
  if (cachePlugin) closingCache = cachePlugin.close();
  cachePlugin = null;
  msalAccount = null;
  cli = null;
  tenantTokens.clear();
  storageTokens.clear();
  credential = null;
  account = null;
  activeTenant = undefined;
}

/** Signs out and forgets the saved sign-in, so the next launch shows the sign-in screen. */
export async function signOut(): Promise<void> {
  pendingSignIn?.abort();
  await forgetSession();
  // Also forget the accounts the sign-in window remembers.
  await session
    .fromPartition(SIGN_IN_PARTITION)
    .clearStorageData()
    .catch((err: Error) =>
      console.warn('[auth] Clearing sign-in window data failed:', err.message),
    );
  reset();
}

/** Drops in-memory state, the encrypted token cache and the saved-session marker. */
async function forgetSession(): Promise<void> {
  clearState();
  updateState((s) => {
    delete s.session;
  });
  // Let an in-flight write finish first, so it can't recreate the file after it's deleted.
  await closingCache;
  await deleteTokenCache();
}

/** Called when the signed-in identity or directory changes, so per-credential caches can be dropped. */
export function onSignOut(listener: () => void): void {
  resetListeners.add(listener);
}

export function getCredential(): TokenCredential {
  if (!credential) throw new Error(SIGNED_OUT);
  return credential;
}

/**
 * Token for Azure Blob Storage data access in the active directory. Blob data is authorized with
 * the user's own Entra identity (Storage Blob Data roles), so no account keys are needed.
 */
export async function getStorageToken(): Promise<string> {
  if (!activeTenant) throw new Error('Choose a directory to continue.');
  const tenantId = activeTenant;
  const cached = storageTokens.get(key(tenantId));
  if (cached && cached.expiresOnTimestamp - Date.now() > REFRESH_MARGIN_MS)
    return cached.token;

  const started = generation;
  let token: AccessToken;
  if (method === 'cli') {
    if (!cli) throw new Error(SIGNED_OUT);
    const t = await cli.getToken(STORAGE_SCOPES, {
      tenantId,
      enableCae: false,
    });
    if (!t) throw new Error('Azure did not return a storage access token.');
    token = t;
  } else {
    if (!pca || !msalAccount) throw new Error(SIGNED_OUT);
    const authority = `${LOGIN}/${tenantId}`;
    try {
      token = toAccessToken(
        await pca.acquireTokenSilent({
          account: msalAccount,
          scopes: STORAGE_SCOPES,
          authority,
          forceRefresh: true,
        }),
      );
    } catch (err) {
      if (!(err instanceof InteractionRequiredAuthError)) throw err;
      token = toAccessToken(
        await interactive(authority, undefined, STORAGE_SCOPES),
      );
    }
  }
  if (generation !== started) throw new Error(SIGNED_OUT);
  storageTokens.set(key(tenantId), token);
  return token.token;
}

export interface Principal {
  objectId: string;
  type: 'User' | 'ServicePrincipal';
}

/** The signed-in identity, read from its Azure token, for granting it role assignments. */
export async function getPrincipal(): Promise<Principal> {
  if (!activeTenant) throw new Error('Choose a directory to continue.');
  const claims = decodeClaims((await tokenFor(activeTenant)).token);
  const objectId = claims.oid as string | undefined;
  if (!objectId)
    throw new Error("Couldn't determine your Azure identity (object ID).");
  return {
    objectId,
    type: claims.idtyp === 'app' ? 'ServicePrincipal' : 'User',
  };
}
