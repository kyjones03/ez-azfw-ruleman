import { app } from 'electron';
import fs from 'node:fs';
import path from 'node:path';
import type {
  AuthMethod,
  CommitProgress,
  CommitRecord,
  CommitResult,
  LastSignIn,
  RuleCollectionGroup,
  SnapshotStorageConfig,
} from '../shared/types';

export interface StagedGroup {
  groupId: string;
  policyId: string;
  policyName: string;
  stagedAt: string;
  /** Draft entry for a group that doesn't exist in Azure yet (baseline is empty). */
  created?: boolean;
  /** Running config at the time the group was first edited (includes etag). */
  baseline: RuleCollectionGroup;
  candidate: RuleCollectionGroup;
}

export interface PersistedState {
  version: 1;
  managedFirewallIds: string[];
  candidate: StagedGroup[];
  history: CommitRecord[];
  /** Centralized Azure Blob Storage configuration for shared policy snapshots. */
  snapshotStorage?: SnapshotStorageConfig;
  /** Last browser sign-in, so the next one can go straight to that directory. */
  lastSignIn?: LastSignIn;
  /** Which sign-in to restore silently at startup (no secrets; tokens live in tokenCache). */
  session?: SavedSession;
  /** Commits that are running; any still here at startup were interrupted and are resumed. */
  activeCommits: ActiveCommit[];
}

export interface ActiveCommit {
  progress: CommitProgress;
  user?: string;
  changeCount: number;
  results: CommitResult[];
  /** What was sent to Azure per group (lower-cased ID), to check the outcome after a restart. */
  written: Record<string, RuleCollectionGroup>;
}

export interface SavedSession {
  method: AuthMethod;
  /** MSAL account ID for window or browser sign-in. */
  homeAccountId?: string;
  /** Directory requested explicitly at sign-in, if any. */
  tenantId?: string;
}

const MAX_HISTORY = 200;

const empty = (): PersistedState => ({
  version: 1,
  managedFirewallIds: [],
  candidate: [],
  history: [],
  activeCommits: [],
});

let cache: PersistedState | null = null;
/** Set when the state file exists but couldn't be read or backed up, so saving would destroy it. */
let persistBlocked = false;

const READ_ATTEMPTS = 5;
const READ_RETRY_MS = 100;

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** Reads the state file, retrying briefly when another process (e.g. antivirus) holds it. */
function readStateFile(file: string): string | null {
  for (let attempt = 1; ; attempt++) {
    try {
      return fs.readFileSync(file, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
      if (attempt >= READ_ATTEMPTS) throw err;
      sleepSync(READ_RETRY_MS);
    }
  }
}

function filePath(): string {
  return path.join(app.getPath('userData'), 'ez-azfw-ruleman-state.json');
}

const arrayOr = <T>(value: unknown): T[] =>
  Array.isArray(value) ? (value as T[]) : [];

function parse(text: string): PersistedState {
  const parsed = JSON.parse(text) as Partial<PersistedState> & {
    /** Earlier versions tracked a single running commit. */
    activeCommit?: ActiveCommit;
    /** Earlier versions stored snapshots locally; strip so snapshots are never kept on disk. */
    snapshots?: unknown;
  };
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
    throw new Error('The state file does not contain an object.');
  const { activeCommit, snapshots: _snapshots, ...rest } = parsed;
  return {
    ...empty(),
    ...rest,
    managedFirewallIds: arrayOr(parsed.managedFirewallIds),
    candidate: arrayOr(parsed.candidate),
    history: arrayOr(parsed.history),
    activeCommits: Array.isArray(parsed.activeCommits)
      ? parsed.activeCommits
      : activeCommit
        ? [activeCommit]
        : [],
  };
}

export function loadState(): PersistedState {
  if (cache) return cache;
  const file = filePath();
  let text: string | null;
  try {
    text = readStateFile(file);
  } catch (err) {
    // The file exists but can't be read: keep a copy before starting empty, and if even that
    // fails, never save over it this session.
    const backup = `${file}.unreadable-${Date.now()}`;
    try {
      fs.copyFileSync(file, backup);
      console.error(
        `[store] Couldn't read ${file} (${(err as Error).message}); copied it to ${backup}.`,
      );
    } catch {
      persistBlocked = true;
      console.error(
        `[store] Couldn't read ${file} (${(err as Error).message}); changes this session won't be saved.`,
      );
    }
    cache = empty();
    return cache;
  }
  if (text === null) {
    cache = empty();
    return cache;
  }
  try {
    cache = parse(text);
  } catch (err) {
    // Keep the damaged file for recovery instead of overwriting drafts and history on next save.
    const backup = `${file}.corrupt-${Date.now()}`;
    console.error(
      `[store] Couldn't read ${file} (${(err as Error).message}); moved it to ${backup}.`,
    );
    try {
      fs.renameSync(file, backup);
    } catch {
      // Best effort: the app still starts with empty state.
    }
    cache = empty();
  }
  return cache;
}

export function updateState(mutate: (state: PersistedState) => void): void {
  const state = loadState();
  mutate(state);
  state.history = state.history.slice(0, MAX_HISTORY);
  if (persistBlocked) return;
  const target = filePath();
  fs.mkdirSync(path.dirname(target), { recursive: true });
  // Write-then-rename so a crash never leaves a truncated state file.
  const tmp = `${target}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2), 'utf8');
  fs.renameSync(tmp, target);
}
