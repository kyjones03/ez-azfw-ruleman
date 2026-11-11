import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { QuipSpinner } from './components/QuipSpinner';
import { ConfirmModal } from './components/Modal';
import { errorMessage, useToast } from './components/Toast';
import { TitleBar } from './components/TitleBar';
import { Blade, type Tab } from './components/Blade';
import { CandidateTray } from './components/CandidateTray';
import { SignIn } from './views/SignIn';
import { DirectoryChooser } from './views/DirectoryChooser';
import { FirewallPicker } from './views/FirewallPicker';
import { Firewalls } from './views/Firewalls';
import { Policies } from './views/Policies';
import { IpGroups } from './views/IpGroups';
import { FlowTesterPage } from './views/FlowTesterPage';
import type { FlowHit } from '../shared/flow';
import { PolicyEditor, type PolicyOption } from './views/PolicyEditor';
import { CommitDialog } from './views/CommitDialog';
import { CommitStatus } from './views/CommitStatus';
import { ChevronDown, RefreshCw } from 'lucide-react';
import { Dropdown } from './components/Dropdown';
import { CommitHistory } from './views/CommitHistory';
import { Snapshots } from './views/Snapshots';
import { DeployWizard } from './views/DeployWizard';
import { DeployStatus } from './views/DeployStatus';
import { ActivityMenu } from './components/ActivityMenu';
import { deployKey, useDeployActivity } from './activity';
import { readSetting, writeSetting } from './storage';
import type { DeployProgress, DeployRequest } from '../shared/deploy';
import { resourceName, sameResourceId } from '../shared/resourceId';
import type {
  AccountInfo,
  CandidateStatus,
  CommitRecord,
  FirewallSummary,
} from '../shared/types';

const AUTO_REFRESH_KEY = 'ez-azfw-ruleman.autoRefreshMinutes';
/** Minutes; 0 turns auto-refresh off. */
const AUTO_REFRESH_OPTIONS = [0, 1, 2, 5, 15];
const BLADE_KEY = 'ez-azfw-ruleman.blade';

type Stage = 'loading' | 'signin' | 'directory' | 'select' | 'workspace';

const EMPTY_STATUS: CandidateStatus = { pending: [], unsaved: false };

export default function App() {
  const toast = useToast();
  const [stage, setStage] = useState<Stage>('loading');
  const [account, setAccount] = useState<AccountInfo | null>(null);
  const [firewalls, setFirewalls] = useState<FirewallSummary[]>([]);
  const [managedIds, setManagedIds] = useState<string[]>([]);
  const [discovering, setDiscovering] = useState(false);
  const [discoverError, setDiscoverError] = useState('');
  const [discoverAttemptAt, setDiscoverAttemptAt] = useState<Date>();
  const [status, setStatus] = useState<CandidateStatus>(EMPTY_STATUS);
  const [tab, setTab] = useState<Tab>('firewalls');
  const [bladeOpen, setBladeOpen] = useState(
    () => readSetting(BLADE_KEY) !== 'collapsed',
  );
  const toggleBlade = () => {
    writeSetting(BLADE_KEY, bladeOpen ? 'collapsed' : 'open');
    setBladeOpen(!bladeOpen);
  };
  const [policyId, setPolicyId] = useState<string>();
  const [ruleFocus, setRuleFocus] = useState<FlowHit>();
  const [showCommit, setShowCommit] = useState(false);
  const [confirmRevertAll, setConfirmRevertAll] = useState(false);
  const [saving, setSaving] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const [showDeploy, setShowDeploy] = useState(false);
  /** Which deployment's status is open: 'live' (the running one) or an activity key. */
  const [statusKey, setStatusKey] = useState<string>();
  const [deployProgress, setDeployProgress] = useState<DeployProgress>();
  const [commits, setCommits] = useState<CommitRecord[]>([]);
  const {
    deployments: deployActivity,
    commits: commitActivity,
    seenAt: activitySeenAt,
    clearedAt: activityClearedAt,
    record: recordDeploy,
    recordCommit,
    markSeen: markActivitySeen,
    clear: clearActivity,
  } = useDeployActivity();
  /** Commit whose status window is open (a commit/activity id). */
  const [commitStatusId, setCommitStatusId] = useState<string>();
  const [refreshing, setRefreshing] = useState(false);
  const [autoRefreshMin, setAutoRefreshMin] = useState(() => {
    const saved = readSetting(AUTO_REFRESH_KEY);
    return saved !== null && AUTO_REFRESH_OPTIONS.includes(Number(saved))
      ? Number(saved)
      : 5;
  });
  const [lastRefreshed, setLastRefreshed] = useState<Date>();
  const [refreshError, setRefreshError] = useState('');

  /** Lists firewalls. `quiet` (auto-refresh) keeps what's shown instead of a loading state. */
  const discover = useCallback(async ({ quiet = false } = {}) => {
    if (!quiet) setDiscovering(true);
    try {
      const [all, managed] = await Promise.all([
        window.api.discoverFirewalls(),
        window.api.getManagedFirewalls(),
      ]);
      setFirewalls(all);
      setManagedIds(managed);
      setDiscoverError('');
      return { all, managed };
    } catch (err) {
      // A failed background refresh keeps the last good list.
      if (quiet) throw err;
      setDiscoverError(errorMessage(err));
      setDiscoverAttemptAt(new Date());
      return { all: [], managed: [] };
    } finally {
      if (!quiet) setDiscovering(false);
    }
  }, []);

  const enterWorkspace = useCallback(
    async (acct: AccountInfo) => {
      setAccount(acct);
      if (!acct.tenantId) {
        setStage('directory');
        return;
      }
      setFirewalls([]);
      setStage('select');
      // A commit interrupted by closing the app carries on; its progress returns to the bell.
      const resumed = await window.api.resumeCommit().catch(() => null);
      if (resumed) recordCommit(resumed);
      const [{ all, managed }, st, history] = await Promise.all([
        discover(),
        window.api.getCandidateStatus().catch(() => EMPTY_STATUS),
        window.api.getHistory().catch(() => []),
      ]);
      setStatus(st);
      setCommits(history);
      const hasManaged = all.some((f) =>
        managed.some((id) => sameResourceId(id, f.id)),
      );
      setStage(hasManaged ? 'workspace' : 'select');
    },
    [discover, recordCommit],
  );

  useEffect(() => {
    window.api
      .getAccount()
      .then((acct) => acct ?? window.api.restoreSession())
      .then((acct) => (acct ? enterWorkspace(acct) : setStage('signin')))
      .catch(() => setStage('signin'));
  }, [enterWorkspace]);

  const managed = useMemo(
    () =>
      firewalls.filter((f) =>
        managedIds.some((id) => sameResourceId(id, f.id)),
      ),
    [firewalls, managedIds],
  );

  const policies = useMemo<PolicyOption[]>(() => {
    const map = new Map<string, PolicyOption>();
    for (const f of managed) {
      if (!f.policyId) continue;
      const key = f.policyId.toLowerCase();
      const entry = map.get(key) ?? {
        id: f.policyId,
        name: resourceName(f.policyId),
        firewallNames: [],
      };
      entry.firewallNames.push(f.name);
      map.set(key, entry);
    }
    return [...map.values()].sort((a, b) => a.name.localeCompare(b.name));
  }, [managed]);

  useEffect(() => {
    if (!policies.some((p) => sameResourceId(p.id, policyId)))
      setPolicyId(policies[0]?.id);
  }, [policies, policyId]);

  const subscriptionNames = useMemo(
    () =>
      Object.fromEntries(
        firewalls
          .filter((f) => f.subscriptionName)
          .map((f) => [f.subscriptionId.toLowerCase(), f.subscriptionName!]),
      ),
    [firewalls],
  );

  const confirmSelection = async (ids: string[]) => {
    try {
      await window.api.setManagedFirewalls(ids);
      setManagedIds(ids);
      setStage('workspace');
    } catch (err) {
      toast('error', errorMessage(err));
    }
  };

  const save = async () => {
    setSaving(true);
    try {
      setStatus(await window.api.save());
      toast('success', 'Draft saved.');
    } catch (err) {
      toast('error', errorMessage(err));
    } finally {
      setSaving(false);
    }
  };

  const revertAll = async () => {
    setConfirmRevertAll(false);
    try {
      setStatus(await window.api.revert());
      setReloadKey((k) => k + 1);
      toast('info', 'All changes discarded.');
    } catch (err) {
      toast('error', errorMessage(err));
    }
  };

  const signOut = async () => {
    try {
      await window.api.signOut();
    } catch (err) {
      toast('error', errorMessage(err));
      return;
    }
    setAccount(null);
    setFirewalls([]);
    setCommits([]);
    setStage('signin');
  };

  const switchTenant = async (tenantId: string) => {
    if (tenantId === account?.tenantId) return;
    try {
      await enterWorkspace(await window.api.switchTenant(tenantId));
    } catch (err) {
      toast('error', errorMessage(err));
    }
  };

  useEffect(
    () =>
      window.api.onDeployProgress((p) => {
        setDeployProgress(p);
        recordDeploy(p);
      }),
    [recordDeploy],
  );

  const deployRunning =
    !!deployProgress &&
    deployProgress.phase !== 'succeeded' &&
    deployProgress.phase !== 'failed';

  const openDeploy = () => {
    // A finished deployment stays visible until its result has been seen.
    if (deployProgress) setStatusKey('live');
    else setShowDeploy(true);
  };

  const startDeploy = async (request: DeployRequest) => {
    setShowDeploy(false);
    setStatusKey('live');
    try {
      const result = await window.api.deployFirewall(request);
      setDeployProgress(result);
      recordDeploy(result);
      if (result.phase === 'succeeded') {
        toast('success', `${result.firewallName} was deployed.`);
        await discover();
        // Resource Graph can lag behind ARM by a minute; refresh again shortly, in the background.
        setTimeout(
          () => discover({ quiet: true }).catch(() => undefined),
          45_000,
        );
      } else {
        toast('error', `Deployment of ${result.firewallName} failed.`);
      }
    } catch (err) {
      setStatusKey(undefined);
      toast('error', errorMessage(err));
    }
  };

  const liveKey = deployProgress ? deployKey(deployProgress) : undefined;
  const closeDeployStatus = () => {
    // Closing a finished live deployment also clears it from the navigation.
    if (!deployRunning && (statusKey === 'live' || statusKey === liveKey))
      setDeployProgress(undefined);
    setStatusKey(undefined);
  };

  const shownDeploy =
    statusKey === 'live' || (statusKey && statusKey === liveKey)
      ? deployProgress && { progress: deployProgress, stale: false }
      : deployActivity.find((d) => d.key === statusKey);

  // Commit progress feeds the bell; when a commit ends, re-sync even if its dialog was hidden.
  useEffect(
    () =>
      window.api.onCommitProgress((p) => {
        recordCommit(p);
        if (!p.done) return;
        window.api
          .getCandidateStatus()
          .then(setStatus)
          .catch(() => undefined);
        window.api
          .getHistory()
          .then(setCommits)
          .catch(() => undefined);
        setReloadKey((k) => k + 1);
      }),
    [recordCommit],
  );

  /**
   * Re-reads everything from Azure (caches dropped first). `silent` is for auto-refresh: no
   * loading states or error pop-ups; problems show on the Refresh button instead.
   */
  const refreshingRef = useRef(false);
  const refresh = async ({ silent = false } = {}) => {
    if (refreshingRef.current) return;
    refreshingRef.current = true;
    setRefreshing(true);
    try {
      await window.api.refresh();
      setReloadKey((k) => k + 1);
      const [, st, history] = await Promise.all([
        discover({ quiet: silent }),
        window.api.getCandidateStatus(),
        window.api.getHistory(),
      ]);
      setStatus(st);
      setCommits(history);
      setLastRefreshed(new Date());
      setRefreshError('');
    } catch (err) {
      if (silent) setRefreshError(errorMessage(err));
      else toast('error', errorMessage(err));
    } finally {
      refreshingRef.current = false;
      setRefreshing(false);
    }
  };
  const refreshRef = useRef(refresh);
  refreshRef.current = refresh;

  const commitRunning = commitActivity.some(
    (c) => !c.progress.done && !c.stale,
  );
  const signedIn = stage === 'select' || stage === 'workspace';

  // Auto-refresh. It never interrupts: skipped while any dialog is open (an edit or commit in
  // progress), while a commit runs, or while the window is hidden; it catches up on return.
  useEffect(() => {
    if (!signedIn || !autoRefreshMin) return;
    const intervalMs = autoRefreshMin * 60_000;
    let last = Date.now();
    const busy = () =>
      document.hidden ||
      !!document.querySelector('[role="dialog"][aria-modal="true"]') ||
      commitRunning;
    const tick = () => {
      if (busy() || Date.now() - last < intervalMs - 1000) return;
      last = Date.now();
      refreshRef.current({ silent: true });
    };
    const timer = setInterval(tick, Math.min(intervalMs, 30_000));
    document.addEventListener('visibilitychange', tick);
    window.addEventListener('focus', tick);
    return () => {
      clearInterval(timer);
      document.removeEventListener('visibilitychange', tick);
      window.removeEventListener('focus', tick);
    };
  }, [signedIn, autoRefreshMin, commitRunning]);

  const chooseAutoRefresh = (minutes: number) => {
    setAutoRefreshMin(minutes);
    writeSetting(AUTO_REFRESH_KEY, String(minutes));
  };

  const commitStatus = (() => {
    if (!commitStatusId) return undefined;
    const live = commitActivity.find((c) => c.key === commitStatusId);
    const record = commits.find((c) => c.id === commitStatusId);
    // Prefer live progress while running; the saved record once it's in the history.
    if (live && (!live.progress.done || live.stale) && !record)
      return { progress: live.progress, stale: live.stale };
    if (record) return { record };
    return live && { progress: live.progress, stale: live.stale };
  })();

  const refreshTitle = [
    refreshError
      ? `Last automatic refresh failed: ${refreshError}`
      : lastRefreshed
        ? `Last refreshed ${lastRefreshed.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}`
        : 'Reload firewalls, policies, rules and IP groups from Azure',
    autoRefreshMin
      ? `Auto-refresh every ${autoRefreshMin} min`
      : 'Auto-refresh is off',
  ].join(' · ');

  const activityMenu = (
    <>
      <button
        type="button"
        onClick={() => refresh()}
        disabled={refreshing}
        aria-label="Refresh from Azure"
        title={refreshTitle}
        className="no-drag relative flex h-9 w-10 items-center justify-center text-fg-muted hover:bg-ink-800 hover:text-fg disabled:opacity-60"
      >
        <RefreshCw size={15} className={refreshing ? 'animate-spin' : ''} />
        {refreshError && (
          <span
            className="absolute right-2 top-2 h-1.5 w-1.5 rounded-full bg-deny"
            aria-hidden
          />
        )}
      </button>
      <div className="no-drag">
        <Dropdown
          align="right"
          label="Auto-refresh interval"
          widthClass="w-52"
          header={
            <span className="text-xs font-semibold text-fg-muted">
              Auto-refresh
            </span>
          }
          triggerClassName="flex h-9 w-5 items-center justify-center text-fg-faint hover:bg-ink-800 hover:text-fg"
          trigger={() => <ChevronDown size={12} />}
          items={AUTO_REFRESH_OPTIONS.map((m) => ({
            id: String(m),
            label: m ? `Every ${m} ${m === 1 ? 'minute' : 'minutes'}` : 'Off',
            checked: autoRefreshMin === m,
            onSelect: () => chooseAutoRefresh(m),
          }))}
        />
      </div>
      <ActivityMenu
        deployments={deployActivity}
        commits={commits}
        liveCommits={commitActivity}
        seenAt={activitySeenAt}
        clearedAt={activityClearedAt}
        onSeen={markActivitySeen}
        onClear={clearActivity}
        onOpenDeploy={(key) => {
          setShowDeploy(false);
          setStatusKey(key);
        }}
        onOpenCommit={setCommitStatusId}
      />
    </>
  );

  const deployOverlays = (
    <>
      {showDeploy && (
        <DeployWizard
          defaultSubscriptionId={(managed[0] ?? firewalls[0])?.subscriptionId}
          onClose={() => setShowDeploy(false)}
          onDeploy={startDeploy}
        />
      )}
      {shownDeploy && (
        <DeployStatus
          progress={shownDeploy.progress}
          stale={shownDeploy.stale}
          onClose={closeDeployStatus}
        />
      )}
      {commitStatus && (
        <CommitStatus
          data={commitStatus}
          onClose={() => setCommitStatusId(undefined)}
        />
      )}
    </>
  );

  if (stage === 'loading') {
    return (
      <div className="flex h-full flex-col">
        <TitleBar />
        <div className="flex flex-1 items-center justify-center">
          <QuipSpinner topic="start" />
        </div>
      </div>
    );
  }

  if (stage === 'signin' || !account) {
    return (
      <div className="flex h-full flex-col">
        <TitleBar />
        <SignIn onSignedIn={enterWorkspace} />
      </div>
    );
  }

  if (stage === 'directory') {
    return (
      <div className="flex h-full flex-col">
        <TitleBar />
        <DirectoryChooser
          account={account}
          onChosen={enterWorkspace}
          onSignOut={signOut}
        />
      </div>
    );
  }

  const openPolicy = (id: string) => {
    setPolicyId(policies.find((p) => sameResourceId(p.id, id))?.id ?? id);
    setTab('rules');
  };

  return (
    <div className="flex h-full flex-col">
      <TitleBar
        bladeOpen={bladeOpen}
        onToggleBlade={toggleBlade}
        actions={activityMenu}
      />
      <div className="flex min-h-0 flex-1">
        <Blade
          open={bladeOpen}
          tab={tab}
          onTab={(t) => {
            setTab(t);
            // Leaving the firewall chooser without saving keeps the current selection.
            if (stage === 'select' && managed.length) setStage('workspace');
          }}
          account={account}
          onSignOut={signOut}
          onSwitchTenant={switchTenant}
        />
        <main className="flex min-w-0 flex-1 flex-col">
          {tab === 'ipGroups' ? (
            <IpGroups
              key={account.tenantId}
              reloadKey={reloadKey}
              defaultSubscriptionId={
                (managed[0] ?? firewalls[0])?.subscriptionId
              }
              onCreated={() => setReloadKey((k) => k + 1)}
            />
          ) : stage === 'select' ? (
            <FirewallPicker
              firewalls={firewalls}
              loading={discovering}
              error={discoverError}
              errorAt={discoverAttemptAt}
              onSignInAgain={signOut}
              tenants={account.tenants ?? []}
              tenantId={account.tenantId}
              onSwitchTenant={switchTenant}
              initialSelection={managedIds}
              onRefresh={() => discover()}
              onConfirm={confirmSelection}
              onCancel={
                managed.length ? () => setStage('workspace') : undefined
              }
            />
          ) : (
            <>
              {tab === 'firewalls' && (
                <Firewalls
                  firewalls={managed}
                  onOpenPolicy={openPolicy}
                  onChooseFirewalls={() => setStage('select')}
                  onDeploy={openDeploy}
                  status={status}
                  onStatus={setStatus}
                  reloadKey={reloadKey}
                />
              )}
              {tab === 'policies' && (
                <Policies
                  policies={policies}
                  subscriptionNames={subscriptionNames}
                  status={status}
                  reloadKey={reloadKey}
                  onOpenPolicy={openPolicy}
                  onStatus={setStatus}
                />
              )}
              {tab === 'rules' && (
                <PolicyEditor
                  policies={policies}
                  policyId={policyId}
                  onSelectPolicy={setPolicyId}
                  status={status}
                  onStatus={setStatus}
                  reloadKey={reloadKey}
                  focus={ruleFocus}
                />
              )}
              {tab === 'flow' && (
                <FlowTesterPage
                  policies={policies}
                  initialPolicyId={policyId}
                  reloadKey={reloadKey}
                  onOpenRule={(id, hit) => {
                    setPolicyId(id);
                    setRuleFocus({ ...hit });
                    setTab('rules');
                  }}
                />
              )}
              {tab === 'snapshots' && (
                <Snapshots
                  policies={policies}
                  refreshKey={reloadKey}
                  onRestored={(restoredPolicyId, nextStatus) => {
                    setStatus(nextStatus);
                    setReloadKey((k) => k + 1);
                    setPolicyId(
                      policies.find((p) =>
                        sameResourceId(p.id, restoredPolicyId),
                      )?.id ?? restoredPolicyId,
                    );
                    setTab('rules');
                  }}
                />
              )}
              {tab === 'history' && (
                <CommitHistory
                  refreshKey={reloadKey}
                  onOpenStorage={() => setTab('snapshots')}
                />
              )}
            </>
          )}
        </main>
      </div>
      <CandidateTray
        status={status}
        saving={saving}
        onSave={save}
        onDiscard={() => setConfirmRevertAll(true)}
        onReview={() => setShowCommit(true)}
        onShowActivity={() => {
          const live = commitActivity.find((c) => !c.progress.done && !c.stale);
          if (live) setCommitStatusId(live.progress.commitId);
        }}
      />

      {showCommit && (
        <CommitDialog
          status={status}
          onStatus={setStatus}
          onClose={() => setShowCommit(false)}
          onCommit={(ids, description) => {
            const run = window.api.commit(ids, description);
            // The commit marks its groups as in flight at once; show that in the tray.
            window.api
              .getCandidateStatus()
              .then(setStatus)
              .catch(() => undefined);
            run
              .then((r) => {
                setCommits((c) => [r, ...c.filter((x) => x.id !== r.id)]);
                setReloadKey((k) => k + 1);
                const failed = r.results.filter((x) => !x.ok).length;
                toast(
                  failed ? 'error' : 'success',
                  failed
                    ? `${failed} of ${r.results.length} ${r.results.some((result) => !!result.target) ? 'resources' : 'groups'} failed to commit. Open the activity bell for details.`
                    : 'Committed to Azure.',
                );
                if (r.snapshotError) toast('error', r.snapshotError);
                if (r.historyError) toast('error', r.historyError);
              })
              .catch((err) => toast('error', errorMessage(err)))
              .finally(() =>
                window.api
                  .getCandidateStatus()
                  .then(setStatus)
                  .catch(() => undefined),
              );
          }}
        />
      )}
      {confirmRevertAll && (
        <ConfirmModal
          title="Discard all changes?"
          message="Every uncommitted change in the draft will be removed. Azure is not affected."
          confirmLabel="Discard all"
          onConfirm={revertAll}
          onCancel={() => setConfirmRevertAll(false)}
        />
      )}
      {deployOverlays}
    </div>
  );
}
