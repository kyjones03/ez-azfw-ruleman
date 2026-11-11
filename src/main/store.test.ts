import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const userData = fs.mkdtempSync(path.join(os.tmpdir(), 'ez-azfw-store-'));
vi.mock('electron', () => ({ app: { getPath: () => userData } }));

const stateFile = path.join(userData, 'ez-azfw-ruleman-state.json');

async function freshStore() {
  vi.resetModules();
  return import('./store');
}

beforeEach(() => {
  for (const f of fs.readdirSync(userData))
    fs.rmSync(path.join(userData, f), { force: true });
});
afterAll(() => fs.rmSync(userData, { recursive: true, force: true }));

describe('state file', () => {
  it('starts empty on first run', async () => {
    const { loadState } = await freshStore();
    expect(loadState()).toMatchObject({
      managedFirewallIds: [],
      candidate: [],
      history: [],
      activeCommits: [],
    });
  });

  it('round-trips through disk', async () => {
    const store = await freshStore();
    store.updateState((s) => {
      s.managedFirewallIds.push('fw1');
    });
    const reloaded = await freshStore();
    expect(reloaded.loadState().managedFirewallIds).toEqual(['fw1']);
  });

  it('keeps policy-setting drafts alongside legacy rule drafts', async () => {
    const store = await freshStore();
    store.updateState((s) => {
      s.policyCandidate = [
        {
          kind: 'policy',
          groupId: 'policy-id',
          policyId: 'policy-id',
          policyName: 'fp',
          stagedAt: '2026-01-01',
          baseline: { name: 'fp', threatIntelMode: 'Alert' },
          candidate: { name: 'fp', threatIntelMode: 'Deny' },
        },
      ];
    });
    const reloaded = await freshStore();
    expect(
      reloaded.loadState().policyCandidate?.[0].candidate.threatIntelMode,
    ).toBe('Deny');
    expect(reloaded.loadState().candidate).toEqual([]);
  });

  it('keeps a damaged file aside instead of overwriting it', async () => {
    fs.writeFileSync(stateFile, '{"history": [', 'utf8');
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const { loadState, updateState } = await freshStore();
    expect(loadState().history).toEqual([]);
    updateState(() => {});
    const backups = fs
      .readdirSync(userData)
      .filter((f) => f.includes('.corrupt-'));
    expect(backups).toHaveLength(1);
    expect(fs.readFileSync(path.join(userData, backups[0]), 'utf8')).toBe(
      '{"history": [',
    );
    expect(error).toHaveBeenCalled();
    error.mockRestore();
  });

  it('retries a briefly locked file instead of starting empty', async () => {
    fs.writeFileSync(stateFile, JSON.stringify({ history: [{ id: 'h1' }] }));
    const realRead = fs.readFileSync;
    let calls = 0;
    const read = vi.spyOn(fs, 'readFileSync').mockImplementation(((
      ...args: Parameters<typeof fs.readFileSync>
    ) => {
      if (args[0] === stateFile && calls++ < 2)
        throw Object.assign(new Error('busy'), { code: 'EBUSY' });
      return realRead(...args);
    }) as typeof fs.readFileSync);
    const { loadState } = await freshStore();
    expect(loadState().history).toEqual([{ id: 'h1' }]);
    read.mockRestore();
  });

  it('never overwrites a file it could neither read nor back up', async () => {
    const original = JSON.stringify({ history: [{ id: 'h1' }] });
    fs.writeFileSync(stateFile, original);
    const locked = () => {
      throw Object.assign(new Error('locked'), { code: 'EPERM' });
    };
    const read = vi
      .spyOn(fs, 'readFileSync')
      .mockImplementation(locked as typeof fs.readFileSync);
    const copy = vi
      .spyOn(fs, 'copyFileSync')
      .mockImplementation(locked as typeof fs.copyFileSync);
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const { loadState, updateState } = await freshStore();
    expect(loadState().history).toEqual([]);
    read.mockRestore();
    copy.mockRestore();
    updateState((s) => {
      s.managedFirewallIds.push('fw1');
    });
    expect(fs.readFileSync(stateFile, 'utf8')).toBe(original);
    error.mockRestore();
  });

  it('carries over a running commit saved by an earlier version', async () => {
    const active = { progress: { commitId: 'c1' } };
    fs.writeFileSync(
      stateFile,
      JSON.stringify({ version: 1, activeCommit: active }),
      'utf8',
    );
    const { loadState } = await freshStore();
    const state = loadState();
    expect(state.activeCommits).toEqual([active]);
    expect('activeCommit' in state).toBe(false);
  });
});
