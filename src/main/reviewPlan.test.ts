import { beforeEach, describe, expect, it, vi } from 'vitest';

const { getAccount } = vi.hoisted(() => ({ getAccount: vi.fn() }));
vi.mock('./auth', () => ({ getAccount }));
import { canonicalPlanHash, reviewPlanHash } from './reviewPlan';

beforeEach(() => {
  getAccount.mockReset();
  getAccount.mockReturnValue({
    method: 'cli',
    username: 'reviewer@example.com',
    tenantId: 'tenant',
  });
});

describe('canonicalPlanHash', () => {
  it('is stable for reordered nested JSON keys and normal JSON undefined handling', () => {
    const first = {
      scope: '/target',
      body: { z: [{ b: 2, a: 1 }], a: undefined },
    };
    const second = { body: { z: [{ a: 1, b: 2 }] }, scope: '/target' };
    expect(canonicalPlanHash(first)).toBe(canonicalPlanHash(second));
    expect(canonicalPlanHash(first)).toMatch(/^[a-f0-9]{64}$/);
  });

  it('preserves array/step order and every target and body field', () => {
    const plan = {
      scope: '/target',
      body: { retained: 'original' },
      steps: ['PUT', 'DELETE'],
    };
    for (const changed of [
      { ...plan, scope: '/other' },
      { ...plan, body: { retained: 'changed' } },
      { ...plan, steps: ['DELETE', 'PUT'] },
    ])
      expect(canonicalPlanHash(changed)).not.toBe(canonicalPlanHash(plan));
  });

  it('does not drop special JSON property names', () => {
    expect(
      canonicalPlanHash(JSON.parse('{"__proto__":{"scope":"other"}}')),
    ).not.toBe(canonicalPlanHash({}));
  });
});

describe('reviewPlanHash', () => {
  it('separates operations and excludes cosmetic account metadata', () => {
    const hash = reviewPlanHash('setup', {});
    expect(reviewPlanHash('cleanup', {})).not.toBe(hash);
    getAccount.mockReturnValue({
      ...getAccount(),
      displayName: 'A new display name',
      tenants: [],
    });
    expect(reviewPlanHash('setup', {})).toBe(hash);
  });

  it('uses only cached account context, including signed-out state', () => {
    getAccount.mockReturnValue(null);
    const hash = reviewPlanHash('setup', {});
    expect(reviewPlanHash('setup', {})).toBe(hash);
    getAccount.mockReturnValue({ method: 'cli', tenantId: 'tenant' });
    expect(reviewPlanHash('setup', {})).not.toBe(hash);
  });
});
