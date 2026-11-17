import { createHash } from 'node:crypto';
import { getAccount } from './auth';

/** Hash JSON as it would be sent, ignoring object key order but preserving array/step order. */
export function canonicalPlanHash(value: unknown): string {
  const json = JSON.stringify(value, (_key, v: unknown) =>
    v && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(
          Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
        )
      : v,
  );
  if (json === undefined) throw new Error('Invalid review plan.');
  return createHash('sha256').update(json).digest('hex');
}

/** Bind confirmation to executable data and the cached active account, never prompting for auth. */
export function reviewPlanHash(operation: string, plan: unknown): string {
  const account = getAccount();
  return canonicalPlanHash({
    version: 1,
    operation,
    account: account
      ? {
          method: account.method,
          tenantId: account.tenantId,
          username: account.username,
        }
      : null,
    plan,
  });
}
