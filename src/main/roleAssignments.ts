import { createHash } from 'node:crypto';
import { getPrincipal } from './auth';
import { armRequest } from './arm';
import { parseResourceId } from '../shared/resourceId';

const ARM_AUTHORIZATION_API_VERSION = '2022-04-01';

/** Stable per (scope, user, role), so granting twice is harmless. */
export function roleAssignmentName(
  scope: string,
  principalId: string,
  roleId: string,
): string {
  const h = createHash('sha256')
    .update(`${scope.toLowerCase()}|${principalId}|${roleId}`)
    .digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

/**
 * Gives the signed-in user a built-in role on `scope` (any resource ID). An existing assignment
 * counts as success. Needs Microsoft.Authorization/roleAssignments/write (Owner or User Access
 * Administrator); other errors are thrown for the caller to explain.
 */
export async function grantRole(scope: string, roleId: string): Promise<void> {
  const { subscriptionId } = parseResourceId(scope);
  const principal = await getPrincipal();
  const name = roleAssignmentName(scope, principal.objectId, roleId);
  try {
    await armRequest(
      `${scope}/providers/Microsoft.Authorization/roleAssignments/${name}?api-version=${ARM_AUTHORIZATION_API_VERSION}`,
      {
        method: 'PUT',
        body: JSON.stringify({
          properties: {
            roleDefinitionId: `/subscriptions/${subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/${roleId}`,
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
