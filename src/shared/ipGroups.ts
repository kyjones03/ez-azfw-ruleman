import { addressEntryError } from './cidr';
import { nameError } from './naming';

export interface CreateIpGroupRequest {
  subscriptionId: string;
  resourceGroup: string;
  location: string;
  name: string;
  addresses: string[];
}

export interface IpGroupContext {
  resourceGroups: string[];
  locations: { name: string; displayName: string }[];
}

export const MAX_IP_GROUP_ADDRESSES = 5000;

export function ipGroupAddressesError(addresses: string[]): string | undefined {
  if (!addresses.length) return 'Enter at least one IP address, CIDR or range.';
  if (addresses.length > MAX_IP_GROUP_ADDRESSES)
    return `An IP group can contain at most ${MAX_IP_GROUP_ADDRESSES} address entries.`;
  for (const [i, address] of addresses.entries()) {
    const error =
      address.trim() === '*'
        ? 'Wildcards are not allowed in IP groups.'
        : addressEntryError(address);
    if (error) return `Address ${i + 1}: ${error}`;
  }
  return undefined;
}

/** Shared by the creation form and the main process before any Azure write. */
export function ipGroupErrors(
  request: CreateIpGroupRequest,
): Partial<Record<keyof CreateIpGroupRequest, string>> {
  const errors: Partial<Record<keyof CreateIpGroupRequest, string>> = {};
  if (
    !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(
      request.subscriptionId,
    )
  )
    errors.subscriptionId = 'Select a subscription.';
  const resourceGroup = nameError('resourceGroup', request.resourceGroup);
  if (resourceGroup) errors.resourceGroup = resourceGroup;
  if (!/^[a-z0-9]{2,40}$/i.test(request.location))
    errors.location = 'Select a location.';
  const name = nameError('ipGroup', request.name);
  if (name) errors.name = name;
  const addresses = ipGroupAddressesError(request.addresses);
  if (addresses) errors.addresses = addresses;
  return errors;
}
