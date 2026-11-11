// Reference data for the rule editor's pickers: IP Groups, service tags, FQDN tags and web
// categories. Each lookup fails independently so one missing permission doesn't hide the rest.
import { onSignOut } from './auth';
import { network, describeAzureError } from './azure';
import { discoverIpGroups } from './ipGroups';
import type { IpGroupInfo, RuleLookups } from '../shared/types';

const CACHE_MS = 15 * 60_000;
const cache = new Map<string, { at: number; value: Promise<RuleLookups> }>();
onSignOut(() => cache.clear());

async function attempt<T>(
  label: string,
  errors: string[],
  fn: () => Promise<T>,
  fallback: T,
): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    errors.push(`${label}: ${describeAzureError(err)}`);
    return fallback;
  }
}

async function load(
  subscriptionId: string,
  location: string,
): Promise<RuleLookups> {
  const errors: string[] = [];
  const client = network(subscriptionId);
  const [ipGroups, serviceTags, fqdnTags, webCategories] = await Promise.all([
    attempt(
      "IP Groups couldn't be listed",
      errors,
      discoverIpGroups,
      [] as IpGroupInfo[],
    ),
    attempt(
      "Service tags couldn't be loaded",
      errors,
      async () => {
        const result = await client.serviceTags.list(location);
        return (result.values ?? [])
          .filter((v) => v.name)
          .map((v) => ({
            name: v.name!,
            region: v.properties?.region || undefined,
            prefixCount: v.properties?.addressPrefixes?.length ?? 0,
          }))
          .sort((a, b) => a.name.localeCompare(b.name));
      },
      [] as RuleLookups['serviceTags'],
    ),
    attempt(
      "FQDN tags couldn't be loaded",
      errors,
      async () => {
        const names: string[] = [];
        for await (const t of client.azureFirewallFqdnTags.listAll())
          if (t.fqdnTagName ?? t.name) names.push((t.fqdnTagName ?? t.name)!);
        return names.sort();
      },
      [] as string[],
    ),
    attempt(
      "Web categories couldn't be loaded",
      errors,
      async () => {
        const out: RuleLookups['webCategories'] = [];
        for await (const c of client.webCategories.listBySubscription())
          if (c.name) out.push({ name: c.name, group: c.group || undefined });
        return out.sort((a, b) => a.name.localeCompare(b.name));
      },
      [] as RuleLookups['webCategories'],
    ),
  ]);
  return { ipGroups, serviceTags, fqdnTags, webCategories, errors };
}

/** Forgets cached lookups so the next request goes to Azure (the Refresh button). */
export function clearLookupCache(): void {
  cache.clear();
}

/** Cached per subscription and region for a few minutes; failures aren't cached. */
export function getRuleLookups(
  subscriptionId: string,
  location: string,
): Promise<RuleLookups> {
  const key = `${subscriptionId}|${location}`.toLowerCase();
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.value;
  const entry = { at: Date.now(), value: load(subscriptionId, location) };
  // Only drop this entry: a refresh or sign-out may have replaced it meanwhile.
  const forget = () => {
    if (cache.get(key) === entry) cache.delete(key);
  };
  entry.value.then((r) => {
    if (r.errors.length) forget();
  }, forget);
  cache.set(key, entry);
  return entry.value;
}
