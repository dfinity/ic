import { Principal } from '@dfinity/principal';
import { isMainNet } from '../requests/utils';
import { DEFAULT_GATEWAY } from './static';
import { CanisterLookup } from './typings';

export const apiGateways = [
  'boundary.dfinity.network',
  'boundary.ic0.app',
  'ic0.app',
  'icp-api.io',
];

/**
 * Try to resolve the Canister ID to contact from headers.
 * @param headers Headers from the HttpRequest.
 * @returns A Canister ID or null if none were found.
 */
export function maybeResolveCanisterFromHeaders(
  headers: Headers
): CanisterLookup | null {
  const maybeHostHeader = headers.get('host');
  if (maybeHostHeader) {
    // Remove the port.
    const lookup = maybeResolveCanisterFromHostName(
      maybeHostHeader.replace(/:\d+$/, '')
    );
    if (lookup) {
      return lookup;
    }
  }

  return null;
}

/**
 * Try to resolve the Canister ID to contact from a URL string.
 * @param url The URL (normally from the request).
 * @returns A Canister ID or null if none were found.
 */
export function resolveCanisterFromUrl(url: URL): CanisterLookup | null {
  try {
    let lookup = maybeResolveCanisterFromHostName(url.hostname);
    if (!lookup) {
      const principal = maybeResolveCanisterIdFromSearchParam(url.searchParams);
      if (principal) {
        lookup = {
          principal,
          gateway: isMainNet ? DEFAULT_GATEWAY : url,
        };
      }
    }

    return lookup;
  } catch (_) {
    return null;
  }
}

/**
 * Try to resolve the Canister ID to contact in the search params.
 * @param searchParams The URL Search params.
 * @returns A Canister ID or null if none were found.
 */
export function maybeResolveCanisterIdFromSearchParam(
  searchParams: URLSearchParams
): Principal | null {
  const maybeCanisterId = searchParams.get('canisterId');
  if (maybeCanisterId) {
    try {
      return Principal.fromText(maybeCanisterId);
    } catch (e) {
      // Do nothing.
    }
  }

  return null;
}

export function isRawDomain(hostname: string): boolean {
  // For security reasons the match is only made for ic[0-9].app, ic[0-9].dev and icp[0-9].io domains. This makes
  // the match less permissive and prevents unwanted matches for domains that could include raw
  // but still serve as a normal dapp domain that should go through response verification.
  const isIcAppRaw = !!hostname.match(new RegExp(/\.raw\.ic[0-9]+\.app/));
  const isIcDevRaw = !!hostname.match(new RegExp(/\.raw\.ic[0-9]+\.dev/));
  const isIcpIoRaw = !!hostname.match(new RegExp(/\.raw\.icp[0-9]+\.io/));
  return isIcAppRaw || isIcDevRaw || isIcpIoRaw;
}

/**
 * Split a hostname up-to the first valid canister ID from the right.
 * @param hostname The hostname to analyze.
 * @returns A canister ID followed by all subdomains that are after it, or null if no canister ID were found.
 */
export function maybeResolveCanisterFromHostName(
  hostname: string
): CanisterLookup | null {
  const subdomains = hostname.split('.').reverse();
  const topdomains: string[] = [];
  // raw ic domain in handled as a normal web2 request
  if (isRawDomain(hostname)) {
    return null;
  }

  for (const domain of subdomains) {
    try {
      const principal = Principal.fromText(domain);
      const gateway = isMainNet
        ? DEFAULT_GATEWAY
        : new URL(
            self.location.protocol + '//' + topdomains.reverse().join('.')
          );
      return {
        principal,
        gateway,
      };
    } catch (_) {
      topdomains.push(domain);
    }
  }

  return null;
}
