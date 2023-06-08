import { Principal } from '@dfinity/principal';
import { isMainNet } from '../requests/utils';

export const apiGateways = [
  'boundary.dfinity.network',
  'boundary.ic0.app',
  'ic0.app',
  'icp0.io',
  'icp-api.io',
];

/**
 * Try to resolve the Canister ID to contact from headers.
 * @param headers Headers from the HttpRequest.
 * @returns A Canister ID or null if none were found.
 */
export function maybeResolveCanisterFromHeaders(
  headers: Headers
): Principal | null {
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
export function resolveCanisterFromUrl(url: URL): Principal | null {
  return maybeResolveCanisterFromHostName(url.hostname);
}

export function isRawDomain(hostname: string, mainNet = isMainNet): boolean {
  // For security reasons the match is only made for ic[0-9].app, ic[0-9].dev and icp[0-9].io domains. This makes
  // the match less permissive and prevents unwanted matches for domains that could include raw
  // but still serve as a normal dapp domain that should go through response verification.
  const isIcAppRaw = !!hostname.match(new RegExp(/\.raw\.ic[0-9]+\.app/));
  const isIcDevRaw = !!hostname.match(new RegExp(/\.raw\.testic[0-9]+\.app/));
  const isIcpIoRaw = !!hostname.match(new RegExp(/\.raw\.icp[0-9]+\.io/));
  const isTestnetRaw =
    !mainNet &&
    (!!hostname.match(new RegExp(/\.raw\.[\w-]+\.testnet\.[\w-]+\.network/)) ||
      !!hostname.match(new RegExp(/\.raw\.ic[0-9]+\.dev/)));
  return isIcAppRaw || isIcDevRaw || isIcpIoRaw || isTestnetRaw;
}

/**
 * Split a hostname up-to the first valid canister ID from the right.
 * @param hostname The hostname to analyze.
 * @returns A canister ID followed by all subdomains that are after it, or null if no canister ID were found.
 */
export function maybeResolveCanisterFromHostName(
  hostname: string
): Principal | null {
  const subdomains = hostname.split('.');
  // raw ic domain in handled as a normal web2 request
  if (isRawDomain(hostname)) {
    return null;
  }

  for (const domain of subdomains) {
    try {
      return Principal.fromText(domain);
    } catch (_) {
      // subdomain did not match expected Principal format
      // continue checking each subdomain
    }
  }

  return null;
}
