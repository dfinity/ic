import { Principal } from '@dfinity/principal';
import { CanisterLookup } from './typings';

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
          gateway: url,
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
  return !!hostname.match(new RegExp(/\.raw\.ic[0-9]+\./));
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
      return {
        principal,
        gateway: new URL(
          self.location.protocol + '//' + topdomains.reverse().join('.')
        ),
      };
    } catch (_) {
      topdomains.push(domain);
    }
  }

  return null;
}
