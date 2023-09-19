import { Principal } from '@dfinity/principal';
import { ICHostInfoEvent } from '../../typings';
import { isMainNet } from '../requests/utils';
import logger from '../../logger';
import { Storage } from '../storage';
import { MalformedCanisterError } from './errors';
import { ResolverMapper } from './mapper';
import { DEFAULT_GATEWAY, hostnameCanisterIdMap } from './static';
import {
  DBHostsItem,
  DomainsStorageDBSchema,
  acceptedLookupUrlProtocols,
  domainLookupHeaders,
  domainStorageProperties,
} from './typings';
import {
  apiGateways,
  isRawDomain,
  maybeResolveCanisterFromHeaders,
  resolveCanisterFromUrl,
} from './utils';

export class CanisterResolver {
  private static instance: CanisterResolver;

  private constructor(
    private readonly storage: Storage<DomainsStorageDBSchema>,
    private readonly ttl = 60 * 60 * 1000, // 60 minutes
    private readonly inflight = new Map<string, Promise<Principal | null>>()
  ) {}

  static async setup(): Promise<CanisterResolver> {
    if (!this.instance) {
      const storage = await CanisterResolver.storageConnection();

      this.instance = new CanisterResolver(storage);
    }

    return this.instance;
  }

  private static async storageConnection(): Promise<
    Storage<DomainsStorageDBSchema>
  > {
    return await Storage.connect<DomainsStorageDBSchema>({
      name: domainStorageProperties.name,
      version: domainStorageProperties.version,
      stores: {
        init: [domainStorageProperties.store],
        default: domainStorageProperties.store,
      },
    });
  }

  async saveICHostInfo(event: ICHostInfoEvent): Promise<void> {
    const item = ResolverMapper.toDBHostsItemFromEvent(event);
    if (item && item.canister) {
      await this.storage.put(self.location.origin, item, {
        ttl: new Date(Date.now() + this.ttl),
      });
    }
  }

  /**
   * Gets the current gateway. On mainnet this is always `DEFAULT_GATEWAY`,
   * on testnets this is based on the current URL, see `getRootDomain` for more information.
   * @returns The current gateway.
   */
  async getCurrentGateway(mainNet = isMainNet): Promise<URL> {
    return mainNet ? DEFAULT_GATEWAY : this.getRootDomain();
  }

  /**
   * Gets the root domain that is currently hosting the service worker,
   * this will be used as the gateway when running on a testnet,
   * or used to determine if a dApp is making requests against itself or another domain.
   *
   * This is based on the current URL and assumes the following format:
   * `${self.location.protocol}//${canisterId}.${gatewayHostname}/${path}`,
   * and will return the following:
   * `${self.location.protocol}//${gatewayHostname}`.
   * If no canister ID is found in the hostname, the full hostname will be returned.
   *
   * For example:
   * `https://rwlgt-iiaaa-aaaaa-aaaaa-cai.small04.testnet.dfinity.network/some-path/`,
   * will return:
   * `https://small04.testnet.dfinity.network/`.
   *
   * @returns The gateway for the testnet hosting the service worker.
   */
  public getRootDomain(): URL {
    const hostnameParts = self.location.hostname.split('.').reverse();
    const rootDomainParts: string[] = [];

    for (const part of hostnameParts) {
      try {
        // we don't need the canister ID at this point,
        // but if we have found a canister ID then we know that we've found the full root domain,
        // so we return it
        Principal.fromText(part);
        return new URL(
          `${self.location.protocol}//${rootDomainParts.reverse().join('.')}`
        );
      } catch (_) {
        // domain part is not a canister ID,
        // so we can assume it is part of the root domain
        rootDomainParts.push(part);
      }
    }

    // this part of the code will be reached if we never find a canister ID in the domain
    // this will happen if we are on a custom domain and it should return the full hostname
    return new URL(`${self.location.protocol}//${self.location.hostname}`);
  }

  resolveLookupFromUrl(domain: URL): Principal | null {
    // maybe resolve from hardcoded mappings to avoid uncessary network round trips
    const staticMapping = hostnameCanisterIdMap.get(domain.hostname);
    if (staticMapping) {
      return staticMapping;
    }

    // handle raw domain as a web2 request
    if (isRawDomain(domain.hostname)) {
      return null;
    }

    // maybe resolve the canister id from url
    return resolveCanisterFromUrl(domain);
  }

  async lookupFromHttpRequest(request: Request): Promise<Principal | null> {
    const url = new URL(request.url);

    if (!acceptedLookupUrlProtocols.has(url.protocol)) {
      return null;
    }

    const canister = maybeResolveCanisterFromHeaders(request.headers);
    if (canister) {
      return canister;
    }

    return await this.lookup(url);
  }

  async lookup(domain: URL): Promise<Principal | null> {
    // inglight map is used to deduplicate lookups for the same domain
    let inflightLookup = this.inflight.get(domain.origin);
    if (inflightLookup) {
      return await inflightLookup;
    }

    inflightLookup = (async (): Promise<Principal | null> => {
      // maybe resolve from information available in the request
      const lookupFromUrl = this.resolveLookupFromUrl(domain);
      if (lookupFromUrl) {
        return lookupFromUrl;
      }

      // maybe resolve from previous cached results
      const cachedLookup = await this.storage.get(domain.origin);
      if (cachedLookup) {
        return ResolverMapper.fromDBHostsItem(cachedLookup);
      }

      // maybe resolve from response headers the domain provides
      const lookup = await this.fetchDomain(domain);

      // we cache lookups to avoid additional round trips to the same domain
      try {
        const dbHostItem: DBHostsItem = ResolverMapper.toDBHostsItem(lookup);
        await this.storage.put(domain.origin, dbHostItem, {
          ttl: new Date(Date.now() + this.ttl),
        });
      } catch (err) {
        // only log the error in case persist transaction fails
        logger.error('Failed to cache host lookup', err);
      }

      return lookup;
    })();

    // caching the promise of inflight requests to enable concurrent
    // requests to the same domain to use the same promise
    this.inflight.set(domain.origin, inflightLookup);
    const lookup = await inflightLookup;
    this.inflight.delete(domain.origin);

    return lookup;
  }

  /**
   * Checks if the given request is a direct api call.
   * @param request The request to check
   */
  public isAPICall(
    request: Request,
    gatewayUrl: URL,
    mainNet = isMainNet
  ): boolean {
    const url = new URL(request.url);

    return (
      url.pathname.startsWith('/api/') &&
      this.isGatewayCall(url, gatewayUrl, mainNet)
    );
  }

  /**
   * Checks if the given request is a call to the `/_/raw/` endpoint.
   * @param request The request to check
   * @param gatewayUrl The current gateway URL
   * @param mainNet Whether the current network is mainnet or not
   * @returns True if the request is a call to the `/_/raw/` endpoint, false otherwise
   */
  public isUnderscoreRawCall(
    request: Request,
    gatewayUrl: URL,
    mainNet = isMainNet
  ): boolean {
    const url = new URL(request.url);

    return (
      url.pathname.startsWith('/_/raw') &&
      this.isGatewayCall(url, gatewayUrl, mainNet)
    );
  }

  private isGatewayCall(
    url: URL,
    gatewayUrl: URL,
    mainNet = isMainNet
  ): boolean {
    if (!mainNet && url.hostname.endsWith(gatewayUrl.hostname)) {
      return true;
    }

    return apiGateways.some((apiGateway) => url.hostname.endsWith(apiGateway));
  }

  /**
   * Performs a HEAD request to the domain expecting to get back the canister id and gateway,
   * if both are not available handles the domain as a web2 request.
   * The lookup request is made over HTTPS for security reasons.
   * @param domain The domain to find out if points to a canister or we2.
   * @param retries Number of fetch tries, only retry on network failures
   */
  private async fetchDomain(
    domain: URL,
    retries = 3
  ): Promise<Principal | null> {
    try {
      const secureDomain = ResolverMapper.toHTTPSUrl(domain);
      const response = await fetch(secureDomain.href, {
        method: 'HEAD',
        mode: 'no-cors',
      });
      const headers = response.headers;

      // we expect a 200 from a request to the http gateway
      const successfulResponse =
        response.status >= 200 && response.status < 300;

      if (successfulResponse && headers.has(domainLookupHeaders.canisterId)) {
        const canisterId = headers.get(domainLookupHeaders.canisterId) ?? '';

        return ResolverMapper.getPrincipalFromText(canisterId);
      }

      return null;
    } catch (err) {
      // we don't retry in case the gateway returned wrong headers
      if (err instanceof MalformedCanisterError) {
        throw err;
      }

      if (retries <= 1) {
        // network failures are thrown after retries
        throw err;
      }

      // retry the request on network failure
      return await this.fetchDomain(domain, retries - 1);
    }
  }
}
