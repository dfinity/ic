import { ICHostInfoEvent } from '../../typings';
import { Storage } from '../storage';
import {
  CurrentGatewayResolveError,
  MalformedCanisterError,
  MalformedHostnameError,
} from './errors';
import { ResolverMapper } from './mapper';
import { hostnameCanisterIdMap } from './static';
import {
  DBHostsItem,
  DomainLookup,
  DomainsStorageDBSchema,
  domainLookupHeaders,
  domainStorageProperties,
} from './typings';
import {
  isRawDomain,
  maybeResolveCanisterFromHeaders,
  resolveCanisterFromUrl,
} from './utils';

export class CanisterResolver {
  private static instance: CanisterResolver;

  private constructor(
    private readonly storage: Storage<DomainsStorageDBSchema>,
    private readonly ttl = 60 * 60 * 1000, // 60 minutes
    private readonly inflight = new Map<string, Promise<DomainLookup>>()
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
      await this.storage.put(event.hostname, item, {
        ttl: new Date(Date.now() + this.ttl),
      });
    }
  }

  async getCurrentGateway(): Promise<URL> {
    const lookup = await this.lookup(new URL(self.location.href), false);

    if (!lookup.canister) {
      throw new CurrentGatewayResolveError();
    }

    return lookup.canister.gateway;
  }

  resolveLookupFromUrl(domain: URL): DomainLookup | null {
    // maybe resolve from hardcoded mappings to avoid uncessary network round trips
    if (hostnameCanisterIdMap.has(domain.hostname)) {
      return hostnameCanisterIdMap.get(domain.hostname);
    }

    // handle raw domain as a web2 request
    if (isRawDomain(domain.hostname)) {
      return { canister: false };
    }

    // maybe resolve the canister id from url
    const canister = resolveCanisterFromUrl(domain);
    if (canister) {
      return {
        canister: {
          gateway: canister.gateway,
          principal: canister.principal,
        },
      };
    }

    return null;
  }

  async lookupFromHttpRequest(request: Request): Promise<DomainLookup> {
    const canister = maybeResolveCanisterFromHeaders(request.headers);
    if (canister) {
      return {
        canister: {
          gateway: canister.gateway,
          principal: canister.principal,
        },
      };
    }

    return await this.lookup(new URL(request.url));
  }

  async lookup(domain: URL, useCurrentGateway = true): Promise<DomainLookup> {
    // inglight map is used to deduplicate lookups for the same domain
    let inflightLookup = this.inflight.get(domain.hostname);
    if (inflightLookup) {
      const lookup = await inflightLookup;
      return useCurrentGateway ? await this.useCurrentGateway(lookup) : lookup;
    }

    inflightLookup = (async (): Promise<DomainLookup> => {
      // maybe resolve from information available in the request
      const lookupFromUrl = this.resolveLookupFromUrl(domain);
      if (lookupFromUrl) {
        return lookupFromUrl;
      }

      // maybe resolve from previous cached results
      const cachedLookup = await this.storage.get(domain.hostname);
      if (cachedLookup) {
        return ResolverMapper.fromDBHostsItem(cachedLookup);
      }

      // maybe resolve from response headers the domain provides
      const lookup = await this.fetchDomain(domain);

      // we cache lookups to avoid additional round trips to the same domain
      try {
        const dbHostItem: DBHostsItem = ResolverMapper.toDBHostsItem(lookup);
        await this.storage.put(domain.hostname, dbHostItem, {
          ttl: new Date(Date.now() + this.ttl),
        });
      } catch (err) {
        // only log the error in case persist transaction fails
        console.error('Failed to cache host lookup', err);
      }

      return lookup;
    })();

    // caching the promise of inflight requests to enable concurrent
    // requests to the same domain to use the same promise
    this.inflight.set(domain.hostname, inflightLookup);
    const lookup = await inflightLookup;
    this.inflight.delete(domain.hostname);

    return useCurrentGateway ? await this.useCurrentGateway(lookup) : lookup;
  }

  /**
   * Checks if the given request is a direct api call.
   * @param request The request to check
   */
  public isAPICall(
    request: Request,
    gateway: URL,
    lookup: DomainLookup
  ): boolean {
    const url = new URL(request.url);
    if (!url.pathname.startsWith('/api/')) {
      return false;
    }

    if (url.hostname.endsWith(gateway.hostname)) {
      return true;
    }

    return lookup.canister !== false;
  }

  /**
   * Checks if the given request is a request to the same domain.
   * @param request The request to check
   */
  public async isIcDomain(request: Request): Promise<boolean> {
    const url = new URL(request.url);
    const sameDomain =
      url.hostname.endsWith(self.location.hostname) &&
      !url.hostname.endsWith(`raw.${self.location.hostname}`);
    if (sameDomain) {
      return true;
    }

    const lookup = await this.lookupFromHttpRequest(request);
    if (lookup.canister) {
      const gateway = lookup.canister.gateway;
      return (
        url.hostname.endsWith(gateway.hostname) &&
        !url.hostname.endsWith(`raw.${gateway.hostname}`)
      );
    }

    return false;
  }

  /**
   * Enrich the domain lookup with the current gateway for all canister api calls,
   * this enables the user to have the freedom to choose the gateway he would
   * be communicating with instead of having the domain mandating it.
   * @param lookup Lookup for the given domain
   */
  private async useCurrentGateway(lookup: DomainLookup): Promise<DomainLookup> {
    if (
      lookup.canister &&
      lookup.canister.gateway.hostname !== self.location.hostname
    ) {
      lookup.canister.gateway = await this.getCurrentGateway();
    }

    return lookup;
  }

  /**
   * Performs a HEAD request to the domain expecting to get back the canister id and gateway,
   * if both are not available handles the domain as a web2 request.
   * @param domain The domain to find out if points to a canister or we2.
   * @param retries Number of fetch tries, only retry on network failures
   */
  private async fetchDomain(domain: URL, retries = 3): Promise<DomainLookup> {
    try {
      const response = await fetch(domain.href, {
        method: 'HEAD',
        mode: 'no-cors',
      });
      const headers = response.headers;
      const lookup: DomainLookup = { canister: false };

      // we expect a 200 from a request to the http gateway
      const successfulResponse =
        response.status >= 200 && response.status < 300;

      if (
        successfulResponse &&
        headers.has(domainLookupHeaders.canisterId) &&
        headers.has(domainLookupHeaders.gateway)
      ) {
        const canisterId = headers.get(domainLookupHeaders.canisterId);
        const gateway = headers.get(domainLookupHeaders.gateway);
        lookup.canister = {
          principal: ResolverMapper.getPrincipalFromText(canisterId),
          gateway: ResolverMapper.getURLFromHostname(gateway),
        };
      }

      return lookup;
    } catch (err) {
      // we don't retry in case the gateway returned wrong headers
      if (
        err instanceof MalformedCanisterError ||
        err instanceof MalformedHostnameError
      ) {
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
