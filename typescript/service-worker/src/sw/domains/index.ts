import { Principal } from '@dfinity/principal';
import { IDBPDatabase, IDBPObjectStore, IDBPTransaction } from 'idb';
import { ICHostInfoEvent } from '../../typings';
import { isMainNet } from '../requests/utils';
import { DBValue, Storage } from '../storage';
import { MalformedCanisterError } from './errors';
import { ResolverMapper } from './mapper';
import { DEFAULT_GATEWAY, hostnameCanisterIdMap } from './static';
import {
  DBHostsItem,
  DomainsStorageDBSchema,
  domainLookupHeaders,
  domainStorageProperties,
  V1DBHostsItem,
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
        init: [CanisterResolver.migrateStorage],
        default: domainStorageProperties.store,
      },
    });
  }

  private static async migrateStorage(
    db: IDBPDatabase<unknown>,
    oldVersion: number,
    transaction: IDBPTransaction<unknown, string[], 'versionchange'>
  ): Promise<
    IDBPObjectStore<unknown, ArrayLike<string>, string, 'versionchange'>
  > {
    switch (oldVersion) {
      default: {
        return db.createObjectStore(domainStorageProperties.store as string);
      }

      case 1: {
        const oldItems: DBValue<V1DBHostsItem>[] = await transaction
          .objectStore(domainStorageProperties.store)
          .getAll();

        db.deleteObjectStore(domainStorageProperties.store);

        const store = db.createObjectStore(
          domainStorageProperties.store as string
        );
        for (const item of oldItems) {
          const canister =
            item.body.canister === false
              ? false
              : { id: item.body.canister.id };
          const newItem: DBValue<DBHostsItem> = {
            expireAt: item.expireAt,
            body: {
              canister,
            },
          };

          await store.put(newItem);
        }

        return store;
      }
    }
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
   * Gets the current gateway. On mainnet this is always `DEFAULT_API_BOUNDARY_NODE`,
   * on testnets this is based on the current URL, see `getTestnetGateway` for more information.
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
   *
   * For example:
   * `https://rwlgt-iiaaa-aaaaa-aaaaa-cai.small04.testnet.dfinity.network/some-path/`,
   * will return:
   * `https://small04.testnet.dfinity.network/`.
   *
   * @returns The gateway for the testnet hosting the service worker.
   */
  public getRootDomain(): URL {
    const splitHostname = self.location.hostname.split('.');
    splitHostname.shift();

    return new URL(`${self.location.protocol}//${splitHostname.join('.')}`);
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
    const canister = maybeResolveCanisterFromHeaders(request.headers);
    if (canister) {
      return canister;
    }

    return await this.lookup(new URL(request.url));
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
        console.error('Failed to cache host lookup', err);
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
    if (!url.pathname.startsWith('/api/')) {
      return false;
    }

    if (!mainNet && url.hostname.endsWith(gatewayUrl.hostname)) {
      return true;
    }

    const hasApiGateway = apiGateways.some((apiGateway) =>
      url.hostname.endsWith(apiGateway)
    );

    return hasApiGateway;
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
