import { HTTPHeaders, HTTPRequestMethod, RequestMapper } from '../requests';
import { Storage } from '../storage';
import { CacheMapper } from './mapper';
import {
  CacheResponseOptions,
  CacheStorageDBSchema,
  cacheStorageProperties,
  supportedRequestDestinations,
} from './typings';

export class ResponseCache {
  private static instance: ResponseCache;

  private constructor(
    private readonly storage: Storage<CacheStorageDBSchema>
  ) {}

  static async setup(): Promise<ResponseCache> {
    if (!this.instance) {
      const storage = await ResponseCache.storageConnection();

      this.instance = new ResponseCache(storage);
    }

    return this.instance;
  }

  private static async storageConnection(): Promise<
    Storage<CacheStorageDBSchema>
  > {
    return await Storage.connect<CacheStorageDBSchema>({
      name: cacheStorageProperties.name,
      version: cacheStorageProperties.version,
      stores: {
        init: [cacheStorageProperties.store],
        default: cacheStorageProperties.store,
      },
    });
  }

  public async match(request: Request): Promise<Response | undefined> {
    const cache = await this.cacheDB(request);
    const response = await cache.match(request);
    if (!response) {
      return;
    }
    const requestKeyHash = await CacheMapper.toRequestKeyHash(
      request,
      response
    );
    const metadata = await this.storage.get(requestKeyHash);
    if (!metadata) {
      await cache.delete(request);
      return;
    }

    // if the browser has been force refreshed we should remove the cache entry
    const cacheControl = RequestMapper.toRequestCacheControlHeader(
      request.headers
    );
    if (cacheControl?.noCache) {
      await cache.delete(request);
      await this.storage.delete(requestKeyHash);
      return;
    }

    return response;
  }

  /**
   * Requests can be cached if they are GET and are loading assets.
   */
  static isRequestCachingSupported(request: Request): boolean {
    const isSupportedDestination = supportedRequestDestinations.has(
      request.destination
    );

    const isSupportedMethod =
      request.method.toLowerCase() === HTTPRequestMethod.Get.toLowerCase();

    const isRangeRequest = !!request.headers.get(HTTPHeaders.Range);

    return isSupportedDestination && isSupportedMethod && !isRangeRequest;
  }

  private shouldCacheResponse(
    request: Request,
    responseHeaders = new Headers()
  ): boolean {
    const requestCacheControl = RequestMapper.toRequestCacheControlHeader(
      request.headers
    );
    if (requestCacheControl?.noStore) {
      return false;
    }

    const responseCacheControl =
      RequestMapper.toResponseCacheControlHeader(responseHeaders);
    if (responseCacheControl?.noStore) {
      return false;
    }

    return responseCacheControl?.maxAge !== undefined;
  }

  /**
   * Decides whether it should cache the response using the available etag and cache control headers.
   * @param request Request is used to calculate the cache key
   * @param response Response being cached
   * @param options Whether it should use method, search and vary headers to compose the key
   */
  public async save({
    request,
    response,
    certifiedResponseHeaders = new Headers(),
  }: CacheResponseOptions): Promise<boolean> {
    if (!this.shouldCacheResponse(request, certifiedResponseHeaders)) {
      return false;
    }

    const cache = await this.cacheDB(request);
    const requestKeyHash = await CacheMapper.toRequestKeyHash(
      request,
      response
    );
    const metadata = CacheMapper.toDBRequestMetadata(request, response);

    // cache control strategy
    const responseCacheControl = RequestMapper.toResponseCacheControlHeader(
      certifiedResponseHeaders
    );
    const cacheTTL = responseCacheControl?.maxAge
      ? new Date(Date.now() + responseCacheControl.maxAge * 1000) // max-age seconds to ms
      : undefined;

    await cache.put(request, response.clone());
    await this.storage.put(requestKeyHash, metadata, {
      ttl: cacheTTL,
    });

    return true;
  }

  /**
   * Creates a cache instance for the cache name associated with the given request.
   * @param request Used to resolve the cache name
   */
  private async cacheDB(request: Request): Promise<Cache> {
    const cacheName = CacheMapper.fromRequestToCacheName(request);
    return await self.caches.open(cacheName);
  }
}
