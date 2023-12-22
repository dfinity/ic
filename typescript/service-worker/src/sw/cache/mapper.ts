import { hashString } from '../../utils';
import { HTTPHeaders, varyHeaderSeparator } from '../requests';
import { CacheStorageNames, DBRequestMetadata, RequestKey } from './typings';

export class CacheMapper {
  /**
   * Creates the request key of a given request composed of hostname, pathname
   * and optional options with method, search and vary headers available from the response.
   * @param request Used to create the key
   * @param response Used to create the key
   * @param options Whether it should use method, search and vary headers to compose the key
   */
  static toRequestKey(
    request: Request,
    response?: Response,
    options?: CacheQueryOptions
  ): RequestKey {
    const url = new URL(request.url);
    const headers: RequestKey['headers'] = [];
    const varyHeader = response?.headers.get(HTTPHeaders.Vary);

    if (!options?.ignoreVary && response && varyHeader) {
      const rawVaryHeaders = varyHeader
        .split(varyHeaderSeparator)
        .map((varyHeader) => varyHeader.toLowerCase().trim());

      // headers need to be sorted to make sure the key has always the same signature
      new Set(rawVaryHeaders.sort()).forEach((varyHeader) => {
        if (varyHeader.length) {
          headers.push([varyHeader, request.headers.get(varyHeader) ?? '']);
        }
      });
    }

    return {
      hostname: url.hostname,
      pathname: url.pathname,
      method: !options?.ignoreMethod ? request.method : null,
      search: !options?.ignoreSearch ? url.search : null,
      headers,
    };
  }

  /**
   * Creates a sha-256 hex from the given request, response and cache query options.
   * @param request Used to create the key
   * @param response Used to create the key
   * @param options Whether it should use method, search and vary headers to compose the key
   */
  static async toRequestKeyHash(
    request: Request,
    response?: Response,
    options?: CacheQueryOptions
  ): Promise<string> {
    const requestKey = CacheMapper.toRequestKey(request, response, options);
    const keyParts = [
      requestKey.hostname,
      requestKey.pathname,
      requestKey.method,
      requestKey.search,
      requestKey.headers,
    ];

    return hashString(`:${keyParts.filter(Boolean).join('::')}:`);
  }

  static toDBRequestMetadata(
    request: Request,
    response: Response
  ): DBRequestMetadata {
    const url = new URL(request.url);
    return {
      hostname: url.hostname,
      pathname: url.pathname,
      method: request.method,
      response: {
        ok: response.ok,
        status: response.status,
      },
    };
  }

  static fromRequestToCacheName(request: Request): CacheStorageNames {
    switch (request.destination) {
      case 'audio':
        return CacheStorageNames.Audio;
      case 'video':
        return CacheStorageNames.Video;
      case 'script':
        return CacheStorageNames.Script;
      case 'style':
        return CacheStorageNames.Style;
      case 'image':
        return CacheStorageNames.Image;
      case 'font':
        return CacheStorageNames.Font;
      default:
        return CacheStorageNames.Other;
    }
  }
}
