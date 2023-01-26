import { parseSafeInteger } from '../../utils';
import {
  RequestCacheControlHeader,
  RequestCacheControlDirectives,
  cacheControlHeaderSeparator,
  HTTPHeaders,
  ResponseCacheControlHeader,
  ResponseCacheControlDirectives,
  HeaderDirectiveEntry,
  headerDirectiveEntrySeparator,
} from './typings';

export class RequestMapper {
  static toRequestCacheControlHeader(
    headers: Headers
  ): RequestCacheControlHeader | undefined {
    const cacheControlHeader = headers.get(HTTPHeaders.CacheControl);
    if (!cacheControlHeader) {
      return;
    }

    const cacheControl: RequestCacheControlHeader = {};
    cacheControlHeader
      .split(cacheControlHeaderSeparator)
      .map((directive) => RequestMapper.toHeaderDirectiveEntry(directive))
      .forEach((entry) => {
        switch (entry.directive) {
          case RequestCacheControlDirectives.NoCache: {
            cacheControl.noCache = true;
            break;
          }
          case RequestCacheControlDirectives.NoStore: {
            cacheControl.noStore = true;
            break;
          }
        }
      });

    return cacheControl;
  }

  static toResponseCacheControlHeader(
    headers: Headers
  ): ResponseCacheControlHeader | undefined {
    const cacheControlHeader = headers.get(HTTPHeaders.CacheControl);
    if (!cacheControlHeader) {
      return;
    }

    const cacheControl: ResponseCacheControlHeader = {};
    cacheControlHeader
      .split(cacheControlHeaderSeparator)
      .map((directive) => RequestMapper.toHeaderDirectiveEntry(directive))
      .forEach((entry) => {
        switch (entry.directive) {
          case ResponseCacheControlDirectives.MaxAge: {
            const maybeMaxAge = parseSafeInteger(entry.value);
            if (!Number.isNaN(maybeMaxAge) && maybeMaxAge >= 0) {
              cacheControl.maxAge = maybeMaxAge;
              // max-age = 0 is equivalent to no-store
              if (maybeMaxAge === 0) {
                cacheControl.noStore = true;
              }
            }
            break;
          }
          case ResponseCacheControlDirectives.NoStore: {
            cacheControl.noStore = true;
            break;
          }
        }
      });

    return cacheControl;
  }

  static toHeaderDirectiveEntry(directive: string): HeaderDirectiveEntry {
    const [key, value] = directive.split(headerDirectiveEntrySeparator);
    return {
      directive: key.toLowerCase().trim(),
      value: value?.toLowerCase().trim(),
    };
  }
}
