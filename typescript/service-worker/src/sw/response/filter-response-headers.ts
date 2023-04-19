import { HeaderField } from '../../http-interface/canister_http_interface_types';
import { cacheHeaders } from '../requests';

// cache headers are remove since those are handled by
// cache storage within the service worker. If returned they would
// reach https://www.chromium.org/blink/ in the cache of chromium which
// could cache those entries in memory and those requests can't be
// intercepted by the service worker
export function filterResponseHeaders(
  responseHeaders: HeaderField[]
): HeaderField[] {
  return responseHeaders.filter(
    ([key]) => !cacheHeaders.includes(key.trim().toLowerCase())
  );
}
