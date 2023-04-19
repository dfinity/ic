import { HeaderField } from '../../http-interface/canister_http_interface_types';
import { filterResponseHeaders } from './filter-response-headers';

describe('filterResponseHeaders', () => {
  it('should filter the cache-control header', () => {
    const headers: HeaderField[] = [
      ['Cache-Control', 'no-cache'],
      ['Content-Encoding', 'gzip'],
      ['Content-Type', 'text/html; charset=utf-8'],
    ];

    const result = filterResponseHeaders(headers);

    expect(result).toEqual([
      ['Content-Encoding', 'gzip'],
      ['Content-Type', 'text/html; charset=utf-8'],
    ]);
  });
});
