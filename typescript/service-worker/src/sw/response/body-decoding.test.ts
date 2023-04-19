import { deflate, gzip } from 'pako';
import { HeaderField } from '../../http-interface/canister_http_interface_types';
import { HTTPHeaders } from '../requests';
import { decodeBody } from './body-decoding';
import { createBody } from '../test';

describe('decodeBody', () => {
  const originalBody = createBody();

  it.each([
    ['identity', originalBody],
    ['', originalBody],
    ['deflate', deflate(originalBody)],
    ['gzip', gzip(originalBody)],
  ])('should decode body with %s encoding', (encoding, body) => {
    const headers: HeaderField[] = [[HTTPHeaders.ContentEncoding, encoding]];

    const result = decodeBody(body, headers);

    expect(result).toEqual(originalBody);
  });

  it('should throw if an unrecognized encoding is provided', () => {
    const headers: HeaderField[] = [[HTTPHeaders.ContentEncoding, 'brotli']];

    expect(() => decodeBody(originalBody, headers)).toThrowError(
      'Unsupported encoding: "brotli"'
    );
  });
});
