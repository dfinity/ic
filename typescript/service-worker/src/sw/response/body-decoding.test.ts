import { deflate, gzip } from 'pako';
import { HeaderField } from '../../http-interface/canister_http_interface_types';
import { HTTPHeaders } from '../requests';
import { decodeBody } from './body-decoding';
import { createBody } from '../test';

async function fetchStream(
  stream: ReadableStream<Uint8Array>
): Promise<Uint8Array> {
  return new Promise((resolve) => {
    const reader = stream.getReader();
    let result = new Uint8Array(0);

    reader.read().then(function processText({ done, value }): Promise<void> {
      if (done) {
        resolve(result);
        return Promise.resolve();
      }

      let newResult = new Uint8Array(result.length + value.length);
      newResult.set(result);
      newResult.set(value, result.length);
      result = newResult;

      return reader.read().then(processText);
    });
  });
}

describe('decodeBody', () => {
  const originalBody = createBody();

  it.each([
    ['identity', originalBody],
    ['', originalBody],
    ['deflate', deflate(originalBody)],
    ['gzip', gzip(originalBody)],
  ])('should decode body with %s encoding', async (encoding, body) => {
    const headers: HeaderField[] = [[HTTPHeaders.ContentEncoding, encoding]];

    const result = decodeBody(body, headers);
    const streamedResult = await fetchStream(result);

    expect(streamedResult).toEqual(originalBody);
  });

  it('should throw if an unrecognized encoding is provided', () => {
    const headers: HeaderField[] = [[HTTPHeaders.ContentEncoding, 'brotli']];

    expect(() => decodeBody(originalBody, headers)).toThrowError(
      'Unsupported encoding: "brotli"'
    );
  });
});
