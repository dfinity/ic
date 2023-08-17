import { inflate, ungzip } from 'pako';
import { HeaderField } from '../../http-interface/canister_http_interface_types';
import { HTTPHeaders } from '../requests';

function getContentEncoding(responseHeaders: HeaderField[]): string {
  return (
    responseHeaders
      .filter(([key]) => key.toLowerCase() === HTTPHeaders.ContentEncoding)
      .map((header) => header[1].trim())
      .pop() ?? ''
  );
}

/**
 * Decode a body (ie. deflate or gunzip it) based on its content-encoding.
 *
 * @param responseBody The response body to decode.
 * @param responseHeaders The response headers.
 */
export function decodeBody(
  responseBody: Uint8Array,
  responseHeaders: HeaderField[]
): Uint8Array {
  const encoding = getContentEncoding(responseHeaders);

  switch (encoding) {
    case 'identity':
    case '':
      return responseBody;
    case 'gzip':
      return ungzip(responseBody);
    case 'deflate':
      return inflate(responseBody);
    default:
      throw new Error(`Unsupported encoding: "${encoding}"`);
  }
}
