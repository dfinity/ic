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

const createStream = (array: Uint8Array): ReadableStream => {
  return new ReadableStream({
    start: (controller) => {
      controller.enqueue(array);
      controller.close();
    },
  });
};

/**
 * Decode a body (ie. deflate or gunzip it) based on its content-encoding.
 *
 * @param responseBody The response body to decode.
 * @param responseHeaders The response headers.
 */
export function decodeBody(
  responseBody: Uint8Array,
  responseHeaders: HeaderField[]
): ReadableStream {
  const encoding = getContentEncoding(responseHeaders);
  const bodyStream = createStream(responseBody);

  switch (encoding) {
    case 'identity':
    case '':
      return bodyStream;
    case 'gzip':
      return bodyStream.pipeThrough(new DecompressionStream('gzip'));
    case 'deflate':
      return bodyStream.pipeThrough(new DecompressionStream('deflate'));
    default:
      throw new Error(`Unsupported encoding: "${encoding}"`);
  }
}
