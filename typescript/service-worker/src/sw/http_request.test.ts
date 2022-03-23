import { handleRequest } from './http_request';
import fetch from 'jest-fetch-mock';

beforeEach(() => {
  fetch.resetMocks();
});

it('should set content-type: application/cbor and x-content-type-options: nosniff on calls to /api', async () => {
  const response = await handleRequest(
    new Request('https://example.com/api/foo')
  );

  expect(response.headers.get('x-content-type-options')).toEqual('nosniff');
  expect(response.headers.get('content-type')).toEqual('application/cbor');
});
