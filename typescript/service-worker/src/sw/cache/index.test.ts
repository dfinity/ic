import * as indexImport from './index';
import { mockBrowserCacheAPI } from '../../mocks/browser-cache';

let ResponseCache: typeof indexImport.ResponseCache;

describe('Response cache calculation', () => {
  beforeEach(async () => {
    jest.useFakeTimers();
    jest.isolateModules(async () => {
      return import('./index').then((module) => {
        ResponseCache = module.ResponseCache;
      });
    });

    self.caches = mockBrowserCacheAPI();
  });

  it('should open only one db connection for multiple setup calls', async () => {
    const spyDb = jest.spyOn(indexedDB, 'open');

    for (let i = 0; i <= 10; ++i) {
      await ResponseCache.setup();
    }

    expect(spyDb).toHaveBeenCalledTimes(1);
  });

  afterEach(async () => {
    jest.clearAllMocks();
    jest.clearAllTimers();
  });

  it('should setup a new ResponseCache instance', async () => {
    const cache = await ResponseCache.setup();

    expect(cache).toBeInstanceOf(ResponseCache);
  });

  it('should not match unknown request', async () => {
    const cache = await ResponseCache.setup();
    const unknownRequest = new Request('https://example.com');
    const matched = await cache.match(unknownRequest);

    expect(matched).toBeUndefined();
  });

  it('should match stored request and response object', async () => {
    const cache = await ResponseCache.setup();
    const request = new Request('https://example.com/image.png');
    const expectedResponse = new Response(null);
    Object.defineProperty(expectedResponse, 'url', {
      get: () => undefined,
    });
    const shouldCacheResponseSpy = jest.spyOn(
      cache as unknown as { shouldCacheResponse(): boolean },
      'shouldCacheResponse'
    );
    shouldCacheResponseSpy.mockReturnValueOnce(true);

    await cache.save({
      request,
      response: expectedResponse,
      certifiedResponseHeaders: expectedResponse.headers,
    });

    const response = await cache.match(request);
    expect(expectedResponse).toEqual(response);
  });

  it('should cache request with response header max-age > 0', async () => {
    const headers = new Headers();
    headers.set('cache-control', 'max-age=60');
    const cache = await ResponseCache.setup();
    const request = new Request('https://internetcomputer.com');
    Object.defineProperty(request, 'destination', {
      get: (): string => 'image',
    });
    const expectedResponse = new Response(null);
    Object.defineProperty(expectedResponse, 'url', {
      get: () => undefined,
    });

    await cache.save({
      request,
      response: expectedResponse,
      certifiedResponseHeaders: headers,
    });

    const response = await cache.match(request);
    expect(expectedResponse).toEqual(response);
  });

  it('should not cache request with response header max-age = 0', async () => {
    const headers = new Headers();
    headers.set('cache-control', 'max-age=0');
    const cache = await ResponseCache.setup();
    const request = new Request('https://internetcomputer.com');
    const expectedResponse = new Response(null, { headers });

    await cache.save({
      request,
      response: expectedResponse,
      certifiedResponseHeaders: expectedResponse.headers,
    });

    const response = await cache.match(request);
    expect(response).toBeUndefined();
  });

  it('should not cache request with the response header `no-store`', async () => {
    const headers = new Headers();
    headers.set('cache-control', 'no-store');
    const cache = await ResponseCache.setup();
    const request = new Request('https://internetcomputer.com');
    const expectedResponse = new Response(null, { headers });

    await cache.save({
      request,
      response: expectedResponse,
      certifiedResponseHeaders: expectedResponse.headers,
    });

    const response = await cache.match(request);
    expect(response).toBeUndefined();
  });

  it('should not cache request with the request header `no-store` and response set to max-age > 0', async () => {
    const headers = new Headers();
    headers.set('cache-control', 'no-store');
    const cache = await ResponseCache.setup();
    const request = new Request('https://internetcomputer.com', { headers });
    const responseHeaders = new Headers();
    responseHeaders.set('cache-control', 'max-age=50');
    const expectedResponse = new Response(null, { headers: responseHeaders });

    await cache.save({
      request,
      response: expectedResponse,
      certifiedResponseHeaders: expectedResponse.headers,
    });

    const response = await cache.match(request);
    expect(response).toBeUndefined();
  });
});
