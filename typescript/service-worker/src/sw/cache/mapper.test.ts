import { CacheMapper } from './mapper';
import { CacheStorageNames, DBRequestMetadata } from './typings';

describe('Request key mapper', () => {
  it('should create request key with `search` being null when set to ignore', async () => {
    const request = new Request(
      'https://internetcomputer.com/assets/image.png?version=v1'
    );
    const response = new Response(null);

    const key = CacheMapper.toRequestKey(request, response, {
      ignoreSearch: true,
    });
    expect(key.search).toBeNull();
  });

  it('should create request key with `search`', async () => {
    const search = '?version=v1';
    const request = new Request(
      'https://internetcomputer.com/assets/image.png' + search
    );
    const response = new Response(null);

    const key = CacheMapper.toRequestKey(request, response);
    expect(key.search).toEqual(search);
  });

  it('should create request key with `method` being null when set to ignore', async () => {
    const request = new Request('https://internetcomputer.com');
    const response = new Response(null);

    const key = CacheMapper.toRequestKey(request, response, {
      ignoreMethod: true,
    });
    expect(key.method).toBeNull();
  });

  it('should create request key with `method`', async () => {
    const request = new Request('https://internetcomputer.com');
    const response = new Response(null);

    const key = CacheMapper.toRequestKey(request, response);
    expect(key.method).toEqual(request.method);
  });

  it('should create request key with `headers` being empty when set to ignore', async () => {
    const requestHeaders = new Headers();
    requestHeaders.set('Origin', 'example.com');
    const responseHeaders = new Headers();
    responseHeaders.set('Vary', 'Origin, Accept-Language');
    const request = new Request('https://internetcomputer.com', {
      headers: requestHeaders,
    });
    const response = new Response(null, {
      headers: responseHeaders,
    });

    const key = CacheMapper.toRequestKey(request, response, {
      ignoreVary: true,
    });
    expect(key.headers).toEqual([]);
  });

  it('should create request key with `headers` set on `vary`', async () => {
    const requestHeaders = new Headers();
    requestHeaders.set('Origin', 'example.com');
    const responseHeaders = new Headers();
    responseHeaders.set('Vary', 'Origin, Accept-Language');
    const request = new Request('https://internetcomputer.com', {
      headers: requestHeaders,
    });
    const response = new Response(null, {
      headers: responseHeaders,
    });

    const key = CacheMapper.toRequestKey(request, response);
    expect(key.headers).toEqual([
      ['accept-language', ''],
      ['origin', 'example.com'],
    ]);
  });

  it('should create request key with `headers` set on `vary` with the same order', async () => {
    const requestHeaders = new Headers();
    requestHeaders.set('Origin', 'example.com');
    const responseHeaders = new Headers();
    responseHeaders.set('Vary', 'Origin, Accept-Language');
    const responseHeadersOtherOrder = new Headers();
    responseHeadersOtherOrder.set('Vary', 'Accept-Language, Origin');
    const request = new Request('https://internetcomputer.com', {
      headers: requestHeaders,
    });
    const response = new Response(null, {
      headers: responseHeaders,
    });
    const response2 = new Response(null, {
      headers: responseHeadersOtherOrder,
    });

    const key = CacheMapper.toRequestKey(request, response);
    const key2 = CacheMapper.toRequestKey(request, response2);
    expect(key.headers).toEqual(key2.headers);
  });

  it('should create request key with `headers` being empty when vary header not available', async () => {
    const requestHeaders = new Headers();
    requestHeaders.set('Origin', 'example.com');
    const request = new Request('https://internetcomputer.com', {
      headers: requestHeaders,
    });
    const response = new Response(null, {
      headers: new Headers(),
    });

    const key = CacheMapper.toRequestKey(request, response);
    expect(key.headers).toEqual([]);
  });

  it('should hash request key with SHA-256', async () => {
    const expectedHash =
      '12daf8ef542ea345fd842bfacbc203b34e7ab1844154e350f91fcd5260950384';
    const request = new Request('https://example.com');
    const response = new Response();
    const hash = await CacheMapper.toRequestKeyHash(request, response);

    expect(hash).toEqual(expectedHash);
  });
});

describe('Request mapper', () => {
  it('should map request and response to db metadata', async () => {
    const request = new Request('https://internetcomputer.com');
    const response = new Response(null);
    const url = new URL(request.url);
    const expectedMetadata: DBRequestMetadata = {
      hostname: url.hostname,
      method: request.method,
      pathname: url.pathname,
      response: {
        ok: response.ok,
        status: response.status,
      },
    };

    const metadata = CacheMapper.toDBRequestMetadata(request, response);
    expect(metadata).toEqual(expectedMetadata);
  });

  it('should map request with known destination to cache name', async () => {
    const request = new Request('https://internetcomputer.com/image.png');
    const cacheNameFn = (
      destination: RequestDestination
    ): CacheStorageNames => {
      return CacheMapper.fromRequestToCacheName({
        ...request,
        destination,
      });
    };

    expect(cacheNameFn('image')).toEqual(CacheStorageNames.Image);
    expect(cacheNameFn('audio')).toEqual(CacheStorageNames.Audio);
    expect(cacheNameFn('font')).toEqual(CacheStorageNames.Font);
    expect(cacheNameFn('video')).toEqual(CacheStorageNames.Video);
    expect(cacheNameFn('script')).toEqual(CacheStorageNames.Script);
    expect(cacheNameFn('style')).toEqual(CacheStorageNames.Style);
  });

  it('should map request with unknown destination to `other` name', async () => {
    const request = new Request('https://internetcomputer.com/');
    const cacheName = CacheMapper.fromRequestToCacheName(request);

    expect(cacheName).toEqual(CacheStorageNames.Other);
  });
});
