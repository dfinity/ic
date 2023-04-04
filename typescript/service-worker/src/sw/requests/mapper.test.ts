import { RequestMapper } from './mapper';

describe('Requests mapper', () => {
  let headers: Headers;

  beforeEach(async (): Promise<void> => {
    headers = new Headers();
  });

  it('should map no-store from request cache-control header', async () => {
    headers.set('cache-control', `no-store`);

    const requestCacheControl =
      RequestMapper.toRequestCacheControlHeader(headers);

    expect(requestCacheControl?.noStore).toBeTruthy();
  });

  it('should map no-cache from request cache-control header', async () => {
    headers.set('cache-control', `no-cache`);

    const requestCacheControl =
      RequestMapper.toRequestCacheControlHeader(headers);

    expect(requestCacheControl?.noCache).toBeTruthy();
  });

  it('should map no-store from response cache-control header', async () => {
    headers.set('cache-control', `no-store`);

    const responseCacheControl =
      RequestMapper.toResponseCacheControlHeader(headers);

    expect(responseCacheControl?.noStore).toBeTruthy();
  });

  it('should map no-store from response cache-control header when max-age is zero', async () => {
    headers.set('cache-control', `max-age=0`);

    const responseCacheControl =
      RequestMapper.toResponseCacheControlHeader(headers);

    expect(responseCacheControl?.noStore).toBeTruthy();
  });

  it('should map max-age=0 from response cache-control header', async () => {
    headers.set('cache-control', `max-age=0`);

    const responseCacheControl =
      RequestMapper.toResponseCacheControlHeader(headers);

    expect(responseCacheControl?.maxAge).toEqual(0);
  });

  it('should fail to map max-age=unknown from response cache-control header', async () => {
    headers.set('cache-control', `max-age=unknown`);

    const responseCacheControl =
      RequestMapper.toResponseCacheControlHeader(headers);

    expect(responseCacheControl?.maxAge).toBeUndefined();
  });

  it('should fail to map max-age when int overflows from response cache-control header', async () => {
    headers.set('cache-control', `max-age=1${Number.MAX_SAFE_INTEGER}`);

    const responseCacheControl =
      RequestMapper.toResponseCacheControlHeader(headers);

    expect(responseCacheControl?.maxAge).toBeUndefined();
  });

  it('should append same header name values from response verification headers', async () => {
    const headers = RequestMapper.fromResponseVerificationHeaders([
      ['Content-Encoding', 'gzip'],
      ['Cache-Control', 'no-cache'],
      ['Cache-Control', 'no-store'],
    ]);

    expect(headers.get('content-encoding')).toEqual('gzip');
    expect(headers.get('cache-control')).toEqual('no-cache, no-store');
  });
});
