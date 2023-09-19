import { Principal } from '@dfinity/principal';
import { mockLocation } from '../../mocks/location';
import { MalformedCanisterError } from './errors';
import * as resolverImport from './index';
import { domainLookupHeaders } from './typings';

let CanisterResolver: typeof resolverImport.CanisterResolver;

describe('Canister resolver lookups', () => {
  beforeEach(async () => {
    jest.useFakeTimers();
    jest.isolateModules(async () => {
      return import('./index').then((module) => {
        CanisterResolver = module.CanisterResolver;
      });
    });
  });

  afterEach(async () => {
    jest.clearAllMocks();
    jest.clearAllTimers();
  });

  it('should open only one db connection for multiple setup calls', async () => {
    const spyDb = jest.spyOn(indexedDB, 'open');

    for (let i = 0; i <= 10; ++i) {
      await CanisterResolver.setup();
    }

    expect(spyDb).toHaveBeenCalledTimes(1);
  });

  it('should complete the setup of the resolver', async () => {
    const resolver = await CanisterResolver.setup();

    expect(resolver).toBeInstanceOf(CanisterResolver);
  });

  it('should resolve current gateway on testnet', async () => {
    global.self.location = mockLocation(
      'https://rdmx6-jaaaa-aaaaa-aaadq-cai.ic1.app'
    );

    const resolver = await CanisterResolver.setup();
    const currentGateway = await resolver.getCurrentGateway(false);

    expect(currentGateway).not.toEqual(null);
    expect(currentGateway).toEqual(new URL('https://ic1.app'));
  });

  it('should not resolve current gateway on mainnet', async () => {
    global.self.location = mockLocation(
      'https://rdmx6-jaaaa-aaaaa-aaadq-cai.ic1.app'
    );

    const resolver = await CanisterResolver.setup();
    const currentGateway = await resolver.getCurrentGateway(true);

    expect(currentGateway).toEqual(new URL('https://icp-api.io'));
  });

  it('should retry lookup on network failure', async () => {
    const fetchSpy = jest.spyOn(global, 'fetch');
    const resolver = await CanisterResolver.setup();

    fetchSpy.mockRejectedValueOnce(new TypeError('Network failure'));
    fetchSpy.mockResolvedValueOnce(
      new Response(null, {
        status: 200,
        statusText: '200 OK',
      })
    );

    await resolver.lookup(new URL('https://www.dappdomain.io'));

    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it('same domain lookup should use cache promises after first request', async () => {
    const fetchSpy = jest.spyOn(global, 'fetch');
    const resolver = await CanisterResolver.setup();

    fetchSpy.mockResolvedValueOnce(
      new Response(null, {
        status: 200,
        statusText: '200 OK',
      })
    );

    // N calls for the same domain should only do one fetch
    const numberOfCalls = 10;
    const lookups: (Principal | null)[] = [];
    for (let i = 0; i < numberOfCalls; ++i) {
      lookups.push(
        await resolver.lookup(new URL('https://www.customdappdomain.io'))
      );
    }

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(Array(numberOfCalls).fill(lookups[0])).toEqual(lookups);
  });

  it('should fetch canister and gateway with a head request', async () => {
    const fetchSpy = jest.spyOn(global, 'fetch');
    const resolver = await CanisterResolver.setup();
    const hostname = 'www.iccustomdomain.io';
    const url = new URL(`${self.location.protocol}//${hostname}`);

    await resolver.lookup(url);

    fetchSpy.mockResolvedValueOnce(
      new Response(null, {
        status: 200,
        statusText: '200 OK',
      })
    );

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy).toHaveBeenCalledWith(url.href, {
      method: 'HEAD',
      mode: 'no-cors',
    });
  });

  it('should invalidate cached domain after 60 minutes', async () => {
    const fetchSpy = jest.spyOn(global, 'fetch');
    const resolver = await CanisterResolver.setup();
    const hostname = 'www.customdomain.io';
    const ttl = 1000 * 60 * 61; // 61 minutes

    fetchSpy.mockResolvedValue(
      new Response(null, {
        status: 200,
        statusText: '200 OK',
      })
    );

    await resolver.lookup(new URL(`${self.location.protocol}//${hostname}`));
    jest.advanceTimersByTime(ttl);
    await resolver.lookup(new URL(`${self.location.protocol}//${hostname}`));

    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it('should handle status codes that are not 2xx as web2 resources', async () => {
    const fetchSpy = jest.spyOn(global, 'fetch');
    const resolver = await CanisterResolver.setup();
    const hostname = 'www.customdomain.com';
    const canisterId = 'rdmx6-jaaaa-aaaaa-aaadq-cai';

    const mockedHeaders = new Headers();
    mockedHeaders.set(domainLookupHeaders.canisterId, canisterId);
    fetchSpy.mockResolvedValue(
      new Response(null, {
        headers: mockedHeaders,
        status: 500,
        statusText: '500 Internal Server Error',
      })
    );

    const web2resource = await resolver.lookup(
      new URL(`${self.location.protocol}//${hostname}`)
    );

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(web2resource).toEqual(null);
  });

  it('should fail lookup if canister header is malformated', async () => {
    const fetchSpy = jest.spyOn(global, 'fetch');
    const resolver = await CanisterResolver.setup();

    const mockedHeaders = new Headers();
    mockedHeaders.set(
      domainLookupHeaders.canisterId,
      'invalid-canister-format'
    );
    fetchSpy.mockResolvedValue(
      new Response(null, {
        headers: mockedHeaders,
        status: 200,
        statusText: '200 OK',
      })
    );

    let error: Error | null = null;
    try {
      await resolver.lookup(
        new URL(`${self.location.protocol}//anydomain.com`)
      );
    } catch (err) {
      error = err as Error;
    }

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(error).toBeInstanceOf(MalformedCanisterError);
  });

  it('should accept https protocols on lookup', async () => {
    const resolver = await CanisterResolver.setup();
    const canister = Principal.fromText('rdmx6-jaaaa-aaaaa-aaadq-cai');
    const requestUrl = `https://${canister.toText()}.icp0.io`;
    const request = new Request(requestUrl, {
      headers: {
        host: requestUrl,
      },
    });

    const lookup = await resolver.lookupFromHttpRequest(request);

    expect(lookup?.toText()).toEqual(canister.toText());
  });

  it('should not resolve non https protocols on lookup', async () => {
    const resolver = await CanisterResolver.setup();
    const canister = Principal.fromText('rdmx6-jaaaa-aaaaa-aaadq-cai');
    const requestUrl = `custom-protocol://${canister.toText()}.icp0.io`;
    const request = new Request(requestUrl, {
      headers: {
        host: requestUrl,
      },
    });

    const lookup = await resolver.lookupFromHttpRequest(request);

    expect(lookup).toBeNull();
  });

  describe('isAPICall', () => {
    const gatewayURL = new URL('https://icp-api.io');

    it.each([
      'https://boundary.dfinity.network/api/v2/canister/xrfpr-ryaaa-aaaaj-aiq7q-cai/query',
      'https://boundary.ic0.app/api/v2/canister/xrfpr-ryaaa-aaaaj-aiq7q-cai/query',
      'https://ic0.app/api/v2/canister/xrfpr-ryaaa-aaaaj-aiq7q-cai/query',
      'https://icp0.io/api/v2/canister/xrfpr-ryaaa-aaaaj-aiq7q-cai/query',
      'https://icp-api.io/api/v2/canister/xrfpr-ryaaa-aaaaj-aiq7q-cai/query',
    ])('should return true for a request to %s', async (url) => {
      const request = new Request(url);
      const resolver = await CanisterResolver.setup();

      expect(resolver.isAPICall(request, gatewayURL, true)).toEqual(true);
    });

    it.each([
      'https://boundary.dfinity.network/index.js',
      'https://boundary.ic0.app/index.js',
      'https://ic0.app/index.js',
      'https://icp0.io/index.js',
      'https://icp-api.io/index.js',
      'https://evilcorp.com/index.js',
      'https://evilcorp.com/api/v2/canister/xrfpr-ryaaa-aaaaj-aiq7q-cai/query',
    ])('should return false for a request to %s', async (url) => {
      const request = new Request(url);
      const resolver = await CanisterResolver.setup();

      expect(resolver.isAPICall(request, gatewayURL, true)).toEqual(false);
    });
  });

  describe('isGatewayCall', () => {
    const gatewayURL = new URL('https://icp-api.io');

    it.each([
      'https://boundary.dfinity.network/_/raw/index.js',
      'https://boundary.ic0.app/_/raw/index.js',
      'https://ic0.app/_/raw/index.js',
      'https://icp0.io/_/raw/index.js',
      'https://icp-api.io/_/raw/index.js',
    ])('should return true for a request to %s', async (url) => {
      const request = new Request(url);
      const resolver = await CanisterResolver.setup();

      expect(resolver.isUnderscoreRawCall(request, gatewayURL, true)).toEqual(
        true
      );
    });

    it.each([
      'https://boundary.dfinity.network/index.js',
      'https://boundary.ic0.app/index.js',
      'https://ic0.app/index.js',
      'https://icp0.io/index.js',
      'https://icp-api.io/index.js',
      'https://evilcorp.com/_/raw/index.js',
    ])('should return false for a request to %s', async (url) => {
      const request = new Request(url);
      const resolver = await CanisterResolver.setup();

      expect(resolver.isUnderscoreRawCall(request, gatewayURL, true)).toEqual(
        false
      );
    });
  });
});
