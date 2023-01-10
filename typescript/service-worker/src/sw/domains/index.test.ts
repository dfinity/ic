import { mockLocation } from '../../mocks/location';
import {
  CurrentGatewayResolveError,
  MalformedCanisterError,
  MalformedHostnameError,
} from './errors';
import { CanisterLookup, DomainLookup, domainLookupHeaders } from './typings';
import * as resolverImport from './index';

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

  it('should resolve current gateway', async () => {
    global.self.location = mockLocation(
      'https://rdmx6-jaaaa-aaaaa-aaadq-cai.ic1.app'
    );

    const resolver = await CanisterResolver.setup();
    const currentGateway = await resolver.getCurrentGateway();

    expect(currentGateway).not.toEqual(null);
    expect(currentGateway).toEqual(new URL('https://ic1.app'));
  });

  it('should fail to resolve current gateway of unknown domain', async () => {
    global.self.location = mockLocation('https://www.unknowncustomdomain.com');

    try {
      const resolver = await CanisterResolver.setup();
      await resolver.getCurrentGateway();
    } catch (err) {
      expect(err).toBeInstanceOf(CurrentGatewayResolveError);
    }
  });

  it('should resolve current gateway of known domain', async () => {
    const protocol = 'https:';
    const canisterId = 'rdmx6-jaaaa-aaaaa-aaadq-cai';
    const gatewayHostname = 'customgateway.io';
    const fetchSpy = jest.spyOn(global, 'fetch');

    global.self.location = mockLocation(
      `${protocol}//www.knowncustomdomain.com`
    );

    const mockedHeaders = new Headers();
    mockedHeaders.set(domainLookupHeaders.canisterId, canisterId);
    mockedHeaders.set(domainLookupHeaders.gateway, gatewayHostname);
    fetchSpy.mockResolvedValueOnce(
      new Response(null, {
        headers: mockedHeaders,
        status: 200,
        statusText: '200 OK',
      })
    );

    const resolver = await CanisterResolver.setup();
    const currentGateway = await resolver.getCurrentGateway();

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(currentGateway).toEqual(new URL(`${protocol}//${gatewayHostname}`));
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
    let lookups: DomainLookup[] = [];
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
    const gatewayHostname = 'customgateway.io';

    const mockedHeaders = new Headers();
    mockedHeaders.set(domainLookupHeaders.canisterId, canisterId);
    mockedHeaders.set(domainLookupHeaders.gateway, gatewayHostname);
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
    expect(web2resource.canister).toEqual(false);
  });

  it('should fail lookup if canister header is malformated', async () => {
    const fetchSpy = jest.spyOn(global, 'fetch');
    const resolver = await CanisterResolver.setup();

    const mockedHeaders = new Headers();
    mockedHeaders.set(
      domainLookupHeaders.canisterId,
      'invalid-canister-format'
    );
    mockedHeaders.set(domainLookupHeaders.gateway, 'ic0.app');
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
      error = err;
    }

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(error).toBeInstanceOf(MalformedCanisterError);
  });

  it('should fail lookup if gateway header is malformated', async () => {
    const fetchSpy = jest.spyOn(global, 'fetch');
    const resolver = await CanisterResolver.setup();

    const mockedHeaders = new Headers();
    mockedHeaders.set(
      domainLookupHeaders.canisterId,
      'rdmx6-jaaaa-aaaaa-aaadq-cai'
    );
    mockedHeaders.set(domainLookupHeaders.gateway, '');
    fetchSpy.mockResolvedValue(
      new Response(null, {
        headers: mockedHeaders,
        status: 200,
        statusText: '200 OK',
      })
    );

    let error: Error | null = null;
    try {
      await resolver.lookup(new URL(`${self.location.protocol}//domain.com`));
    } catch (err) {
      error = err;
    }

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(error).toBeInstanceOf(MalformedHostnameError);
  });

  it('should add gateway protocol as the current location protocol', async () => {
    const protocol = 'http:';
    global.self.location = mockLocation(
      `${protocol}//rdmx6-jaaaa-aaaaa-aaadq-cai.ic0.app`
    );

    const canisterId = 'qoctq-giaaa-aaaaa-aaaea-cai';
    const gatewayHostname = 'anothergateway.io';
    const fetchSpy = jest.spyOn(global, 'fetch');
    const resolver = await CanisterResolver.setup();

    const mockedHeaders = new Headers();
    mockedHeaders.set(domainLookupHeaders.canisterId, canisterId);
    mockedHeaders.set(domainLookupHeaders.gateway, gatewayHostname);
    fetchSpy.mockResolvedValue(
      new Response(null, {
        headers: mockedHeaders,
        status: 200,
        statusText: '200 OK',
      })
    );

    const urlContainsCanisterLookup = await resolver.lookup(
      new URL('https://g3wsl-eqaaa-aaaan-aaaaa-cai.customgateway.com')
    );
    const customDomainLookup = await resolver.lookup(
      new URL('https://newdomain.com')
    );

    expect(urlContainsCanisterLookup).not.toEqual(null);
    expect(customDomainLookup).not.toEqual(null);
    expect(urlContainsCanisterLookup.canister).not.toBeFalsy();
    expect(customDomainLookup.canister).not.toBeFalsy();
    expect(
      (urlContainsCanisterLookup.canister as CanisterLookup).gateway.protocol
    ).toEqual(protocol);
    expect(
      (customDomainLookup.canister as CanisterLookup).gateway.protocol
    ).toEqual(protocol);
  });
});
