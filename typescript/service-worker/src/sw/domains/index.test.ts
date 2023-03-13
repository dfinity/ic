import { Principal } from '@dfinity/principal';
import { IDBPDatabase, IDBPTransaction } from 'idb';
import { mockLocation } from '../../mocks/location';
import { MalformedCanisterError } from './errors';
import {
  DBHostsItem,
  domainLookupHeaders,
  domainStorageProperties,
  V1DBHostsItem,
} from './typings';
import { Storage, CreateStoreFn, DBValue } from '../storage';
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
    let lookups: (Principal | null)[] = [];
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

  describe('database migrations', () => {
    const storeMock = {
      put: jest.fn(),
      getAll: jest.fn(),
    };
    const transactionMock = {
      objectStore: jest.fn().mockReturnValue(storeMock),
    };
    const dbMock = {
      deleteObjectStore: jest.fn(),
      createObjectStore: jest.fn().mockReturnValue(storeMock),
    };

    beforeEach(async () => {
      CanisterResolver['instance'] = null as any;
    });

    function mockConnect(previousVersion: number) {
      const connectSpy = jest.spyOn(Storage, 'connect');

      connectSpy.mockImplementation(async (args) => {
        const upgradeFn = args?.stores?.init?.[0] as CreateStoreFn;

        await upgradeFn(
          dbMock as unknown as IDBPDatabase<unknown>,
          previousVersion,
          transactionMock as unknown as IDBPTransaction<
            unknown,
            string[],
            'versionchange'
          >
        );

        return {} as Storage<unknown>;
      });

      return connectSpy;
    }

    it('should migrate database version from 1 to 2', async () => {
      const previousVersion = 1;
      const connectSpy = mockConnect(previousVersion);

      const oldDbItems: DBValue<V1DBHostsItem>[] = [
        {
          expireAt: 1678118590100,
          body: {
            canister: false,
          },
        },
        {
          expireAt: undefined,
          body: {
            canister: {
              gateway: 'https://ic0.app',
              id: 'rdmx6-jaaaa-aaaaa-aaadq-cai',
            },
          },
        },
        {
          expireAt: 694479600000,
          body: {
            canister: {
              gateway: 'https://icp-api.io',
              id: 'ewh3f-3qaaa-aaaap-aazjq-cai',
            },
          },
        },
        {
          expireAt: undefined,
          body: {
            canister: false,
          },
        },
      ];
      const expectedNewDbItems: DBValue<DBHostsItem>[] = [
        {
          expireAt: 1678118590100,
          body: {
            canister: false,
          },
        },
        {
          expireAt: undefined,
          body: {
            canister: {
              id: 'rdmx6-jaaaa-aaaaa-aaadq-cai',
            },
          },
        },
        {
          expireAt: 694479600000,
          body: {
            canister: {
              id: 'ewh3f-3qaaa-aaaap-aazjq-cai',
            },
          },
        },
        {
          expireAt: undefined,
          body: {
            canister: false,
          },
        },
      ];

      storeMock.getAll.mockResolvedValue(oldDbItems);

      await CanisterResolver.setup();

      expect(connectSpy).toHaveBeenCalled();
      expect(transactionMock.objectStore).toHaveBeenCalledWith(
        domainStorageProperties.store
      );
      expect(storeMock.getAll).toHaveBeenCalled();
      expect(dbMock.deleteObjectStore).toHaveBeenCalledWith(
        domainStorageProperties.store
      );
      expect(dbMock.createObjectStore).toHaveBeenCalledWith(
        domainStorageProperties.store
      );

      expect(storeMock.put).toHaveBeenCalledTimes(expectedNewDbItems.length);
      for (const item of expectedNewDbItems) {
        expect(storeMock.put).toHaveBeenCalledWith(item);
      }
    });

    it('should init new databases', async () => {
      const previousVersion = 2;
      const connectSpy = mockConnect(previousVersion);

      await CanisterResolver.setup();

      expect(connectSpy).toHaveBeenCalled();
      expect(dbMock.createObjectStore).toHaveBeenCalledWith(
        domainStorageProperties.store
      );

      expect(transactionMock.objectStore).not.toHaveBeenCalled();
      expect(storeMock.getAll).not.toHaveBeenCalled();
      expect(dbMock.deleteObjectStore).not.toHaveBeenCalledWith();
      expect(storeMock.put).not.toHaveBeenCalled();
    });
  });
});
