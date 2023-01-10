import {
  Storage,
  DB_VERSION,
  DB_NAME,
  CreateStoreOptions,
  IDBKey,
  DB_DEFAULT_STORE,
} from './storage';

describe('Storage connection to indexed db', () => {
  let storage!: Storage;

  afterEach(() => {
    storage?.disconnect();
    storage?.remove();
  });

  it('should connect to default db', async () => {
    storage = await Storage.connect();

    expect(storage.db().version).toEqual(DB_VERSION);
    expect(storage.db().name).toEqual(DB_NAME);
  });

  it('should create default store when none provided', async () => {
    storage = await Storage.connect();

    expect(storage.store()).toEqual(DB_DEFAULT_STORE);
  });

  it('should create store and set it to default when single name provided', async () => {
    const storeName = 'ic-awesome';
    storage = await Storage.connect({
      stores: {
        init: [storeName],
      },
    });

    expect(storage.store()).toEqual(storeName);
  });

  it('should connect with custom db name', async () => {
    const dbName = 'ic-rocks';
    storage = await Storage.connect({
      name: dbName,
    });

    expect(storage.db().name).toEqual(dbName);
  });

  it('should connect with custom db version', async () => {
    const version = 2;
    storage = await Storage.connect({
      version,
    });

    expect(storage.db().version).toEqual(version);
  });

  it('should connect with custom db name and version', async () => {
    const dbName = 'ic-rocks';
    const version = 2;
    storage = await Storage.connect({
      name: dbName,
      version,
    });

    expect(storage.db().name).toEqual(dbName);
    expect(storage.db().version).toEqual(version);
  });

  it('should connect and create new store', async () => {
    const storeName: CreateStoreOptions = 'ic-singularity';
    storage = await Storage.connect({
      stores: {
        init: [storeName],
      },
    });

    expect(storage.db().objectStoreNames.length).toEqual(1);
    expect(storage.db().objectStoreNames[0]).toEqual(storeName);
  });

  it('should connect and create multiple stores', async () => {
    const storeNames: CreateStoreOptions[] = [
      'ic-singularity',
      'ic-scalability',
    ];
    storage = await Storage.connect({
      stores: {
        init: storeNames,
      },
    });

    expect(storage.db().objectStoreNames.length).toEqual(2);
  });

  it('should connect and create stores from callback', async () => {
    const storeNames: CreateStoreOptions[] = [
      'ic-singularity',
      (database) => database.createObjectStore<string>('ic-scalability'),
    ];
    storage = await Storage.connect({
      stores: {
        init: storeNames,
      },
    });

    expect(storage.db().objectStoreNames.length).toEqual(2);
  });
});

describe('Storage persist to indexed db', () => {
  let storage!: Storage;

  beforeEach(async () => {
    jest.resetAllMocks();
    jest.useFakeTimers();
    storage = await Storage.connect();
  });

  afterEach(async () => {
    storage.disconnect();
    storage.remove();
  });

  it('values are enveloped with expireAt and unwrapped when returned', async () => {
    const storage = await Storage.connect<{
      stable: {
        value: {
          body: {
            gateway: string;
            canister: string;
          };
        };
      };
    }>({
      version: 2,
      stores: {
        init: ['stable'],
        default: 'stable',
      },
    });
    const key: IDBKey = 'identity.ic0.app';
    const values = {
      gateway: 'ic0.app',
      canister: 'rdmx6-jaaaa-aaaaa-aaadq-cai',
    };

    await storage.put(key, values);
    const foundValue = await storage.get(key, { storeName: 'stable' });

    expect(foundValue?.canister).toEqual(values.canister);
    expect(foundValue?.gateway).toEqual(values.gateway);
  });

  it('should persist even if ttl is not set', async () => {
    const key: IDBKey = 'identity.ic0.app';
    const value = {
      gateway: 'ic0.app',
      canister: 'rdmx6-jaaaa-aaaaa-aaadq-cai',
    };

    await storage.put(key, value);
    const foundValue = await storage.get(key);

    expect(foundValue).toEqual(value);
  });

  it('should remove value if it reachs ttl', async () => {
    const key: IDBKey = 'identity.ic0.app';
    const value = {
      gateway: 'ic0.app',
      canister: 'rdmx6-jaaaa-aaaaa-aaadq-cai',
    };

    await storage.put(key, value, { ttl: new Date(Date.now() + 50) });
    jest.advanceTimersByTime(100);

    const foundValue = await storage.get(key);
    const removedValue = await storage.db().get(DB_DEFAULT_STORE, key);

    expect(foundValue).toEqual(undefined);
    expect(removedValue).toEqual(undefined);
  });

  it('should store value if still belongs in ttl window', async () => {
    const key: IDBKey = 'identity.ic0.app';
    const value = {
      gateway: 'ic0.app',
      canister: 'rdmx6-jaaaa-aaaaa-aaadq-cai',
    };

    await storage.put(key, value, { ttl: new Date(Date.now() + 10000) });

    jest.advanceTimersByTime(100);
    const valueLookupWithinTTL = await storage.get(key);

    jest.advanceTimersByTime(20000);
    const valueLookupAfternTTL = await storage.get(key);

    expect(valueLookupWithinTTL).toEqual(value);
    expect(valueLookupAfternTTL).toEqual(undefined);
  });

  it('should remove all outdated records on new connections', async () => {
    await storage.put(
      'identity.ic0.app',
      {
        gateway: 'ic0.app',
        canister: 'rdmx6-jaaaa-aaaaa-aaadq-cai',
      },
      { ttl: new Date(Date.now() + 10000) }
    );
    await storage.put(
      'nns.ic0.app',
      {
        gateway: 'ic0.app',
        canister: 'qoctq-giaaa-aaaaa-aaaea-cai',
      },
      { ttl: new Date(Date.now() + 20000) }
    );

    jest.advanceTimersByTime(100);
    const hasAllEntries = await storage.getAll();
    jest.advanceTimersByTime(10000);
    const hasOneEntry = await storage.getAll();
    jest.advanceTimersByTime(20000);
    const hasNoEntry = await storage.getAll();

    expect(hasAllEntries.length).toEqual(2);
    expect(hasOneEntry.length).toEqual(1);
    expect(hasNoEntry.length).toEqual(0);
  });
});
