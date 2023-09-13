import {
  openDB,
  deleteDB,
  IDBPDatabase,
  IDBPObjectStore,
  IDBPTransaction,
} from 'idb';

const DB_NAME = 'sw';
const DB_VERSION = 1.0;
const DB_DEFAULT_STORE = 'main';
const TTL_INDEX_NAME = 'ttl';
const TTL_INDEX_KEY_PATH = 'expireAt';

type KeysOf<T> = keyof T & string;
type DBValue<T = unknown> = { expireAt?: number; body: T };
type DBValueSchema = {
  value: DBValue;
};
type DBSchema = { [storeName: string]: DBValueSchema };
type StoreName<StorageDB> = StorageDB extends DBSchema
  ? KeysOf<StorageDB>
  : 'main';
type PickDBSchemaValue<
  StorageDB extends DBSchema | unknown,
  Name extends StoreName<StorageDB>
> = StorageDB extends DBSchema ? StorageDB[Name]['value'] : DBValue;

type IDBKey = IDBValidKey | IDBKeyRange;
type CreateStoreFn = (
  database: IDBPDatabase<unknown>,
  oldVersion: number,
  transaction: IDBPTransaction<unknown, string[], 'versionchange'>
) => Promise<
  IDBPObjectStore<unknown, ArrayLike<string>, string, 'versionchange'>
>;
type CreateStoreOptions = CreateStoreFn | string;
type InitStores = CreateStoreOptions[];

interface StoresOptions<StorageDB extends DBSchema | unknown = unknown> {
  init?: InitStores;
  default?: StoreName<StorageDB>;
}

interface StorageConnectOptions<
  StorageDB extends DBSchema | unknown = unknown
> {
  name?: string;
  version?: number;
  stores?: StoresOptions<StorageDB>;
  onTerminated?: () => void;
}

/**
 * Provides custom access to indexed db storage while still
 * keeping access to the underlying idb object.
 */
class Storage<StorageDB extends DBSchema | unknown = unknown> {
  private constructor(
    private readonly idb: IDBPDatabase<unknown>,
    private readonly defaultStore: StoreName<StorageDB>
  ) {}

  /**
   * Retrieves the underlying IDBPDatabase instance.
   */
  db(): IDBPDatabase<unknown> {
    return this.idb;
  }

  /**
   * Retrieves the default store name used for access.
   */
  store(): StoreName<StorageDB> {
    return this.defaultStore;
  }

  /**
   * Connects to the given database name from indexed db.
   *
   * @param name Name of the database to connect
   * @param version Version of the database
   * @param stores Stores options
   * @param onTerminated Callback when the browser interrupts the db connection
   */
  static async connect<StorageDB extends DBSchema | unknown = unknown>({
    name = DB_NAME,
    version = DB_VERSION,
    stores = {},
    onTerminated,
  }: StorageConnectOptions<StorageDB> = {}): Promise<Storage<StorageDB>> {
    if (!stores?.init || !stores?.init?.length) {
      // we initialize the default store in case no other store is provided
      stores.init = [DB_DEFAULT_STORE];
    }

    const idb = await openDB(name, version, {
      async upgrade(database, oldVersion, _newVersion, transaction) {
        for (const createStore of stores.init ?? []) {
          if (typeof createStore !== 'string') {
            const store = await createStore(database, oldVersion, transaction);
            store.createIndex(TTL_INDEX_NAME, TTL_INDEX_KEY_PATH);
            return;
          }

          if (database.objectStoreNames.contains(createStore)) {
            // we return early here to avoid a store with the same name to be created
            // on db version changes which would cause an error to be thrown
            return;
          }

          const store = database.createObjectStore(createStore);
          store.createIndex(TTL_INDEX_NAME, TTL_INDEX_KEY_PATH);
        }

        database.onversionchange = function () {
          database.close();
        };
      },
      terminated() {
        onTerminated?.();
      },
    });

    if (stores?.default && !idb.objectStoreNames.contains(stores?.default)) {
      throw new Error('Default store name not found');
    }

    const defaultStore =
      stores?.default ?? (idb.objectStoreNames[0] as StoreName<StorageDB>);
    const storage = new Storage<StorageDB>(idb, defaultStore);

    await storage.removeOutdatedRecords();

    return storage;
  }

  /**
   * Closes the open database connection after all active transactions are finalized.
   */
  async disconnect(): Promise<void> {
    return this.idb.close();
  }

  /**
   * Removes the active indexed db storage.
   */
  async remove(): Promise<void> {
    return deleteDB(this.idb.name);
  }

  /**
   * Gets the value for a given key from indexed db store, if the value has already expired
   * it's removed and returns undefined.
   *
   * @param key Key to fetch from the indexed db
   * @param storeName Optional store name, defaults to initial store
   */
  async get(
    key: IDBKey,
    opts?: { storeName?: StoreName<StorageDB> }
  ): Promise<
    PickDBSchemaValue<StorageDB, StoreName<StorageDB>>['body'] | undefined
  > {
    const store = opts?.storeName ?? this.defaultStore;
    const value: PickDBSchemaValue<
      StorageDB,
      StoreName<StorageDB>
    > = await this.idb.get(store, key);

    if (value?.expireAt && Date.now() >= value.expireAt) {
      await this.idb.delete(store, key);
      return;
    }

    return value?.body;
  }

  /**
   * Deletes the value for a given key from indexed db store if available.
   *
   * @param key Key to fetch from the indexed db
   * @param storeName Optional store name, defaults to initial store
   */
  async delete(
    key: IDBKey,
    opts?: { storeName?: StoreName<StorageDB> }
  ): Promise<void> {
    const store = opts?.storeName ?? this.defaultStore;
    await this.idb.delete(store, key);
  }

  /**
   * Gets all values from indexed db store, if the value has already expired
   * it's removed and returns undefined.
   *
   * @param storeName Optional store name, defaults to initial store
   */
  async getAll(opts?: {
    storeName?: StoreName<StorageDB>;
  }): Promise<PickDBSchemaValue<StorageDB, StoreName<StorageDB>>['body'][]> {
    const store = opts?.storeName ?? this.defaultStore;
    await this.removeOutdatedRecords({ storeName: store });
    const values: PickDBSchemaValue<StorageDB, StoreName<StorageDB>>[] =
      await this.idb.getAll(store);

    return values.map((value) => value?.body);
  }

  /**
   * Sets the value for a given key to indexed db store, it wraps the value with the given ttl to
   * expire the record. If TTL is not present, the value won't expire.
   *
   * @param key Key to set into the indexed db
   * @param value Value to be persisted
   * @param ttl Expire date for the value
   * @param storeName Optional store name, defaults to initial store
   * @returns
   */
  async put(
    key: IDBKey,
    value: PickDBSchemaValue<StorageDB, StoreName<StorageDB>>['body'],
    opts?: {
      ttl?: Date;
      storeName?: StoreName<StorageDB>;
    }
  ): Promise<IDBValidKey> {
    const store = opts?.storeName ?? this.defaultStore;
    const expireAt = opts?.ttl?.getTime();
    const storeValue: DBValue = {
      expireAt: expireAt && expireAt > Date.now() ? expireAt : undefined,
      body: value,
    };

    return this.idb.put(store, storeValue, key);
  }

  /**
   * Removes all entries for the given store.
   *
   * @param storeName Optional store name, defaults to initial store
   */
  async clear(opts?: { storeName?: StoreName<StorageDB> }): Promise<void> {
    const store = opts?.storeName ?? this.defaultStore;
    return this.idb.clear(store);
  }

  /**
   * Cleanup all outdated records of a given store
   */
  private async removeOutdatedRecords(opts?: {
    storeName?: StoreName<StorageDB>;
  }): Promise<void> {
    const store = opts?.storeName ?? this.defaultStore;
    const entriesUntil = IDBKeyRange.upperBound(Date.now());
    const transaction = this.idb.transaction(store, 'readwrite');
    const expiredKeys = await transaction.db.getAllKeysFromIndex(
      store,
      TTL_INDEX_NAME,
      entriesUntil
    );
    const removeOperations = expiredKeys.map((expiredKey) =>
      transaction.db.delete(store, expiredKey)
    );

    await Promise.all([...removeOperations, transaction.done]);
  }
}

export {
  DB_NAME,
  DB_VERSION,
  DB_DEFAULT_STORE,
  Storage,
  StorageConnectOptions,
  DBValue,
  CreateStoreFn,
  StoresOptions,
  IDBKey,
  CreateStoreOptions,
  InitStores,
  DBSchema,
};
