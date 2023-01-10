import { Principal } from '@dfinity/principal';

export interface CanisterLookup {
  principal: Principal;
  gateway: URL;
}

export interface DomainLookup {
  canister: CanisterLookup | false;
}

export type StaticDomainMappings = Map<string, DomainLookup>;

export enum DomainStorageStores {
  Hosts = 'hosts',
}

export const domainLookupHeaders = {
  canisterId: 'x-ic-canister-id',
  gateway: 'x-ic-gateway',
};

export const domainStorageProperties = {
  name: 'ic-domains',
  version: 1,
  store: DomainStorageStores.Hosts,
};

export interface DBHostsItem {
  canister:
    | {
        id: string;
        gateway: string;
      }
    | false;
}

export type DomainsStorageDBSchema = {
  [DomainStorageStores.Hosts]: {
    value: {
      body: DBHostsItem;
    };
  };
};
