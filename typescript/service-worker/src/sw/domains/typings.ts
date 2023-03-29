export enum DomainStorageStores {
  Hosts = 'hosts',
}

export enum AcceptedLookupUrlProtocol {
  Http = 'http:',
  Https = 'https:',
}

export const acceptedLookupUrlProtocols = new Set(
  Object.values(AcceptedLookupUrlProtocol).map(String)
);

export const domainLookupHeaders = {
  canisterId: 'x-ic-canister-id',
};

export const domainStorageProperties = {
  name: 'ic-domains-v2',
  version: 2,
  store: DomainStorageStores.Hosts,
};

export interface DBHostsItem {
  canister:
    | {
        id: string;
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
