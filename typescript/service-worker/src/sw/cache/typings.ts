export enum CacheStorageStores {
  Assets = 'assets',
}

export const cacheStorageProperties = {
  name: 'ic-cache',
  version: 1,
  store: CacheStorageStores.Assets,
};

export interface RequestKey {
  hostname: string;
  pathname: string;
  method: string | null;
  search: string | null;
  headers: Array<[string, string]>;
}

export interface DBRequestMetadata {
  method: string;
  hostname: string;
  pathname: string;
  response: {
    ok: boolean;
    status: number;
  };
}

export interface RequestMatchOptions {
  ignoreSearch: boolean;
  ignoreMethod: boolean;
  ignoreVary: boolean;
}

export type CacheStorageDBSchema = {
  [CacheStorageStores.Assets]: {
    value: {
      body: DBRequestMetadata;
    };
  };
};

export interface CacheResponseOptions {
  request: Request;
  response: Response;
  certifiedResponseHeaders?: Headers;
}

export enum CacheStorageNames {
  Image = 'image',
  Audio = 'audio',
  Video = 'video',
  Script = 'script',
  Style = 'style',
  Font = 'font',
  Other = 'other',
}

export const supportedRequestDestinations = new Set([
  'image',
  'script',
  'style',
  'font',
  'audio',
  'video',
]);
