export enum HTTPHeaders {
  Vary = 'vary',
  CacheControl = 'cache-control',
  Range = 'range',
}

export const cacheHeaders = [HTTPHeaders.CacheControl.toString()];

export enum HTTPRequestMethod {
  Get = 'GET',
}

export const headerDirectiveEntrySeparator = '=';
export const varyHeaderSeparator = ',';
export const cacheControlHeaderSeparator = ',';

export interface RequestCacheControlHeader {
  noCache?: boolean;
  noStore?: boolean;
}

export enum RequestCacheControlDirectives {
  NoCache = 'no-cache',
  NoStore = 'no-store',
}

export interface ResponseCacheControlHeader {
  maxAge?: number;
  noStore?: boolean;
}

export enum ResponseCacheControlDirectives {
  NoStore = 'no-store',
  MaxAge = 'max-age',
}

export interface HeaderDirectiveEntry {
  directive: string;
  value?: string;
}

export interface VerifiedResponse {
  response: Response;
  certifiedHeaders: Headers;
}
