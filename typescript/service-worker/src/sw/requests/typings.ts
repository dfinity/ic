import { ActorSubclass, HttpAgent } from '@dfinity/agent';
import { _SERVICE } from '../../http-interface/canister_http_interface_types';
import { Principal } from '@dfinity/principal';

export enum HTTPHeaders {
  Vary = 'vary',
  CacheControl = 'cache-control',
  Range = 'range',
  ContentEncoding = 'content-encoding',
  BoundaryNodeRequestId = 'x-request-id',
}

export const cacheHeaders = [HTTPHeaders.CacheControl.toString()];

export const responseVerificationFailedResponse = Object.freeze({
  status: 500,
  statusText: 'Response verification failed',
});

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

export interface UpdateCallHandlerResult {
  result: VerifiedResponse;
  boundaryNodeRequestId?: string;
}

export interface FetchAssetRequest {
  url: string;
  method: string;
  body: Uint8Array;
  headers: [string, string][];
}

export interface FetchAssetResponse {
  body: Uint8Array;
  encoding: string;
  headers: [string, string][];
  statusCode: number;
}

export interface FetchAssetData {
  updateCall: boolean;
  request: FetchAssetRequest;
  response: FetchAssetResponse;
}

export type FetchAssetResult =
  | {
      ok: false;
      error: unknown;
    }
  | {
      ok: true;
      data: FetchAssetData;
    };

export interface FetchAssetOptions {
  request: Request;
  canisterId: Principal;
  agent: HttpAgent;
  actor: ActorSubclass<_SERVICE>;
  certificateVersion: number;
}
