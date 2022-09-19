import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import { IDL } from '@dfinity/candid';

export type HeaderField = [string, string];
export interface HttpRequest {
  url: string;
  method: string;
  body: Uint8Array;
  headers: Array<HeaderField>;
}
export interface HttpResponse {
  body: Uint8Array;
  headers: Array<HeaderField>;
  upgrade: [] | [boolean];
  streaming_strategy: [] | [StreamingStrategy];
  status_code: number;
}
export interface StreamingCallbackHttpResponse {
  token: [] | [Token];
  body: Uint8Array;
}
export type StreamingStrategy = {
  Callback: { token: Token; callback: [Principal, string] };
};
export type Token = { type: <T>() => IDL.Type<T> };
export interface _SERVICE {
  http_request: ActorMethod<[HttpRequest], HttpResponse>;
  http_request_update: ActorMethod<[HttpRequest], HttpResponse>;
}
