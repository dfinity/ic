import { handleRequest } from './http_request';
import fetch from 'jest-fetch-mock';
import * as Agent from '@dfinity/agent';
import {
  CallRequest,
  QueryRequest,
  QueryResponse,
  QueryResponseStatus,
  ReadStateResponse,
  UnSigned,
} from '@dfinity/agent';
import { IDL } from '@dfinity/candid';
import { fromHex } from '@dfinity/agent/lib/cjs/utils/buffer';
import { Principal } from '@dfinity/principal';
import { HttpRequest } from '../http-interface/canister_http_interface_types';

const CANISTER_ID = 'rdmx6-jaaaa-aaaaa-aaadq-cai';
const TEST_DATA = {
  queryData: {
    root_key:
      '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c050302010361008fcd89d93d038059ceec489f42bbb93fb873a890e9c748dd864741198e822dd24dbb984f7a735bcc75b6abb5d42832ea153c7f7a01e3f9b03b9a67ae4e4dfb00901cb20139ac5f787fae28cc7da755cf2064702220aa7c92282e17b9935169ae',
    certificate:
      'certificate=:2dn3omR0cmVlgwGDAkhjYW5pc3RlcoMCSgAAAAAAAAAHAQGDAk5jZXJ0aWZpZWRfZGF0YYIDWCBb1aIcc2xftgJaN6877pAf6qk3k8NHiyRKu4Hn3ft+/4MCRHRpbWWCA0OHrUtpc2lnbmF0dXJlWDCytYtviuunJRV7M7gStQhiDSJy1Tp1kZIV7WaLSSJ1HeF83rf97V0WAMF+yR8ZdqY=:, tree=:2dn3gwJLaHR0cF9hc3NldHODAkEvggNYIHUJ5b2gx2LSusf5DXWLWyJj+gHMvFQqtePfFjvgjmyp:',
    body: 'hello world!',
  },
  updateData: {
    root_key:
      '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c050302010361008096df0d1ffb96ca6fff319d4e1dd4b8339f3019d7e9848a9d315a6468df1e51dc6989efdcdcb90f33bae821281a90781202aa623dd38eb9cfae16424e7c4764e0ad3362b549b7fc4a5d8bf1f326df0171e12c68814743f8371459b9680fde64',
    certificate:
      'd9d9f7a2647472656583024e726571756573745f7374617475738302582007bf53acde2967b1ddc8f06814fb8a0d037e5ef19ba597e92b9d1febe726698983018302457265706c79820358354449444c046d7b6c02007101716d016c03a2f5ed880400c6a4a19806029aa1b2f90c7a01030c68656c6c6f20776f726c642100c8008302467374617475738203477265706c696564697369676e61747572655830971e62f35e9c288ea9b4c446b8febfc2bf040172a539753bed5349ed671bda6d80b4c7ae641ce9df0fc779deb61511e6',
  },
};

const HeaderFieldType = IDL.Tuple(IDL.Text, IDL.Text);
const HttpRequestType = IDL.Record({
  url: IDL.Text,
  method: IDL.Text,
  body: IDL.Vec(IDL.Nat8),
  headers: IDL.Vec(HeaderFieldType),
});

beforeEach(() => {
  fetch.resetMocks();
});

afterEach(() => {
  jest.spyOn(global.Math, 'random').mockRestore();
});

it('should set content-type: application/cbor and x-content-type-options: nosniff on calls to /api', async () => {
  fetch.mockResponse('test response');

  const response = await handleRequest(
    new Request('https://example.com/api/foo')
  );

  expect(response.headers.get('x-content-type-options')).toEqual('nosniff');
  expect(response.headers.get('content-type')).toEqual('application/cbor');
  expect(await response.text()).toEqual('test response');
  expect(response.status).toEqual(200);
});

it('should reject invalid certification', async () => {
  const queryHttpPayload = createHttpQueryResponsePayload(
    'this payload does not match the certificate and must not be accepted',
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.queryData.certificate
  );
  mockFetchResponses(TEST_DATA.queryData.root_key, { query: queryHttpPayload });

  const response = await handleRequest(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );

  expect(response.status).toEqual(500);
  expect(await response.text()).toEqual('Body does not pass verification');
  expect(fetch.mock.calls).toHaveLength(2);
  expect(fetch.mock.calls[0][0]).toEqual('https://ic0.app/api/v2/status');
  expect(fetch.mock.calls[1][0]).toEqual(
    `https://ic0.app/api/v2/canister/${CANISTER_ID}/query`
  );
});

it('should accept valid certification without callbacks', async () => {
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.queryData.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.queryData.certificate
  );
  mockFetchResponses(TEST_DATA.queryData.root_key, { query: queryHttpPayload });

  const response = await handleRequest(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );

  expect(response.status).toEqual(200);
  expect(await response.text()).toEqual(TEST_DATA.queryData.body);
  expect(fetch.mock.calls).toHaveLength(2);
  expect(fetch.mock.calls[0][0]).toEqual('https://ic0.app/api/v2/status');
  expect(fetch.mock.calls[1][0]).toEqual(
    `https://ic0.app/api/v2/canister/${CANISTER_ID}/query`
  );

  let [queryCall, req] = decodeContent<HttpRequest>(
    fetch.mock.calls[1],
    HttpRequestType
  );
  expect(queryCall.method_name).toEqual('http_request');
  expect(req.url).toEqual('/');
  expect(req.method).toEqual('GET');
});

it('should accept valid certification using callbacks with primitive tokens', async () => {
  const tokenType = IDL.Text;
  const [httpResponseType, CallbackResponseType] = getResponseTypes(tokenType);
  const queryHttpPayload = createHttpQueryResponsePayload(
    'hello',
    httpResponseType,
    TEST_DATA.queryData.certificate,
    [
      {
        Callback: {
          token: 'text token',
          callback: [Principal.anonymous(), 'some_callback_method'],
        },
      },
    ]
  );
  const callbackPayload = createCallbackResponsePayload(
    ' world!',
    CallbackResponseType
  );
  mockFetchResponses(
    TEST_DATA.queryData.root_key,
    { query: queryHttpPayload },
    { query: callbackPayload }
  );

  const response = await handleRequest(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );

  expect(response.status).toEqual(200);
  expect(await response.text()).toEqual(TEST_DATA.queryData.body);
  expect(fetch.mock.calls).toHaveLength(3);
  expect(fetch.mock.calls[0][0]).toEqual('https://ic0.app/api/v2/status');
  fetch.mock.calls
    .slice(1, 3)
    .forEach((call) =>
      expect(call[0]).toEqual(
        `https://ic0.app/api/v2/canister/${CANISTER_ID}/query`
      )
    );

  let [queryCall, req] = decodeContent<HttpRequest>(
    fetch.mock.calls[1],
    HttpRequestType
  );
  expect(queryCall.method_name).toEqual('http_request');
  expect(req.url).toEqual('/');
  expect(req.method).toEqual('GET');

  let [callbackQuery, token] = decodeContent<string>(
    fetch.mock.calls[2],
    tokenType
  );
  expect(callbackQuery.method_name).toEqual('some_callback_method');
  expect(token).toEqual('text token');
});

it('should accept valid certification using multiple callbacks with structured tokens', async () => {
  const [httpResponseType, CallbackResponseType] = getResponseTypes(
    IDL.Record({
      counter: IDL.Nat,
      variant: IDL.Variant({ test1: IDL.Text, test2: IDL.Vec(IDL.Bool) }),
    })
  );
  const queryHttpPayload = createHttpQueryResponsePayload(
    'hel',
    httpResponseType,
    TEST_DATA.queryData.certificate,
    [
      {
        Callback: {
          token: { counter: 12, variant: { test1: 'test' } },
          callback: [Principal.anonymous(), 'some_callback_method'],
        },
      },
    ]
  );
  const callbackPayload1 = createCallbackResponsePayload(
    'lo wo',
    CallbackResponseType,
    [
      {
        counter: BigInt('32654653165435654'),
        variant: { test2: [true, false, true] },
      },
    ]
  );
  const callbackPayload2 = createCallbackResponsePayload(
    'rld!',
    CallbackResponseType
  );
  mockFetchResponses(
    TEST_DATA.queryData.root_key,
    { query: queryHttpPayload },
    { query: callbackPayload1 },
    { query: callbackPayload2 }
  );

  const response = await handleRequest(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );

  expect(response.status).toEqual(200);
  expect(await response.text()).toEqual(TEST_DATA.queryData.body);
  expect(fetch.mock.calls).toHaveLength(4);
  expect(fetch.mock.calls[0][0]).toEqual('https://ic0.app/api/v2/status');
  fetch.mock.calls
    .slice(1, 4)
    .forEach((call) =>
      expect(call[0]).toEqual(
        `https://ic0.app/api/v2/canister/${CANISTER_ID}/query`
      )
    );
});

it('should do update call on upgrade flag', async () => {
  jest.setSystemTime(1650551764352); // required because request id is dependent on time
  jest.spyOn(global.Math, 'random').mockReturnValue(0.5); // required because request id is dependent on 'random' nonce
  mockFetchResponses(TEST_DATA.updateData.root_key, {
    query: createUpgradeQueryResponse(),
    update: createHttpUpdateResponsePayload(TEST_DATA.updateData.certificate),
  });

  const response = await handleRequest(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );

  expect(response.status).toEqual(200);
  expect(await response.text()).toEqual('hello world!');
  expect(fetch.mock.calls).toHaveLength(4);
  expect(fetch.mock.calls[0][0]).toEqual('https://ic0.app/api/v2/status');
  // query, which prompts the update call
  expect(fetch.mock.calls[1][0]).toEqual(
    `https://ic0.app/api/v2/canister/${CANISTER_ID}/query`
  );

  let [queryCall, queryReq] = decodeContent<HttpRequest>(
    fetch.mock.calls[1],
    HttpRequestType
  );
  expect(queryCall.method_name).toEqual('http_request');
  expect(queryCall.request_type).toEqual('query');
  expect(queryReq.url).toEqual('/');
  expect(queryReq.method).toEqual('GET');

  // the update call
  expect(fetch.mock.calls[2][0]).toEqual(
    `https://ic0.app/api/v2/canister/${CANISTER_ID}/call`
  );
  let [updateCall, updateReq] = decodeContent<HttpRequest>(
    fetch.mock.calls[2],
    HttpRequestType
  );
  expect(updateCall.method_name).toEqual('http_request_update');
  expect(updateCall.request_type).toEqual('call');
  expect(updateReq).toEqual(queryReq);

  // retrieve the result of the update call
  expect(fetch.mock.calls[3][0]).toEqual(
    `https://ic0.app/api/v2/canister/${CANISTER_ID}/read_state`
  );
});

function decodeContent<T>(
  [_, request]: [unknown, RequestInit],
  argType: IDL.Type
): [QueryRequest | CallRequest, T] {
  let decodedRequest = Agent.Cbor.decode<UnSigned<QueryRequest | CallRequest>>(
    request.body as ArrayBuffer
  );
  // @ts-ignore
  let decodedArg = IDL.decode([argType], decodedRequest.content.arg)[0] as T;
  return [decodedRequest.content, decodedArg];
}

export type StreamingStrategy = {
  Callback: { token: any; callback: [Principal, string] };
};

function getResponseTypes(tokenType: IDL.Type): [IDL.Type, IDL.Type] {
  const StreamingCallbackHttpResponse = IDL.Record({
    token: IDL.Opt(tokenType),
    body: IDL.Vec(IDL.Nat8),
  });
  const StreamingStrategy = IDL.Variant({
    Callback: IDL.Record({
      token: tokenType,
      callback: IDL.Func(
        [tokenType],
        [StreamingCallbackHttpResponse],
        ['query']
      ),
    }),
  });
  const HttpResponse = IDL.Record({
    body: IDL.Vec(IDL.Nat8),
    headers: IDL.Vec(HeaderFieldType),
    streaming_strategy: IDL.Opt(StreamingStrategy),
    status_code: IDL.Nat16,
    upgrade: IDL.Opt(IDL.Bool),
  });
  return [HttpResponse, StreamingCallbackHttpResponse];
}

function fetchRootKeyResponse(rootKey: string) {
  return Agent.Cbor.encode({
    ic_api_version: '0.18.0',
    root_key: fromHex(rootKey),
    impl_hash:
      '2e2e9c46e6139cd31c2aa736ae85b841af0a368c7083981def876cd4bcea9880',
    impl_version: '7424ea8c83b86cd7867c0686eaeb2c0285450b12',
    replica_health_status: 'healthy',
  });
}

function mockFetchResponses(
  rootKey: string,
  ...httpPayloads: { query: ArrayBuffer; update?: ArrayBuffer }[]
) {
  // index to track how far we are into the (sequential) httpPayloads response array
  let fetchCounter = 0;
  fetch.doMock((req) => {
    // status is just used to fetch the rootKey and is independent of the response payloads
    // -> no need to do anything with the fetchCounter
    if (req.url.endsWith('status')) {
      return Promise.resolve({
        status: 200,
        body: fetchRootKeyResponse(rootKey),
      });
    }
    if (req.url.endsWith('query')) {
      const promise = Promise.resolve({
        status: 200,
        body: httpPayloads[fetchCounter].query,
      });
      // do not update the counter if we expect an update call
      if (!httpPayloads[fetchCounter].update) {
        fetchCounter++;
      }
      return promise;
    }
    // call must be followed by read_state to retrieve the result
    if (req.url.endsWith('call')) {
      return Promise.resolve({
        status: 202,
      });
    }
    if (req.url.endsWith('read_state')) {
      const promise = Promise.resolve({
        status: 200,
        body: httpPayloads[fetchCounter].update,
      });
      // update response has been fetched, go to the next response payload
      fetchCounter++;
      return promise;
    }
    return Promise.reject('unexpected request');
  });
}

function createUpgradeQueryResponse() {
  return createHttpQueryResponsePayload(
    '',
    getResponseTypes(IDL.Text)[0],
    '',
    [],
    true
  );
}

function createHttpQueryResponsePayload(
  body: string,
  responseType: IDL.Type,
  certificate: string = '',
  streamingStrategy: StreamingStrategy[] = [],
  upgrade: boolean = false
) {
  const response = {
    status_code: 200,
    headers: [['IC-Certificate', certificate]],
    body: Array.from(new TextEncoder().encode(body)),
    streaming_strategy: streamingStrategy,
    upgrade: upgrade ? [upgrade] : [],
  };
  const candidResponse: QueryResponse = {
    status: QueryResponseStatus.Replied,
    reply: {
      arg: IDL.encode([responseType], [response]),
    },
  };
  return Agent.Cbor.encode(candidResponse);
}

function createHttpUpdateResponsePayload(certificate: string) {
  const readStateResponse: ReadStateResponse = {
    certificate: fromHex(certificate),
  };
  return Agent.Cbor.encode(readStateResponse);
}

function createCallbackResponsePayload(
  body: string,
  responseType: IDL.Type,
  token: any[] = []
) {
  const response = {
    token: token,
    body: Array.from(new TextEncoder().encode(body)),
  };
  const candidResponse: QueryResponse = {
    status: QueryResponseStatus.Replied,
    reply: {
      arg: IDL.encode([responseType], [response]),
    },
  };
  return Agent.Cbor.encode(candidResponse);
}
