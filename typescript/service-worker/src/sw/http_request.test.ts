import { handleRequest } from './http_request';
import fetch from 'jest-fetch-mock';
import * as cbor from '@dfinity/agent/lib/cjs/cbor';
import { QueryResponse, QueryResponseStatus } from '@dfinity/agent';
import { IDL } from '@dfinity/candid';
import { fromHex } from '@dfinity/agent/lib/cjs/utils/buffer';
import { Principal } from '@dfinity/principal';

const CANISTER_ID = 'rdmx6-jaaaa-aaaaa-aaadq-cai';
const TEST_DATA = [
  {
    root_key:
      '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c050302010361008fcd89d93d038059ceec489f42bbb93fb873a890e9c748dd864741198e822dd24dbb984f7a735bcc75b6abb5d42832ea153c7f7a01e3f9b03b9a67ae4e4dfb00901cb20139ac5f787fae28cc7da755cf2064702220aa7c92282e17b9935169ae',
    certificate:
      'certificate=:2dn3omR0cmVlgwGDAkhjYW5pc3RlcoMCSgAAAAAAAAAHAQGDAk5jZXJ0aWZpZWRfZGF0YYIDWCBb1aIcc2xftgJaN6877pAf6qk3k8NHiyRKu4Hn3ft+/4MCRHRpbWWCA0OHrUtpc2lnbmF0dXJlWDCytYtviuunJRV7M7gStQhiDSJy1Tp1kZIV7WaLSSJ1HeF83rf97V0WAMF+yR8ZdqY=:, tree=:2dn3gwJLaHR0cF9hc3NldHODAkEvggNYIHUJ5b2gx2LSusf5DXWLWyJj+gHMvFQqtePfFjvgjmyp:',
    body: 'hello world!',
  },
];

beforeEach(() => {
  fetch.resetMocks();
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
  const testData = TEST_DATA[0];
  const queryHttpPayload = createHttpQueryResponsePayload(
    testData.certificate,
    'this payload does not match the certificate and must not be accepted',
    getResponseTypes(IDL.Text)[0]
  );
  mockFetchResponses(testData.root_key, queryHttpPayload);

  const response = await handleRequest(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );

  expect(response.status).toEqual(500);
  expect(await response.text()).toEqual('Body does not pass verification');
  expect(fetch.mock.calls).toHaveLength(2);
  expect(fetch.mock.calls[0][0]).toEqual(
    `https://ic0.app/api/v2/canister/${CANISTER_ID}/query`
  );
  expect(fetch.mock.calls[1][0]).toEqual('https://ic0.app/api/v2/status');
});

it('should accept valid certification without callbacks', async () => {
  const testData = TEST_DATA[0];
  const queryHttpPayload = createHttpQueryResponsePayload(
    testData.certificate,
    testData.body,
    getResponseTypes(IDL.Text)[0]
  );
  mockFetchResponses(testData.root_key, queryHttpPayload);

  const response = await handleRequest(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );

  expect(response.status).toEqual(200);
  expect(await response.text()).toEqual(testData.body);
  expect(fetch.mock.calls).toHaveLength(2);
  expect(fetch.mock.calls[0][0]).toEqual(
    `https://ic0.app/api/v2/canister/${CANISTER_ID}/query`
  );
  expect(fetch.mock.calls[1][0]).toEqual('https://ic0.app/api/v2/status');
});

it('should accept valid certification using callbacks with primitive tokens', async () => {
  const testData = TEST_DATA[0];
  const [httpResponseType, CallbackResponseType] = getResponseTypes(IDL.Text);
  const queryHttpPayload = createHttpQueryResponsePayload(
    testData.certificate,
    'hello',
    httpResponseType,
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
  mockFetchResponses(testData.root_key, queryHttpPayload, callbackPayload);

  const response = await handleRequest(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );

  expect(response.status).toEqual(200);
  expect(await response.text()).toEqual(testData.body);
  expect(fetch.mock.calls).toHaveLength(3);
  fetch.mock.calls
    .slice(0, 2)
    .forEach((call) =>
      expect(call[0]).toEqual(
        `https://ic0.app/api/v2/canister/${CANISTER_ID}/query`
      )
    );
  expect(fetch.mock.calls[2][0]).toEqual('https://ic0.app/api/v2/status');
});

it('should accept valid certification using multiple callbacks with structured tokens', async () => {
  const testData = TEST_DATA[0];
  const [httpResponseType, CallbackResponseType] = getResponseTypes(
    IDL.Record({
      counter: IDL.Nat,
      variant: IDL.Variant({ test1: IDL.Text, test2: IDL.Vec(IDL.Bool) }),
    })
  );
  const queryHttpPayload = createHttpQueryResponsePayload(
    testData.certificate,
    'hel',
    httpResponseType,
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
    testData.root_key,
    queryHttpPayload,
    callbackPayload1,
    callbackPayload2
  );

  const response = await handleRequest(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );

  expect(response.status).toEqual(200);
  expect(await response.text()).toEqual(testData.body);
  expect(fetch.mock.calls).toHaveLength(4);
  fetch.mock.calls
    .slice(0, 3)
    .forEach((call) =>
      expect(call[0]).toEqual(
        `https://ic0.app/api/v2/canister/${CANISTER_ID}/query`
      )
    );
  expect(fetch.mock.calls[3][0]).toEqual('https://ic0.app/api/v2/status');
});

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
  const HeaderField = IDL.Tuple(IDL.Text, IDL.Text);
  const HttpResponse = IDL.Record({
    body: IDL.Vec(IDL.Nat8),
    headers: IDL.Vec(HeaderField),
    streaming_strategy: IDL.Opt(StreamingStrategy),
    status_code: IDL.Nat16,
  });
  return [HttpResponse, StreamingCallbackHttpResponse];
}

function fetchRootKeyResponse(rootKey: string) {
  return cbor.encode({
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
  ...queryHttpPayloads: ArrayBuffer[]
) {
  let counter = 0;
  // We need to ignore type checks here because jest-fetch-mock typings were designed for string payloads only.
  // In practice JavaScript does not mind and this still works.
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  fetch.doMock((req) => {
    if (req.url.endsWith('status')) {
      return Promise.resolve({
        status: 200,
        body: fetchRootKeyResponse(rootKey),
      });
    }
    if (req.url.endsWith('query')) {
      const promise = Promise.resolve({
        status: 200,
        body: queryHttpPayloads[counter],
      });
      counter++;
      return promise;
    }
    Promise.reject('unexpected request');
  });
}

function createHttpQueryResponsePayload(
  certificate: string,
  body: string,
  responseType: IDL.Type,
  streamingStrategy: StreamingStrategy[] = []
) {
  const response = {
    status_code: 200,
    headers: [['IC-Certificate', certificate]],
    body: Array.from(new TextEncoder().encode(body)),
    streaming_strategy: streamingStrategy,
  };
  const candidResponse: QueryResponse = {
    status: QueryResponseStatus.Replied,
    reply: {
      arg: IDL.encode([responseType], [response]),
    },
  };
  return cbor.encode(candidResponse);
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
  return cbor.encode(candidResponse);
}
