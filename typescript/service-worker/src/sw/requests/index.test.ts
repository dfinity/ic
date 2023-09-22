import * as Agent from '@dfinity/agent';
import {
  CallRequest,
  QueryRequest,
  QueryResponse,
  QueryResponseStatus,
  ReadStateResponse,
  UnSigned,
} from '@dfinity/agent';
import { fromHex } from '@dfinity/agent/lib/cjs/utils/buffer';
import { IDL } from '@dfinity/candid';
import { Principal } from '@dfinity/principal';
import fetch from 'jest-fetch-mock';
import { v4 as uuidv4 } from 'uuid';
import { HttpRequest } from '../../http-interface/canister_http_interface_types';
import { CanisterResolver } from '../domains';
import { maxCertTimeOffsetNs } from '../response';
import { HTTPHeaders, RequestProcessor } from './index';
import * as requestUtils from './utils';

const CANISTER_ID = 'qoctq-giaaa-aaaaa-aaaea-cai';
const maxCertTimeOffsetMs = Number(maxCertTimeOffsetNs) / 1_000_000;
const INVALID_ROOT_KEY =
  '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c050302010361008fcd89d93d038059ceec489f42bbb93fb873a890e9c748dd864741198e822dd24dbb984f7a735bcc75b6abb5d42832ea153c7f7a01e3f9b03b9a67ae4e4dfb00901cb20139ac5f787fae28cc7da755cf2064702220aa7c92282e17b9935169ae';

interface QueryCallTestFixture {
  root_key: string;
  certificate: string;
  body: string;
  certificate_time: number;
}
interface UpdateCallTestFixture {
  root_key: string;
  certificate: string;
  request_time: number;
}
interface AllTestFixtures {
  query_call: QueryCallTestFixture;
  query_call_with_index_html_fallback: QueryCallTestFixture;
  query_call_with_dscvr_canister_id: QueryCallTestFixture;
  query_call_with_no_witness: QueryCallTestFixture;
  query_call_with_invalid_witness: QueryCallTestFixture;
  update_call: UpdateCallTestFixture;
}
const TEST_DATA: AllTestFixtures = require('../../../test_utils/fixtures.json');

const HeaderFieldType = IDL.Tuple(IDL.Text, IDL.Text);
const HttpRequestType = IDL.Record({
  url: IDL.Text,
  method: IDL.Text,
  body: IDL.Vec(IDL.Nat8),
  headers: IDL.Vec(HeaderFieldType),
});
beforeEach(() => {
  jest.useFakeTimers();
  fetch.resetMocks();
  jest
    .spyOn(requestUtils, 'loadResponseVerification')
    .mockResolvedValue(Promise.resolve());
});
afterEach(() => {
  jest.spyOn(global.Math, 'random').mockRestore();
});

it('should not set content-type: application/cbor and x-content-type-options: nosniff on non-ic calls to /api', async () => {
  fetch.mockResponse('test response');

  const requestProcessor = new RequestProcessor(
    new Request('https://example.com/api/foo')
  );
  const response = await requestProcessor.perform();

  expect(response.headers.get('x-content-type-options')).not.toEqual('nosniff');
  expect(response.headers.get('content-type')).not.toEqual('application/cbor');
  expect(await response.text()).toEqual('test response');
  expect(response.status).toEqual(200);
  expect(fetch.mock.calls).toHaveLength(2);
});

it.each([
  `https://${CANISTER_ID}.ic0.app/api/foo`,
  `https://ic0.app/api/${CANISTER_ID}/foo`,
  `https://icp-api.io/api/${CANISTER_ID}/foo`,
  `https://boundary.ic0.app/api/${CANISTER_ID}/foo`,
  `https://boundary.dfinity.network/api/${CANISTER_ID}/foo`,
])(
  'should set content-type: application/cbor and x-content-type-options: nosniff on ic calls to %s',
  async (url) => {
    fetch.mockResponse('test response');

    const requestProcessor = new RequestProcessor(new Request(url));
    const response = await requestProcessor.perform();

    expect(response.headers.get('x-content-type-options')).toEqual('nosniff');
    expect(response.headers.get('content-type')).toEqual('application/cbor');
    expect(await response.text()).toEqual('test response');
    expect(response.status).toEqual(200);
    expect(fetch.mock.calls).toHaveLength(1);
  }
);

it.each([
  {
    requestUrl: `https://boundary.ic0.app/api/${CANISTER_ID}/foo`,
    responseUrl: `https://ic0.app/api/${CANISTER_ID}/foo`,
  },
  {
    requestUrl: `https://mainnet.ic0.app/api/${CANISTER_ID}/foo`,
    responseUrl: `https://ic0.app/api/${CANISTER_ID}/foo`,
  },
])(
  'should set content-type: application/cbor and x-content-type-options: nosniff and strip legacy subdomains on ic calls to $requestUrl',
  async ({ requestUrl, responseUrl }) => {
    fetch.mockResponse('test response');

    const requestProcessor = new RequestProcessor(new Request(requestUrl));
    const response = await requestProcessor.perform();

    expect(response.headers.get('x-content-type-options')).toEqual('nosniff');
    expect(response.headers.get('content-type')).toEqual('application/cbor');
    expect(await response.text()).toEqual('test response');
    expect(response.status).toEqual(200);
    expect(fetch).toHaveBeenCalledWith(
      expect.objectContaining({
        url: responseUrl,
      })
    );
    expect(fetch.mock.calls).toHaveLength(1);
  }
);

it('should reject invalid certification (body hash mismatch)', async () => {
  jest.setSystemTime(TEST_DATA.query_call.certificate_time);
  const queryHttpPayload = createHttpQueryResponsePayload(
    'this payload does not match the certificate and must not be accepted',
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.query_call.certificate
  );
  mockFetchResponses(TEST_DATA.query_call.root_key, {
    query: queryHttpPayload,
  });

  const requestProcessor = new RequestProcessor(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(500);
  expect(await response.text()).toEqual('Response verification failed');
  expect(fetch.mock.calls).toHaveLength(2);
  expect(fetch.mock.calls[0][0]).toEqual('https://ic0.app/api/v2/status');
  expect(fetch.mock.calls[1][0]).toEqual(
    `https://ic0.app/api/v2/canister/${CANISTER_ID}/query`
  );
});

it('should reject invalid certification (invalid root key)', async () => {
  jest.setSystemTime(TEST_DATA.query_call.certificate_time);
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.query_call.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.query_call.certificate
  );
  mockFetchResponses(INVALID_ROOT_KEY, { query: queryHttpPayload });

  const requestProcessor = new RequestProcessor(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(500);
  expect(await response.text()).toEqual('Response verification failed');
  expect(fetch.mock.calls).toHaveLength(2);
  expect(fetch.mock.calls[0][0]).toEqual('https://ic0.app/api/v2/status');
  expect(fetch.mock.calls[1][0]).toEqual(
    `https://ic0.app/api/v2/canister/${CANISTER_ID}/query`
  );
});

it('should accept valid certification without callbacks', async () => {
  jest.setSystemTime(TEST_DATA.query_call.certificate_time);
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.query_call.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.query_call.certificate
  );
  mockFetchResponses(TEST_DATA.query_call.root_key, {
    query: queryHttpPayload,
  });

  const requestProcessor = new RequestProcessor(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(200);
  expect(await response.text()).toEqual(TEST_DATA.query_call.body);
  expect(fetch.mock.calls).toHaveLength(2);
  expect(fetch.mock.calls[0][0]).toEqual('https://ic0.app/api/v2/status');
  expect(fetch.mock.calls[1][0]).toEqual(
    `https://ic0.app/api/v2/canister/${CANISTER_ID}/query`
  );

  const [queryCall, req] = decodeContent<HttpRequest>(
    fetch.mock.calls[1],
    HttpRequestType
  );
  expect(queryCall.method_name).toEqual('http_request');
  expect(req.url).toEqual('/');
  expect(req.method).toEqual('GET');
});

it('should use hostnameCanisterIdMap to resolve canister id', async () => {
  jest.setSystemTime(TEST_DATA.query_call.certificate_time);
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.query_call.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.query_call.certificate
  );
  mockFetchResponses(TEST_DATA.query_call.root_key, {
    query: queryHttpPayload,
  });

  const requestProcessor = new RequestProcessor(
    new Request(`https://nns.ic0.app/`)
  );
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(200);
  expect(fetch.mock.calls).toHaveLength(2);
  expect(fetch.mock.calls[1][0]).toEqual(
    `https://ic0.app/api/v2/canister/${CANISTER_ID}/query`
  );
});

it('should send canister calls to https://ic0.app for any mapped domain in hostnameCanisterIdMap', async () => {
  jest.setSystemTime(
    TEST_DATA.query_call_with_dscvr_canister_id.certificate_time
  );
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.query_call_with_dscvr_canister_id.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.query_call_with_dscvr_canister_id.certificate
  );
  mockFetchResponses(TEST_DATA.query_call_with_dscvr_canister_id.root_key, {
    query: queryHttpPayload,
  });

  const requestProcessor = new RequestProcessor(
    new Request(`https://dscvr.one`)
  );
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(200);
  expect(fetch.mock.calls).toHaveLength(2);
  expect(fetch.mock.calls[1][0]).toEqual(
    'https://ic0.app/api/v2/canister/h5aet-waaaa-aaaab-qaamq-cai/query'
  );
});

it('should drop if-none-match request header', async () => {
  jest.setSystemTime(TEST_DATA.query_call.certificate_time);
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.query_call.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.query_call.certificate
  );
  mockFetchResponses(TEST_DATA.query_call.root_key, {
    query: queryHttpPayload,
    reqValidator: (req: HttpRequest) =>
      headerPresent(req, 'If-None-Match2') &&
      !headerPresent(req, 'If-None-Match'),
  });

  const request = new Request(`https://nns.ic0.app/`);
  request.headers.append('If-None-Match', '"some etag"');
  request.headers.append('If-None-Match2', '"some etag"');
  const requestProcessor = new RequestProcessor(request);
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(200);
  expect(fetch.mock.calls).toHaveLength(2);
  expect(fetch.mock.calls[1][0]).toEqual(
    `https://ic0.app/api/v2/canister/${CANISTER_ID}/query`
  );
});

it('should accept valid certification for index.html fallback', async () => {
  jest.setSystemTime(
    TEST_DATA.query_call_with_index_html_fallback.certificate_time
  );
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.query_call_with_index_html_fallback.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.query_call_with_index_html_fallback.certificate
  );
  mockFetchResponses(TEST_DATA.query_call_with_index_html_fallback.root_key, {
    query: queryHttpPayload,
  });

  const requestProcessor = new RequestProcessor(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(200);
});

it('should accept almost (but not yet) expired certificate', async () => {
  jest.setSystemTime(
    TEST_DATA.query_call.certificate_time + maxCertTimeOffsetMs
  );
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.query_call.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.query_call.certificate
  );
  mockFetchResponses(TEST_DATA.query_call.root_key, {
    query: queryHttpPayload,
  });

  const requestProcessor = new RequestProcessor(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(200);
});

it('should reject expired certificate', async () => {
  jest.setSystemTime(
    TEST_DATA.query_call.certificate_time + maxCertTimeOffsetMs + 1
  );
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.query_call.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.query_call.certificate
  );
  mockFetchResponses(TEST_DATA.query_call.root_key, {
    query: queryHttpPayload,
  });

  const requestProcessor = new RequestProcessor(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(500);
});

it('should reject certificate for other canister', async () => {
  jest.setSystemTime(
    TEST_DATA.query_call_with_dscvr_canister_id.certificate_time
  );
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.query_call_with_dscvr_canister_id.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.query_call_with_dscvr_canister_id.certificate
  );
  mockFetchResponses(TEST_DATA.query_call_with_dscvr_canister_id.root_key, {
    query: queryHttpPayload,
  });

  const requestProcessor = new RequestProcessor(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(500);
});

it('should reject certificate with invalid witness', async () => {
  jest.setSystemTime(
    TEST_DATA.query_call_with_invalid_witness.certificate_time
  );
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.query_call_with_invalid_witness.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.query_call_with_invalid_witness.certificate
  );
  mockFetchResponses(TEST_DATA.query_call_with_invalid_witness.root_key, {
    query: queryHttpPayload,
  });

  const requestProcessor = new RequestProcessor(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(500);
});

it('should reject certificate for different asset', async () => {
  jest.setSystemTime(TEST_DATA.query_call.certificate_time);
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.query_call.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.query_call.certificate
  );
  mockFetchResponses(TEST_DATA.query_call.root_key, {
    query: queryHttpPayload,
  });

  const requestProcessor = new RequestProcessor(
    new Request(`https://${CANISTER_ID}.ic0.app/not-found`)
  );
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(500);
});

it('should accept certificate time almost (but not quite) too far in the future', async () => {
  jest.setSystemTime(
    // we add 1 extra ms since we lose nanosecond precision due to timers being only available in ms
    TEST_DATA.query_call.certificate_time - maxCertTimeOffsetMs + 1
  );
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.query_call.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.query_call.certificate
  );
  mockFetchResponses(TEST_DATA.query_call.root_key, {
    query: queryHttpPayload,
  });

  const requestProcessor = new RequestProcessor(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(200);
});

it('should extract the boundary node request id and make it available', async () => {
  jest.setSystemTime(TEST_DATA.query_call.certificate_time);
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.query_call.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.query_call.certificate
  );
  mockFetchResponses(TEST_DATA.query_call.root_key, {
    query: queryHttpPayload,
  });

  const requestProcessor = new RequestProcessor(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(200);
  expect(requestProcessor.requestId).not.toBeUndefined();
  expect(requestProcessor.requestId?.length).toEqual(36); // uuidv4 length
});

it('should reject certificate with time too far in the future', async () => {
  jest.setSystemTime(
    TEST_DATA.query_call.certificate_time - maxCertTimeOffsetMs - 1
  );
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.query_call.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.query_call.certificate
  );
  mockFetchResponses(TEST_DATA.query_call.root_key, {
    query: queryHttpPayload,
  });

  const requestProcessor = new RequestProcessor(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(500);
});

it('should accept valid certification using callbacks with primitive tokens', async () => {
  jest.setSystemTime(TEST_DATA.query_call.certificate_time);
  const tokenType = IDL.Text;
  const [httpResponseType, CallbackResponseType] = getResponseTypes(tokenType);
  const queryHttpPayload = createHttpQueryResponsePayload(
    'hello',
    httpResponseType,
    TEST_DATA.query_call.certificate,
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
    TEST_DATA.query_call.root_key,
    { query: queryHttpPayload },
    { query: callbackPayload }
  );

  const requestProcessor = new RequestProcessor(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(200);
  expect(await response.text()).toEqual(TEST_DATA.query_call.body);
  expect(fetch.mock.calls).toHaveLength(3);
  expect(fetch.mock.calls[0][0]).toEqual('https://ic0.app/api/v2/status');
  fetch.mock.calls
    .slice(1, 3)
    .forEach((call) =>
      expect(call[0]).toEqual(
        `https://ic0.app/api/v2/canister/${CANISTER_ID}/query`
      )
    );

  const [queryCall, req] = decodeContent<HttpRequest>(
    fetch.mock.calls[1],
    HttpRequestType
  );
  expect(queryCall.method_name).toEqual('http_request');
  expect(req.url).toEqual('/');
  expect(req.method).toEqual('GET');

  const [callbackQuery, token] = decodeContent<string>(
    fetch.mock.calls[2],
    tokenType
  );
  expect(callbackQuery.method_name).toEqual('some_callback_method');
  expect(token).toEqual('text token');
});

it('should accept valid certification using multiple callbacks with structured tokens', async () => {
  jest.setSystemTime(TEST_DATA.query_call.certificate_time);
  const [httpResponseType, CallbackResponseType] = getResponseTypes(
    IDL.Record({
      counter: IDL.Nat,
      variant: IDL.Variant({ test1: IDL.Text, test2: IDL.Vec(IDL.Bool) }),
    })
  );
  const queryHttpPayload = createHttpQueryResponsePayload(
    'hel',
    httpResponseType,
    TEST_DATA.query_call.certificate,
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
    TEST_DATA.query_call.root_key,
    { query: queryHttpPayload },
    { query: callbackPayload1 },
    { query: callbackPayload2 }
  );

  const requestProcessor = new RequestProcessor(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(200);
  expect(await response.text()).toEqual(TEST_DATA.query_call.body);
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
  jest.setSystemTime(TEST_DATA.update_call.request_time); // required because request id is dependent on time
  jest.spyOn(global.Math, 'random').mockReturnValue(0.5); // required because request id is dependent on 'random' nonce
  jest.spyOn(CanisterResolver, 'setup').mockReturnValue(
    // required because CanisterResolver is used to resolve domains
    new Promise<CanisterResolver>((resolve) => {
      CanisterResolver.setup().then((canisterResolver) => {
        jest
          .spyOn(canisterResolver, 'getCurrentGateway')
          .mockResolvedValue(new URL('https://ic0.app'));
        jest
          .spyOn(canisterResolver, 'lookup')
          .mockResolvedValue(Principal.fromText(CANISTER_ID));
        resolve(canisterResolver);
      });
    })
  );
  mockFetchResponses(TEST_DATA.update_call.root_key, {
    query: createUpgradeQueryResponse(),
    update: createHttpUpdateResponsePayload(TEST_DATA.update_call.certificate),
  });

  const requestProcessor = new RequestProcessor(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(200);
  expect(await response.text()).toEqual('hello world!');
  expect(fetch.mock.calls).toHaveLength(4);
  expect(fetch.mock.calls[0][0]).toEqual('https://ic0.app/api/v2/status');
  // query, which prompts the update call
  expect(fetch.mock.calls[1][0]).toEqual(
    `https://ic0.app/api/v2/canister/${CANISTER_ID}/query`
  );

  const [queryCall, queryReq] = decodeContent<HttpRequest>(
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
  const [updateCall, updateReq] = decodeContent<HttpRequest>(
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

it('should reject redirects', async () => {
  jest.setSystemTime(TEST_DATA.query_call.certificate_time);
  const queryHttpPayload = createHttpRedirectResponsePayload(
    TEST_DATA.query_call.body,
    TEST_DATA.query_call.certificate
  );
  mockFetchResponses(TEST_DATA.query_call.root_key, {
    query: queryHttpPayload,
  });

  const requestProcessor = new RequestProcessor(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );
  const response = await requestProcessor.perform();

  expect(response.status).toEqual(500);
  expect(await response.text()).toEqual(
    'Response verification v1 does not allow redirects'
  );
});

function decodeContent<T>(
  [_, request]: [unknown, RequestInit | undefined],
  argType: IDL.Type
): [QueryRequest | CallRequest, T] {
  const decodedRequest = Agent.Cbor.decode<
    UnSigned<QueryRequest | CallRequest>
  >(request?.body as ArrayBuffer);
  // @ts-ignore
  const decodedArg = IDL.decode([argType], decodedRequest.content.arg)[0] as T;
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
  ...httpPayloads: {
    query: ArrayBuffer;
    update?: ArrayBuffer;
    reqValidator?: (req: HttpRequest) => boolean;
  }[]
) {
  // index to track how far we are into the (sequential) httpPayloads response array
  let fetchCounter = 0;
  fetch.doMock(async (req) => {
    const boundaryNodeResponseHeaders = new Headers();
    boundaryNodeResponseHeaders.set(
      HTTPHeaders.BoundaryNodeRequestId,
      uuidv4()
    );

    // status is just used to fetch the rootKey and is independent of the response payloads
    // -> no need to do anything with the fetchCounter
    if (req.url.endsWith('status')) {
      return Promise.resolve({
        status: 200,
        headers: boundaryNodeResponseHeaders,
        body: fetchRootKeyResponse(rootKey),
      });
    }

    // if a predicate for the request was supplied: decode request and validate
    if (httpPayloads[fetchCounter].reqValidator) {
      const body = await req.arrayBuffer();
      const cborDecoded: { content: { arg: ArrayBuffer } } =
        Agent.Cbor.decode(body);
      const request = IDL.decode([HttpRequestType], cborDecoded.content.arg)[0];
      if (
        !httpPayloads[fetchCounter].reqValidator?.(
          request as unknown as HttpRequest
        )
      ) {
        return Promise.reject('request rejected by validator');
      }
    }

    if (req.url.endsWith('query')) {
      const promise = Promise.resolve({
        status: 200,
        headers: boundaryNodeResponseHeaders,
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
        headers: boundaryNodeResponseHeaders,
        body: httpPayloads[fetchCounter].update,
      });
      // update response has been fetched, go to the next response payload
      fetchCounter++;
      return promise;
    }
    return Promise.reject(`Request with URL ${req.url} has not been mocked`);
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
  certificate = '',
  streamingStrategy: StreamingStrategy[] = [],
  upgrade = false
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

function createHttpRedirectResponsePayload(body: string, certificate = '') {
  const response = {
    status_code: 302,
    headers: [
      ['Location', 'https://catphish.cg'],
      ['IC-Certificate', certificate],
    ],
    body: Array.from(new TextEncoder().encode(body)),
    streaming_strategy: [],
    upgrade: [],
  };
  const candidResponse: QueryResponse = {
    status: QueryResponseStatus.Replied,
    reply: {
      arg: IDL.encode([getResponseTypes(IDL.Text)[0]], [response]),
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

function headerPresent(req: HttpRequest, headerName: string) {
  const result = req.headers.find(
    ([key, _]: [string, string]) =>
      key.toLowerCase() === headerName.toLowerCase()
  );
  return result !== undefined;
}
