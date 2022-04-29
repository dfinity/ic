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
const CERT_MAX_TIME_OFFSET = 300_000; // 5 Minutes
const INVALID_ROOT_KEY =
  '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c050302010361008fcd89d93d038059ceec489f42bbb93fb873a890e9c748dd864741198e822dd24dbb984f7a735bcc75b6abb5d42832ea153c7f7a01e3f9b03b9a67ae4e4dfb00901cb20139ac5f787fae28cc7da755cf2064702220aa7c92282e17b9935169ae';
const TEST_DATA = {
  queryData: {
    root_key:
      '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100a6a3c5c70ad96a6c3f987f747312a2232dcec6ced0daf07d6a6b63a70199149f647430534c3b33023cc6d096bef178b3184637ecbe2e6ae148c1797bf19245d634aa4b33264ba66357294b66f49e1f0c6eb9c0ac5147dbddba07068bfaf18fc7',
    certificate:
      'certificate=:2dn3omR0cmVlgwGDAkhjYW5pc3RlcoMCSgAAAAAAAAAHAQGDAk5jZXJ0aWZpZWRfZGF0YYIDWCBb1aIcc2xftgJaN6877pAf6qk3k8NHiyRKu4Hn3ft+/4MCRHRpbWWCA0mnm/H8zaOC9RZpc2lnbmF0dXJlWDCSPmVbeBM5Xg6nxdmheXDezSOY111ikBHCMf/OV9aF50EAPZKOSQq9RYRwdoTwfJo=:, tree=:2dn3gwJLaHR0cF9hc3NldHODAkEvggNYIHUJ5b2gx2LSusf5DXWLWyJj+gHMvFQqtePfFjvgjmyp:',
    body: 'hello world!',
    certificate_time: 1651142233000,
  },
  updateData: {
    root_key:
      '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c050302010361008096df0d1ffb96ca6fff319d4e1dd4b8339f3019d7e9848a9d315a6468df1e51dc6989efdcdcb90f33bae821281a90781202aa623dd38eb9cfae16424e7c4764e0ad3362b549b7fc4a5d8bf1f326df0171e12c68814743f8371459b9680fde64',
    certificate:
      'd9d9f7a2647472656583024e726571756573745f7374617475738302582007bf53acde2967b1ddc8f06814fb8a0d037e5ef19ba597e92b9d1febe726698983018302457265706c79820358354449444c046d7b6c02007101716d016c03a2f5ed880400c6a4a19806029aa1b2f90c7a01030c68656c6c6f20776f726c642100c8008302467374617475738203477265706c696564697369676e61747572655830971e62f35e9c288ea9b4c446b8febfc2bf040172a539753bed5349ed671bda6d80b4c7ae641ce9df0fc779deb61511e6',
    request_time: 1650551764352,
  },
  wrongCanisterId: {
    root_key:
      '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c0503020103610086d6f09aa8ba5a3fe67dd3fcba6b75266c2f96961fb1d35f7f4f34a6af5e99cc01386e703fa517e16f4006aef5513f460a809cfdadf60a32ac6930550d9473d6e792786253f6fd6b0d08189482ce9a07cc6f68821bc655c59ce24a21174e393f',
    certificate:
      'certificate=:2dn3omR0cmVlgwGDAkhjYW5pc3RlcoMCSgAAAAAAMAAZAQGDAk5jZXJ0aWZpZWRfZGF0YYIDWCBb1aIcc2xftgJaN6877pAf6qk3k8NHiyRKu4Hn3ft+/4MCRHRpbWWCA0mnm/H8zaOC9RZpc2lnbmF0dXJlWDCYu3oVZ8ckpUkz715Pcf4TtLwRVF42BBg9BcC2wj2g3BH9cdIk6D6PoUVWiVXkL4I=:, tree=:2dn3gwJLaHR0cF9hc3NldHODAkEvggNYIHUJ5b2gx2LSusf5DXWLWyJj+gHMvFQqtePfFjvgjmyp:',
    body: 'hello world!',
    certificate_time: 1651142233000,
  },
  invalidWitness: {
    root_key:
      '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100974dbc96e64a3651e2ddd5ee083834777a6cee28854eb125017fc3da329e1b651cad89b01f28ef453f10ada8c8c915d0065daa5330ef09500e0eee24483a6fe4ccbf1fa6e4b2d15f4211304a812811a03289f87eb46c3d9868f37cb36846aed5',
    certificate:
      'certificate=:2dn3omR0cmVlgwGDAkhjYW5pc3RlcoMCSgAAAAAAAAAHAQGDAk5jZXJ0aWZpZWRfZGF0YYIDWCD9vaIGJzGndcAVzeIv5atRB2VKT+F1SLMwfmidEXTaP4MCRHRpbWWCA0mnm/H8zaOC9RZpc2lnbmF0dXJlWDCYtUjT5AcZyvqnsqETmCL8X+ndP4h7URgjr6YJshGOraoPOBSiaQqk0TUDxoReBWk=:, tree=:2dn3gwJLaHR0cF9hc3NldHODAkEvggNYIHUJ5b2gx2LSusf5DXWLWyJj+gHMvFQqtePfFjvgjmyp:',
    body: 'hello world!',
    certificate_time: 1651142233000,
  },
  fallbackToIndexHtml: {
    root_key:
      '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c0503020103610095864d503c4d238b03fe480ddd2ebde6b29bb911dd2d394329c4bd17f868d7d2e260848b47cd4cd1b5f5d6ea691ed906103e5c3226e7ed3c7de0a0dcf8efa6adab96a5ce07757427e9de7be270177df67a2761f3e0b821adf97ae89747e0f6c2',
    certificate:
      'certificate=:2dn3omR0cmVlgwGDAkhjYW5pc3RlcoMCSgAAAAAAAAAHAQGDAk5jZXJ0aWZpZWRfZGF0YYIDWCCTYiq9Z2R97ckZGkWaapIku/HPaP1nllHaYnSbPIr8JoMCRHRpbWWCA0mnm/H8zaOC9RZpc2lnbmF0dXJlWDCFYbCbcUPBbVVASJfnqklL6jR4pdW/hYFVMs5SRG5SqoUr9ZCIyaOfQ8OKIL8r1PQ=:, tree=:2dn3gwJLaHR0cF9hc3NldHODAksvaW5kZXguaHRtbIIDWCB1CeW9oMdi0rrH+Q11i1siY/oBzLxUKrXj3xY74I5sqQ==:',
    body: 'hello world!',
    certificate_time: 1651142233000,
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

it('should reject invalid certification (body hash mismatch)', async () => {
  jest.setSystemTime(TEST_DATA.queryData.certificate_time);
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

it('should reject invalid certification (invalid root key)', async () => {
  jest.setSystemTime(TEST_DATA.queryData.certificate_time);
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.queryData.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.queryData.certificate
  );
  mockFetchResponses(INVALID_ROOT_KEY, { query: queryHttpPayload });

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
  jest.setSystemTime(TEST_DATA.queryData.certificate_time);
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

it('should accept valid certification for index.html fallback', async () => {
  jest.setSystemTime(TEST_DATA.fallbackToIndexHtml.certificate_time);
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.fallbackToIndexHtml.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.fallbackToIndexHtml.certificate
  );
  mockFetchResponses(TEST_DATA.fallbackToIndexHtml.root_key, {
    query: queryHttpPayload,
  });

  const response = await handleRequest(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );

  expect(response.status).toEqual(200);
});

it('should accept almost (but not yet) expired certificate', async () => {
  jest.setSystemTime(
    TEST_DATA.queryData.certificate_time + CERT_MAX_TIME_OFFSET
  );
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
});

it('should reject expired certificate', async () => {
  jest.setSystemTime(
    TEST_DATA.queryData.certificate_time + CERT_MAX_TIME_OFFSET + 1
  );
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.queryData.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.queryData.certificate
  );
  mockFetchResponses(TEST_DATA.queryData.root_key, { query: queryHttpPayload });

  const response = await handleRequest(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );

  expect(response.status).toEqual(500);
});

it('should reject certificate for other canister', async () => {
  jest.setSystemTime(TEST_DATA.wrongCanisterId.certificate_time);
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.wrongCanisterId.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.wrongCanisterId.certificate
  );
  mockFetchResponses(TEST_DATA.wrongCanisterId.root_key, {
    query: queryHttpPayload,
  });

  const response = await handleRequest(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );

  expect(response.status).toEqual(500);
});

it('should reject certificate with invalid witness', async () => {
  jest.setSystemTime(TEST_DATA.invalidWitness.certificate_time);
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.invalidWitness.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.invalidWitness.certificate
  );
  mockFetchResponses(TEST_DATA.invalidWitness.root_key, {
    query: queryHttpPayload,
  });

  const response = await handleRequest(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );

  expect(response.status).toEqual(500);
});

it('should reject certificate for different asset', async () => {
  jest.setSystemTime(TEST_DATA.queryData.certificate_time);
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.queryData.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.queryData.certificate
  );
  mockFetchResponses(TEST_DATA.queryData.root_key, {
    query: queryHttpPayload,
  });

  const response = await handleRequest(
    new Request(`https://${CANISTER_ID}.ic0.app/not-found`)
  );

  expect(response.status).toEqual(500);
});

it('should accept certificate time almost (but not quite) too far in the future', async () => {
  jest.setSystemTime(
    TEST_DATA.queryData.certificate_time - CERT_MAX_TIME_OFFSET
  );
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
});

it('should reject certificate with time too far in the future', async () => {
  jest.setSystemTime(
    TEST_DATA.queryData.certificate_time - CERT_MAX_TIME_OFFSET - 1
  );
  const queryHttpPayload = createHttpQueryResponsePayload(
    TEST_DATA.queryData.body,
    getResponseTypes(IDL.Text)[0],
    TEST_DATA.queryData.certificate
  );
  mockFetchResponses(TEST_DATA.queryData.root_key, { query: queryHttpPayload });

  const response = await handleRequest(
    new Request(`https://${CANISTER_ID}.ic0.app/`)
  );

  expect(response.status).toEqual(500);
});

it('should accept valid certification using callbacks with primitive tokens', async () => {
  jest.setSystemTime(TEST_DATA.queryData.certificate_time);
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
  jest.setSystemTime(TEST_DATA.queryData.certificate_time);
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
  jest.setSystemTime(TEST_DATA.updateData.request_time); // required because request id is dependent on time
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
