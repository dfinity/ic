import { Principal } from '@dfinity/principal';
import {
  HttpRequest,
  HttpResponse,
} from '../../http-interface/canister_http_interface_types';
import { queryCallHandler } from './query-call';
import { HttpAgent } from '@dfinity/agent';

const verifyRequestResponsePairMock = jest.fn();
jest.mock('@dfinity/response-verification', () => ({
  ...jest.requireActual('@dfinity/response-verification'),
  verifyRequestResponsePair: (...args: any[]) =>
    verifyRequestResponsePairMock(args),
}));

const streamBodyMock = jest.fn();
jest.mock('../response', () => ({
  ...jest.requireActual('../response'),
  streamBody: (...args: any[]) => streamBodyMock(args),
}));

describe('queryCall', () => {
  const agentMock: jest.Mocked<HttpAgent> = {
    rootKey: new Uint8Array(0),
  } as any;
  const httpRequestMock: HttpRequest = {
    body: new Uint8Array(),
    certificate_version: [1],
    headers: [],
    method: 'GET',
    url: '',
  };
  const httpResponseMock: HttpResponse = {
    body: new Uint8Array(),
    headers: [],
    status_code: 200,
    streaming_strategy: [],
    upgrade: [],
  };
  const canisterId = Principal.fromUint8Array(new Uint8Array([0]));

  beforeEach(() => {
    jest.resetAllMocks();
  });

  it('should return original headers and status code', async () => {
    const httpRequest = {
      ...httpRequestMock,
    };
    const httpResponse: HttpResponse = {
      ...httpResponseMock,
      headers: [['Content-Type', 'application/javascript']],
    };

    verifyRequestResponsePairMock.mockReturnValue({
      passed: true,
      verificationVersion: 1,
      response: {
        statusCode: undefined,
        headers: [],
      },
    });

    const result = await queryCallHandler(
      agentMock,
      httpRequest,
      httpResponse,
      canisterId
    );

    expect(result.response.status).toEqual(httpResponse.status_code);
    expect(result.response.headers).toEqual(new Headers(httpResponse.headers));
    expect(result.certifiedHeaders).toEqual(new Headers());
  });
});
