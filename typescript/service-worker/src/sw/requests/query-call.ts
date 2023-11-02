import { HttpAgent } from '@dfinity/agent';
import {
  decodeBody,
  filterResponseHeaders,
  responseVerification,
  streamBody,
} from '../response';
import {
  VerifiedResponse,
  responseVerificationFailedResponse,
} from './typings';
import {
  HttpRequest,
  HttpResponse,
} from '../../http-interface/canister_http_interface_types';
import { Principal } from '@dfinity/principal';
import {
  getMinVerificationVersion,
  ResponseVerificationError,
} from '@dfinity/response-verification';

export async function queryCallHandler(
  agent: HttpAgent,
  httpRequest: HttpRequest,
  httpResponse: HttpResponse,
  canisterId: Principal
): Promise<VerifiedResponse> {
  try {
    const minAllowedVerificationVersion = getMinVerificationVersion();
    const streamedBody = await streamBody(agent, httpResponse, canisterId);

    const verificationResult = responseVerification(
      httpRequest,
      {
        ...httpResponse,
        body: streamedBody,
      },
      minAllowedVerificationVersion,
      canisterId,
      agent.rootKey
    );

    if (verificationResult.verificationVersion < 2) {
      if (httpResponse.status_code >= 300 && httpResponse.status_code < 400) {
        return {
          response: new Response(
            'Response verification v1 does not allow redirects',
            {
              status: 500,
              statusText: 'Response verification v1 does not allow redirects',
            }
          ),
          certifiedHeaders: new Headers(),
        };
      }
    }

    const decodedResponseBody = decodeBody(streamedBody, httpResponse.headers);
    const responseHeaders = filterResponseHeaders(httpResponse.headers);

    return {
      response: new Response(decodedResponseBody, {
        status: httpResponse.status_code,
        headers: responseHeaders,
      }),
      certifiedHeaders: new Headers(verificationResult.response?.headers),
    };
  } catch (error) {
    if (error instanceof ResponseVerificationError) {
      return {
        response: new Response('Response verification failed', {
          status: responseVerificationFailedResponse.status,
          statusText: responseVerificationFailedResponse.statusText,
        }),
        certifiedHeaders: new Headers(),
      };
    }

    throw error;
  }
}
