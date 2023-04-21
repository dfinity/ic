import { HttpAgent } from '@dfinity/agent';
import {
  decodeBody,
  filterResponseHeaders,
  responseVerification,
  streamBody,
} from '../response';
import { VerifiedResponse } from './typings';
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

    const certificationResult = responseVerification(
      httpRequest,
      {
        ...httpResponse,
        body: streamedBody,
      },
      minAllowedVerificationVersion,
      canisterId,
      agent.rootKey
    );

    if (!certificationResult.passed || !certificationResult.response) {
      return {
        response: new Response('Body does not pass verification', {
          status: 500,
        }),
        certifiedHeaders: new Headers(),
      };
    }

    if (certificationResult.verificationVersion < 2) {
      if (httpResponse.status_code >= 300 && httpResponse.status_code < 400) {
        return {
          response: new Response(
            'Due to security reasons redirects are blocked on the IC until further notice!',
            {
              status: 500,
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
      certifiedHeaders: new Headers(certificationResult.response.headers),
    };
  } catch (error) {
    if (error instanceof ResponseVerificationError) {
      return {
        response: new Response('Body does not pass verification', {
          status: 500,
        }),
        certifiedHeaders: new Headers(),
      };
    }

    throw error;
  }
}
