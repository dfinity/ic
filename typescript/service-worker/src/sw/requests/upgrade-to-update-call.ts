import { ActorSubclass, HttpAgent } from '@dfinity/agent';
import {
  HttpRequest,
  HttpResponse,
  _SERVICE,
} from '../../http-interface/canister_http_interface_types';
import { Principal } from '@dfinity/principal';
import { VerifiedResponse } from './typings';
import { decodeBody, filterResponseHeaders, streamBody } from '../response';

export function shouldUpgradeToUpdateCall(response: HttpResponse): boolean {
  return response.upgrade.length === 1 && response.upgrade[0];
}

export async function updateCallHandler(
  agent: HttpAgent,
  actor: ActorSubclass<_SERVICE>,
  canisterId: Principal,
  httpRequest: HttpRequest
): Promise<VerifiedResponse> {
  const httpResponse = await actor.http_request_update({
    url: httpRequest.url,
    method: httpRequest.method,
    body: httpRequest.body,
    headers: httpRequest.headers,
  });
  const streamedBody = await streamBody(agent, httpResponse, canisterId);
  const decodedBody = decodeBody(streamedBody, httpResponse.headers);
  const filteredResponseHeaders = filterResponseHeaders(httpResponse.headers);

  return {
    response: new Response(decodedBody, {
      status: httpResponse.status_code,
      headers: filteredResponseHeaders,
    }),
    // all headers are considered certified for update calls
    certifiedHeaders: new Headers(httpResponse.headers),
  };
}
