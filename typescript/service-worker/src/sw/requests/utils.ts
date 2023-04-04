import { Actor, ActorSubclass, HttpAgent, concat } from '@dfinity/agent';
import { Principal } from '@dfinity/principal';
import { inflate, ungzip } from 'pako';
import { idlFactory } from '../../http-interface/canister_http_interface';
import {
  HttpRequest,
  _SERVICE,
} from '../../http-interface/canister_http_interface_types';
import { streamContent } from '../streaming';
import { NotAllowedRequestRedirectError } from './errors';
import { FetchAssetOptions, FetchAssetResult, HTTPHeaders } from './typings';

export const shouldFetchRootKey = Boolean(process.env.FORCE_FETCH_ROOT_KEY);
export const isMainNet = !shouldFetchRootKey;

export async function createAgentAndActor(
  gatewayUrl: URL,
  canisterId: Principal,
  fetchRootKey: boolean
): Promise<[HttpAgent, ActorSubclass<_SERVICE>]> {
  const agent = new HttpAgent({ host: gatewayUrl.toString() });
  if (fetchRootKey) {
    await agent.fetchRootKey();
  }
  const actor = Actor.createActor<_SERVICE>(idlFactory, {
    agent,
    canisterId: canisterId,
  });
  return [agent, actor];
}

/**
 * Decode a body (ie. deflate or gunzip it) based on its content-encoding.
 * @param body The body to decode.
 * @param encoding Its content-encoding associated header.
 */
export function decodeBody(body: Uint8Array, encoding: string): Uint8Array {
  switch (encoding) {
    case 'identity':
    case '':
      return body;
    case 'gzip':
      return ungzip(body);
    case 'deflate':
      return inflate(body);
    default:
      throw new Error(`Unsupported encoding: "${encoding}"`);
  }
}

/**
 * Request objects cannot be mutated, so we have to clone them and
 * object spread does not work so we have to manually deconstruct the request.
 * If we create a new Request using the original one then the duplex property is not copied over, so we have to set it manually.
 * The duplex property also does not exist in the Typescript definitions so we need to cast to unknown.
 * Safari does not support creating a Request with a readable stream as a body, so we have to read the stream and set the body
 * as the UIntArray that is read.
 */
export async function updateRequestApiGateway(
  originalRequest: Request,
  gatewayUrl: URL
): Promise<Request> {
  const url = new URL(originalRequest.url);

  const {
    cache,
    credentials,
    headers,
    integrity,
    keepalive,
    method,
    mode,
    redirect,
    referrer,
    referrerPolicy,
    signal,
  } = originalRequest;

  const requestInit = {
    cache,
    credentials,
    headers,
    integrity,
    keepalive,
    method,
    mode,
    redirect,
    referrer,
    referrerPolicy,
    signal,
    duplex: 'half',
  } as RequestInit;

  if (!['HEAD', 'GET'].includes(method)) {
    requestInit['body'] = await originalRequest.arrayBuffer();
  }

  return new Request(
    `${url.protocol}//${gatewayUrl.hostname}${url.pathname}`,
    requestInit
  );
}

/**
 * Fetch a requested asset and handles upgrade calls when required.
 *
 * @param canisterId Canister holding the asset
 * @returns Fetched asset
 */
export const fetchAsset = async ({
  actor,
  agent,
  canisterId,
  request,
  certificateVersion,
}: FetchAssetOptions): Promise<FetchAssetResult> => {
  try {
    const url = new URL(request.url);

    const requestHeaders: [string, string][] = [['Host', url.hostname]];
    request.headers.forEach((value, key) => {
      if (key.toLowerCase() === 'if-none-match') {
        // Drop the if-none-match header because we do not want a "304 not modified" response back.
        // See TT-30.
        return;
      }
      requestHeaders.push([key, value]);
    });

    // If the accept encoding isn't given, add it because we want to save bandwidth.
    if (!request.headers.has('Accept-Encoding')) {
      requestHeaders.push(['Accept-Encoding', 'gzip, deflate, identity']);
    }

    const httpRequest: HttpRequest = {
      method: request.method,
      url: url.pathname + url.search,
      headers: requestHeaders,
      body: new Uint8Array(await request.arrayBuffer()),
      certificate_version: [BigInt(certificateVersion)],
    };

    let httpResponse = await actor.http_request(httpRequest);
    const upgradeCall =
      httpResponse.upgrade.length === 1 && httpResponse.upgrade[0];
    const bodyEncoding =
      httpResponse.headers
        .filter(([key]) => key.toLowerCase() === HTTPHeaders.ContentEncoding)
        ?.map((header) => header[1].trim())
        .pop() ?? '';

    if (upgradeCall) {
      const { certificate_version, ...httpUpdateRequest } = httpRequest;

      // repeat the request as an update call
      httpResponse = await actor.http_request_update(httpUpdateRequest);
    }

    // Redirects are blocked for query calls only: if this response has the upgrade to update call flag set,
    // the update call is allowed to redirect. This is safe because the response (including the headers) will go through consensus.
    if (
      !upgradeCall &&
      httpResponse.status_code >= 300 &&
      httpResponse.status_code < 400
    ) {
      throw new NotAllowedRequestRedirectError();
    }

    // if we do streaming, body contains the first chunk
    let buffer = new ArrayBuffer(0);
    buffer = concat(buffer, httpResponse.body);
    if (httpResponse.streaming_strategy.length !== 0) {
      buffer = concat(
        buffer,
        await streamContent(
          agent,
          canisterId,
          httpResponse.streaming_strategy[0]
        )
      );
    }
    const responseBody = new Uint8Array(buffer);

    return {
      ok: true,
      data: {
        updateCall: upgradeCall,
        request: {
          body: httpRequest.body,
          method: httpRequest.method,
          url: httpRequest.url,
          headers: httpRequest.headers.map(([key, value]) => [key, value]),
        },
        response: {
          encoding: bodyEncoding,
          body: responseBody,
          statusCode: httpResponse.status_code,
          headers: httpResponse.headers.map(([key, value]) => [key, value]),
        },
      },
    };
  } catch (e) {
    return {
      ok: false,
      error: e,
    };
  }
};
