import { Actor, ActorSubclass, HttpAgent } from '@dfinity/agent';
import { Principal } from '@dfinity/principal';
import { inflate, ungzip } from 'pako';
import { idlFactory } from '../../http-interface/canister_http_interface';
import { _SERVICE } from '../../http-interface/canister_http_interface_types';

export const shouldFetchRootKey = Boolean(process.env.FORCE_FETCH_ROOT_KEY);

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

const legacyGateways = new Set([
  'boundary.dfinity.network',
  'boundary.ic0.app',
]);

/**
 * Removes legacy sub domains from the URL of the request.
 * Request objects cannot be mutated, so we have to clone them and
 * object spread does not work so we have to manually deconstruct the request.
 * If we create a new Request using the original one then the duplex property is not copied over, so we have to set it manually.
 * The duplex property also does not exist in the Typescript definitions so we need to cast to unknown.
 * Safari does not support creating a Request with a readable stream as a body, so we have to read the stream and set the body
 * as the UIntArray that is read.
 */
export async function removeLegacySubDomains(
  originalRequest: Request,
  gatewayUrl: URL
): Promise<Request> {
  const url = new URL(originalRequest.url);

  if (legacyGateways.has(url.hostname)) {
    console.warn(
      `${url.hostname} refers to a legacy, deprecated sub domain. Please migrate to the latest version of @dfinity/agent-js and remove any subdomains from your 'host' configuration when creating the agent.`
    );
  }

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
