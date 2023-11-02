import {
  Actor,
  ActorMethodMappedWithHttpDetails,
  ActorSubclass,
  HttpAgent,
  HttpDetailsResponse,
} from '@dfinity/agent';
import { Principal } from '@dfinity/principal';
import initResponseVerification, {
  InitOutput,
  getMaxVerificationVersion,
} from '@dfinity/response-verification';
import responseVerificationWasmModule from '@dfinity/response-verification/dist/web/web_bg.wasm';
import { idlFactory } from '../../http-interface/canister_http_interface';
import {
  HttpRequest,
  _SERVICE,
} from '../../http-interface/canister_http_interface_types';
import { HTTPHeaders } from './typings';

declare const self: ServiceWorkerGlobalScope;

export const shouldFetchRootKey = Boolean(process.env.FORCE_FETCH_ROOT_KEY);
export const isMainNet = !shouldFetchRootKey;

export async function createAgentAndActor(
  gatewayUrl: URL,
  canisterId: Principal,
  fetchRootKey: boolean
): Promise<
  [HttpAgent, ActorSubclass<ActorMethodMappedWithHttpDetails<_SERVICE>>]
> {
  const agent = new HttpAgent({ host: gatewayUrl.toString() });
  if (fetchRootKey) {
    await agent.fetchRootKey();
  }
  const actor = Actor.createActorWithHttpDetails<_SERVICE>(idlFactory, {
    agent,
    canisterId: canisterId,
  });

  return [agent, actor];
}

export async function uninstallServiceWorker(): Promise<void> {
  await self.registration.unregister();
}

export async function reloadServiceWorkerClients(): Promise<void> {
  self.clients.matchAll({ type: 'window' }).then(function (clients) {
    clients.forEach((client) => {
      client.navigate(client.url);
    });
  });
}

export function getBoundaryNodeRequestId(
  httpDetails: HttpDetailsResponse
): string | undefined {
  for (const [key, value] of httpDetails.headers) {
    if (key.toLowerCase() === HTTPHeaders.BoundaryNodeRequestId) {
      return value;
    }
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

export async function createHttpRequest(
  request: Request
): Promise<HttpRequest> {
  const certificateVersion = getMaxVerificationVersion();
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

  return {
    method: request.method,
    url: url.pathname + url.search,
    headers: requestHeaders,
    body: new Uint8Array(await request.arrayBuffer()),
    certificate_version: [certificateVersion],
  };
}

let responseVerificationWasm: InitOutput | null = null;
let loadingResponseVerificationWasm: Promise<InitOutput> | null = null;

export const loadResponseVerification = async (): Promise<void> => {
  if (!responseVerificationWasm && !loadingResponseVerificationWasm) {
    loadingResponseVerificationWasm = initResponseVerification(
      responseVerificationWasmModule
    );
    responseVerificationWasm = await loadingResponseVerificationWasm;
    loadingResponseVerificationWasm = null;
    return;
  }

  if (loadingResponseVerificationWasm) {
    await loadingResponseVerificationWasm;
  }
};
