import { Principal } from '@dfinity/principal';
import {
  getMaxVerificationVersion,
  getMinVerificationVersion,
  verifyRequestResponsePair,
} from '@dfinity/response-verification';
import { ResponseCache } from '../cache';
import { CanisterResolver } from '../domains';
import { isRawDomain } from '../domains/utils';
import { RequestMapper } from './mapper';
import { VerifiedResponse, cacheHeaders, maxCertTimeOffsetNs } from './typings';
import {
  createAgentAndActor,
  decodeBody,
  fetchAsset,
  shouldFetchRootKey,
  updateRequestApiGateway,
} from './utils';

export class RequestProcessor {
  private readonly url: URL;

  constructor(private readonly request: Request) {
    this.url = new URL(this.request.url);
  }

  /**
   * Executes the current request performing the network request when necessary.
   * @returns The response to send to the browser.
   * @throws If an internal error happens.
   */
  async perform(): Promise<Response> {
    const responseCache = await ResponseCache.setup();
    const cachedResponse = await responseCache.match(this.request);

    if (cachedResponse) {
      return cachedResponse;
    }

    // maybe check if the response should be denied
    if (this.url.pathname.startsWith('/_/')) {
      return this.denyRequestHandler();
    }

    const canisterResolver = await CanisterResolver.setup();
    const gatewayUrl = await canisterResolver.getCurrentGateway();

    // maybe check if is an api call
    if (canisterResolver.isAPICall(this.request, gatewayUrl)) {
      return await this.apiRequestHandler(gatewayUrl);
    }

    const canisterId = await canisterResolver.lookupFromHttpRequest(
      this.request
    );

    // maybe check if its an asset
    if (canisterId) {
      const assetResponse = await this.assetRequestHandler(
        gatewayUrl,
        canisterId
      );

      // assets are cached depending of the available cache headers
      await responseCache.save({
        request: this.request,
        response: assetResponse.response,
        certifiedResponseHeaders: assetResponse.certifiedHeaders,
      });

      return assetResponse.response;
    }

    // make sure that we don't make a request against the service worker's origin,
    // else we'll end up in a service worker loading loop
    if (this.url.hostname === self.location.hostname) {
      console.error(
        `URL ${JSON.stringify(
          this.url.toString()
        )} did not resolve to a canister ID.`
      );
      return new Response('Could not find the canister ID.', { status: 404 });
    }

    return await this.directRequestHandler();
  }

  /**
   * We refuse any request to /_/*
   */
  private denyRequestHandler(): Response {
    return new Response(null, { status: 404 });
  }

  /**
   * We forward all requests to /api/ to the gateway, as is.
   */
  private async apiRequestHandler(gatewayUrl: URL): Promise<Response> {
    const cleanedRequest = await updateRequestApiGateway(
      this.request,
      gatewayUrl
    );
    const response = await fetch(cleanedRequest);
    // force the content-type to be cbor as /api/ is exclusively used for canister calls
    const sanitizedHeaders = new Headers(response.headers);
    sanitizedHeaders.set('X-Content-Type-Options', 'nosniff');
    sanitizedHeaders.set('Content-Type', 'application/cbor');
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: sanitizedHeaders,
    });
  }

  /**
   * We perform asset certification for all ic asset requests.
   */
  private async assetRequestHandler(
    gatewayUrl: URL,
    canisterId: Principal
  ): Promise<VerifiedResponse> {
    try {
      const minAllowedVerificationVersion = getMinVerificationVersion();
      const desiredVerificationVersion = getMaxVerificationVersion();

      const [agent, actor] = await createAgentAndActor(
        gatewayUrl,
        canisterId,
        shouldFetchRootKey
      );
      const result = await fetchAsset({
        agent,
        actor,
        request: this.request,
        canisterId,
        certificateVersion: desiredVerificationVersion,
      });

      if (!result.ok) {
        let errMessage = 'Failed to fetch response';
        if (result.error instanceof Error) {
          console.error(result.error);
          errMessage = result.error.message;
        }

        return {
          response: new Response(errMessage, { status: 500 }),
          certifiedHeaders: new Headers(),
        };
      }

      const assetFetchResult = result.data;
      const responseHeaders = new Headers();
      for (const [key, value] of assetFetchResult.response.headers) {
        const headerKey = key.trim().toLowerCase();
        if (cacheHeaders.includes(headerKey)) {
          // cache headers are remove since those are handled by
          // cache storage within the service worker. If returned they would
          // reach https://www.chromium.org/blink/ in the cache of chromium which
          // could cache those entries in memory and those requests can't be
          // intercepted by the service worker
          continue;
        }

        responseHeaders.append(key, value);
      }

      // update calls are certified since they've went through consensus
      if (assetFetchResult.updateCall) {
        const decodedResponseBody = decodeBody(
          assetFetchResult.response.body,
          assetFetchResult.response.encoding
        );

        return {
          response: new Response(decodedResponseBody, {
            status: assetFetchResult.response.statusCode,
            headers: responseHeaders,
          }),
          certifiedHeaders: responseHeaders,
        };
      }

      const currentTimeNs = BigInt.asUintN(64, BigInt(Date.now() * 1_000_000)); // from ms to nanoseconds
      const assetCertification = verifyRequestResponsePair(
        {
          headers: assetFetchResult.request.headers,
          method: assetFetchResult.request.method,
          url: assetFetchResult.request.url,
        },
        {
          statusCode: assetFetchResult.response.statusCode,
          body: assetFetchResult.response.body,
          headers: assetFetchResult.response.headers,
        },
        canisterId.toUint8Array(),
        currentTimeNs,
        maxCertTimeOffsetNs,
        new Uint8Array(agent.rootKey),
        minAllowedVerificationVersion
      );

      if (assetCertification.passed && assetCertification.response) {
        const decodedResponseBody = decodeBody(
          assetFetchResult.response.body,
          assetFetchResult.response.encoding
        );
        const certifiedResponseHeaders =
          RequestMapper.fromResponseVerificationHeaders(
            assetCertification.response.headers
          );

        return {
          response: new Response(decodedResponseBody, {
            status: assetCertification.response.statusCode,
            headers: responseHeaders,
          }),
          certifiedHeaders: certifiedResponseHeaders,
        };
      }
    } catch (err) {
      console.error(String(err));
    }

    return {
      response: new Response('Body does not pass verification', {
        status: 500,
      }),
      certifiedHeaders: new Headers(),
    };
  }

  /**
   * Last check. IF this is not an ic domain, then we simply let it load as is.
   * An ic domain will always load using our service worker, and not an ic domain
   * would load by reference. If you want security for your users at that point you
   * should use SRI to make sure the resource matches.
   */
  private async directRequestHandler(): Promise<Response> {
    console.log('Direct call ...');
    // todo: Do we need to check for headers and certify the content here?
    return await fetch(this.request);
  }
}

export * from './mapper';
export * from './typings';
