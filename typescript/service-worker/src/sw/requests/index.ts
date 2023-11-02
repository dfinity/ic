import { Principal } from '@dfinity/principal';
import logger from '../../logger';
import { ResponseCache } from '../cache';
import { CanisterResolver } from '../domains';
import { queryCallHandler } from './query-call';
import { VerifiedResponse } from './typings';
import {
  shouldUpgradeToUpdateCall,
  updateCallHandler,
} from './upgrade-to-update-call';
import {
  createAgentAndActor,
  createHttpRequest,
  getBoundaryNodeRequestId,
  loadResponseVerification,
  shouldFetchRootKey,
  updateRequestApiGateway,
} from './utils';

export class RequestProcessor {
  private readonly url: URL;
  private _requestId?: string;

  constructor(private readonly request: Request) {
    this.url = new URL(this.request.url);
  }

  /**
   * Only available if the api boundary node adds the 'X-Request-Id' header.
   */
  public get requestId(): string | undefined {
    return this._requestId;
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

    const canisterResolver = await CanisterResolver.setup();
    const gatewayUrl = await canisterResolver.getCurrentGateway();

    // maybe check if the response should be denied
    if (canisterResolver.isUnderscoreRawCall(this.request, gatewayUrl)) {
      return this.denyRequestHandler();
    }

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
      return new Response(
        `${this.url.toString()} did not resolve to a canister ID.`,
        {
          status: 404,
          statusText: `${this.url.toString()} did not resolve to a canister ID.`,
        }
      );
    }

    return await this.directRequestHandler();
  }

  /**
   * We refuse any request to /_/*
   */
  private denyRequestHandler(): Response {
    return new Response(null, {
      status: 404,
      statusText: 'Requests to /_/* are not allowed',
    });
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
    await loadResponseVerification();

    const [agent, actor] = await createAgentAndActor(
      gatewayUrl,
      canisterId,
      shouldFetchRootKey
    );

    const httpRequest = await createHttpRequest(this.request);
    const agentResponse = await actor.http_request(httpRequest);

    this._requestId = getBoundaryNodeRequestId(agentResponse.httpDetails);
    const httpResponse = await agentResponse.result;

    if (shouldUpgradeToUpdateCall(httpResponse)) {
      const updateCallResult = await updateCallHandler(
        agent,
        actor,
        canisterId,
        httpRequest
      );
      this._requestId = updateCallResult.boundaryNodeRequestId;

      return updateCallResult.result;
    }

    return await queryCallHandler(agent, httpRequest, httpResponse, canisterId);
  }

  /**
   * Last check. IF this is not an ic domain, then we simply let it load as is.
   * An ic domain will always load using our service worker, and not an ic domain
   * would load by reference. If you want security for your users at that point you
   * should use SRI to make sure the resource matches.
   */
  private async directRequestHandler(): Promise<Response> {
    logger.info('Direct call ...');
    // todo: Do we need to check for headers and certify the content here?
    return await fetch(this.request);
  }
}

export * from './mapper';
export * from './typings';
