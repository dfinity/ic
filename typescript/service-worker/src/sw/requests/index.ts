import { concat } from '@dfinity/agent';
import { decode as base64ArraybufferDecode } from 'base64-arraybuffer';
import { HttpRequest } from '../../http-interface/canister_http_interface_types';
import { ResponseCache } from '../cache';
import { CanisterResolver } from '../domains';
import { CanisterLookup } from '../domains/typings';
import { streamContent } from '../streaming';
import { validateBody } from '../validation';
import { VerifiedResponse, cacheHeaders } from './typings';
import {
  createAgentAndActor,
  decodeBody,
  removeLegacySubDomains,
  shouldFetchRootKey,
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
    let currentGateway: URL;
    try {
      currentGateway = await canisterResolver.getCurrentGateway();
    } catch (err) {
      const error = err as Error;
      console.error(
        `Fetch failed for ${this.request.url}, resolving to a status code of 404 (${error.message})`
      );

      return new Response('Could not find the canister ID.', { status: 404 });
    }

    const lookup = await canisterResolver.lookupFromHttpRequest(this.request);

    // maybe check if is an api call
    if (canisterResolver.isAPICall(this.request, currentGateway, lookup)) {
      return await this.apiRequestHandler(currentGateway);
    }

    // maybe check if its an asset
    if (lookup.canister) {
      const assetResponse = await this.assetRequestHandler(lookup.canister);

      // assets are cached depending of the available cache headers
      await responseCache.save({
        request: this.request,
        response: assetResponse.response,
        certifiedResponseHeaders: assetResponse.certifiedHeaders,
      });

      return assetResponse.response;
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
  private async apiRequestHandler(currentGateway: URL): Promise<Response> {
    const cleanedRequest = await removeLegacySubDomains(
      this.request,
      currentGateway
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
    canister: CanisterLookup
  ): Promise<VerifiedResponse> {
    try {
      const [agent, actor] = await createAgentAndActor(
        canister.gateway,
        canister.principal,
        shouldFetchRootKey
      );
      const requestHeaders: [string, string][] = [['Host', this.url.hostname]];
      this.request.headers.forEach((value, key) => {
        if (key.toLowerCase() === 'if-none-match') {
          // Drop the if-none-match header because we do not want a "304 not modified" response back.
          // See TT-30.
          return;
        }
        requestHeaders.push([key, value]);
      });

      // If the accept encoding isn't given, add it because we want to save bandwidth.
      if (!this.request.headers.has('Accept-Encoding')) {
        requestHeaders.push(['Accept-Encoding', 'gzip, deflate, identity']);
      }

      const httpRequest: HttpRequest = {
        method: this.request.method,
        url: this.url.pathname + this.url.search,
        headers: requestHeaders,
        body: new Uint8Array(await this.request.arrayBuffer()),
      };

      let httpResponse = await actor.http_request(httpRequest);
      const upgradeCall =
        httpResponse.upgrade.length === 1 && httpResponse.upgrade[0];

      if (upgradeCall) {
        // repeat the request as an update call
        httpResponse = await actor.http_request_update(httpRequest);
      }

      // Redirects are blocked for query calls only: if this response has the upgrade to update call flag set,
      // the update call is allowed to redirect. This is safe because the response (including the headers) will go through consensus.
      if (
        !upgradeCall &&
        httpResponse.status_code >= 300 &&
        httpResponse.status_code < 400
      ) {
        console.error(
          'Due to security reasons redirects are blocked on the IC until further notice!'
        );
        return {
          response: new Response(
            'Due to security reasons redirects are blocked on the IC until further notice!',
            { status: 500 }
          ),
          certifiedHeaders: new Headers(),
        };
      }

      const headers = new Headers();

      let certificate: ArrayBuffer | undefined;
      let tree: ArrayBuffer | undefined;
      let encoding = '';
      for (const [key, value] of httpResponse.headers) {
        const headerKey = key.trim().toLowerCase();
        switch (headerKey) {
          case 'ic-certificate':
            {
              const fields = value.split(/,/);
              for (const f of fields) {
                const matchParts = f.match(/^(.*)=:(.*):$/) ?? [];
                const [, name, b64Value] = [...matchParts].map((x) => x.trim());
                const value = base64ArraybufferDecode(b64Value);

                if (name === 'certificate') {
                  certificate = value;
                } else if (name === 'tree') {
                  tree = value;
                }
              }
            }
            continue;
          case 'content-encoding':
            encoding = value.trim();
            break;
        }

        if (cacheHeaders.includes(headerKey)) {
          // cache headers are remove since those are handled by
          // cache storage within the service worker. If returned they would
          // reach https://www.chromium.org/blink/ in the cache of chromium which
          // could cache those entries in memory and those requests can't be
          // intercepted by the service worker
          continue;
        }

        headers.append(key, value);
      }

      // if we do streaming, body contains the first chunk
      let buffer = new ArrayBuffer(0);
      buffer = concat(buffer, httpResponse.body);
      if (httpResponse.streaming_strategy.length !== 0) {
        buffer = concat(
          buffer,
          await streamContent(
            agent,
            canister.principal,
            httpResponse.streaming_strategy[0]
          )
        );
      }
      const body = new Uint8Array(buffer);
      const identity = decodeBody(body, encoding);

      // when an update call is used, the response certification is checked by
      // agent-js
      let bodyValid = upgradeCall;
      if (!upgradeCall && certificate && tree) {
        // Try to validate the body as is.
        bodyValid = await validateBody(
          canister.principal,
          this.url.pathname,
          body.buffer,
          certificate,
          tree,
          agent,
          shouldFetchRootKey
        );

        if (!bodyValid) {
          // If that didn't work, try to validate its identity version. This is for
          // backward compatibility.
          bodyValid = await validateBody(
            canister.principal,
            this.url.pathname,
            identity.buffer,
            certificate,
            tree,
            agent,
            shouldFetchRootKey
          );
        }
      }
      if (bodyValid) {
        // todo: add certified headers when available from response-verification integration
        const certifiedHeaders = new Headers();

        return {
          response: new Response(identity.buffer, {
            status: httpResponse.status_code,
            headers,
          }),
          certifiedHeaders,
        };
      } else {
        console.error('BODY DOES NOT PASS VERIFICATION');
        return {
          response: new Response('Body does not pass verification', {
            status: 500,
          }),
          certifiedHeaders: new Headers(),
        };
      }
    } catch (e) {
      console.error('Failed to fetch response:', e);

      return {
        response: new Response(`Failed to fetch response: ${String(e)}`, {
          status: 500,
        }),
        certifiedHeaders: new Headers(),
      };
    }
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
