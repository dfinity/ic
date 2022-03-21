/**
 * Implement the HttpRequest to Canisters Proposal.
 *
 * TODO: Add support for streaming.
 */
import { Actor, HttpAgent } from '@dfinity/agent';
import { IDL } from '@dfinity/candid';
import { Principal } from '@dfinity/principal';
import { validateBody } from './validation';
import * as base64Arraybuffer from 'base64-arraybuffer';
import * as pako from 'pako';

const hostnameCanisterIdMap: Record<string, [string, string]> = {
  'identity.ic0.app': ['rdmx6-jaaaa-aaaaa-aaadq-cai', 'ic0.app'],
  'nns.ic0.app': ['qoctq-giaaa-aaaaa-aaaea-cai', 'ic0.app'],
  'dscvr.ic0.app': ['h5aet-waaaa-aaaab-qaamq-cai', 'ic0.page'],
  'personhood.ic0.app': ['g3wsl-eqaaa-aaaan-aaaaa-cai', 'ic0.app'],
};

const shouldFetchRootKey: boolean = ["1", "true"].includes(process.env.FORCE_FETCH_ROOT_KEY);

const swLocation = new URL(self.location.toString());
const [_swCanisterId, swDomains] = (() => {
  const maybeSplit = splitHostnameForCanisterId(swLocation.hostname);
  if (maybeSplit) {
    return maybeSplit;
  } else {
    return [null, swLocation.hostname];
  }
})() as [Principal | null, string];

/**
 * Split a hostname up-to the first valid canister ID from the right.
 * @param hostname The hostname to analyze.
 * @returns A canister ID followed by all subdomains that are after it, or null if no
 *     canister ID were found.
 */
function splitHostnameForCanisterId(hostname: string): [Principal, string] | null {
  const maybeFixed = hostnameCanisterIdMap[hostname];
  if (maybeFixed) {
    return [Principal.fromText(maybeFixed[0]), maybeFixed[1]];
  }

  const subdomains = hostname.split('.').reverse();
  const topdomains = [];
  for (const domain of subdomains) {
    try {
      const principal = Principal.fromText(domain);
      return [principal, topdomains.reverse().join('.')];
    } catch (_) {
      topdomains.push(domain);
    }
  }

  return null;
}

/**
 * Try to resolve the Canister ID to contact in the domain name.
 * @param hostname The domain name to look up.
 * @returns A Canister ID or null if none were found.
 */
function maybeResolveCanisterIdFromHostName(hostname: string): Principal | null {
  // Try to resolve from the right to the left.
  const maybeCanisterId = splitHostnameForCanisterId(hostname);
  if (maybeCanisterId && swDomains === maybeCanisterId[1]) {
    return maybeCanisterId[0];
  }

  return null;
}

/**
 * Try to resolve the Canister ID to contact in the search params.
 * @param searchParams The URL Search params.
 * @param isLocal Whether to resolve headers as if we were running locally.
 * @returns A Canister ID or null if none were found.
 */
function maybeResolveCanisterIdFromSearchParam(
  searchParams: URLSearchParams,
  isLocal: boolean,
): Principal | null {
  // Skip this if we're not on localhost.
  if (!isLocal) {
    return null;
  }

  const maybeCanisterId = searchParams.get('canisterId');
  if (maybeCanisterId) {
    try {
      return Principal.fromText(maybeCanisterId);
    } catch (e) {
      // Do nothing.
    }
  }

  return null;
}

/**
 * Try to resolve the Canister ID to contact from a URL string.
 * @param urlString The URL in string format (normally from the request).
 * @param isLocal Whether to resolve headers as if we were running locally.
 * @returns A Canister ID or null if none were found.
 */
function resolveCanisterIdFromUrl(urlString: string, isLocal: boolean): Principal | null {
  try {
    const url = new URL(urlString);
    return (
      maybeResolveCanisterIdFromHostName(url.hostname) ||
      maybeResolveCanisterIdFromSearchParam(url.searchParams, isLocal)
    );
  } catch (_) {
    return null;
  }
}

/**
 * Try to resolve the Canister ID to contact from headers.
 * @param headers Headers from the HttpRequest.
 * @param isLocal Whether to resolve headers as if we were running locally.
 * @returns A Canister ID or null if none were found.
 */
function maybeResolveCanisterIdFromHeaders(headers: Headers, isLocal: boolean): Principal | null {
  const maybeHostHeader = headers.get('host');
  if (maybeHostHeader) {
    // Remove the port.
    const maybeCanisterId = maybeResolveCanisterIdFromHostName(
      maybeHostHeader.replace(/:\d+$/, ''),
    );
    if (maybeCanisterId) {
      return maybeCanisterId;
    }
  }

  if (isLocal) {
    const maybeRefererHeader = headers.get('referer');
    if (maybeRefererHeader) {
      const maybeCanisterId = resolveCanisterIdFromUrl(maybeRefererHeader, isLocal);
      if (maybeCanisterId) {
        return maybeCanisterId;
      }
    }
  }

  return null;
}

function maybeResolveCanisterIdFromHttpRequest(request: Request, isLocal: boolean) {
  return (
    (isLocal && resolveCanisterIdFromUrl(request.referrer, isLocal)) ||
    maybeResolveCanisterIdFromHeaders(request.headers, isLocal) ||
    resolveCanisterIdFromUrl(request.url, isLocal)
  );
}

const canisterIdlFactory: IDL.InterfaceFactory = ({ IDL }) => {
  const HeaderField = IDL.Tuple(IDL.Text, IDL.Text);
  const HttpRequest = IDL.Record({
    method: IDL.Text,
    url: IDL.Text,
    headers: IDL.Vec(HeaderField),
    body: IDL.Vec(IDL.Nat8),
  });
  const HttpResponse = IDL.Record({
    status_code: IDL.Nat16,
    headers: IDL.Vec(HeaderField),
    body: IDL.Vec(IDL.Nat8),
    // TODO: Support streaming in JavaScript.
  });

  return IDL.Service({
    http_request: IDL.Func([HttpRequest], [HttpResponse], ['query']),
  });
};

/**
 * Decode a body (ie. deflate or gunzip it) based on its content-encoding.
 * @param body The body to decode.
 * @param encoding Its content-encoding associated header.
 */
function decodeBody(body: Uint8Array, encoding: string): Uint8Array {
  switch (encoding) {
    case 'identity':
    case '':
      return body;
    case 'gzip':
      return pako.ungzip(body);
    case 'deflate':
      return pako.inflate(body);
    default:
      throw new Error(`Unsupported encoding: "${encoding}"`);
  }
}

/**
 * Box a request, send it to the canister, and handle its response, creating a Response
 * object.
 * @param request The request received from the browser.
 * @returns The response to send to the browser.
 * @throws If an internal error happens.
 */
export async function handleRequest(request: Request): Promise<Response> {
  const url = new URL(request.url);

  /**
   * We forward all requests to /api/ to the replica, as is.
   */
  if (url.pathname.startsWith('/api/')) {
    let response = await fetch(request);
    // force the content-type to be cbor as /api/ is exclusively used for canister calls
    let sanitizedHeaders = new Headers(response.headers);
    sanitizedHeaders.set('X-Content-Type-Options', 'nosniff');
    sanitizedHeaders.set('Content-Type', 'application/cbor');
    return new Response(response.body, {status: response.status, statusText: response.statusText, headers: sanitizedHeaders});
  }

  /**
   * We refuse any request to /_/*
   */
  if (url.pathname.startsWith('/_/')) {
    return new Response(null, { status: 404 });
  }

  /**
   * We try to do an HTTP Request query.
   */
  const isLocal = swDomains === 'localhost';
  const maybeCanisterId = maybeResolveCanisterIdFromHttpRequest(request, isLocal);
  if (maybeCanisterId) {
    try {
      const replicaUrl = new URL(url.origin);
      const agent = new HttpAgent({ host: replicaUrl.toString() });
      const actor = Actor.createActor(canisterIdlFactory, {
        agent,
        canisterId: maybeCanisterId,
      });
      const requestHeaders: [string, string][] = [];
      request.headers.forEach((value, key) => requestHeaders.push([key, value]));

      // If the accept encoding isn't given, add it because we want to save bandwidth.
      if (!request.headers.has('Accept-Encoding')) {
        requestHeaders.push(['Accept-Encoding', 'gzip, deflate, identity']);
      }

      const httpRequest = {
        method: request.method,
        url: url.pathname + url.search,
        headers: requestHeaders,
        body: [...new Uint8Array(await request.arrayBuffer())],
      };

      const httpResponse: any = await actor.http_request(httpRequest);
      const headers = new Headers();

      let certificate: ArrayBuffer | undefined;
      let tree: ArrayBuffer | undefined;
      let encoding = '';
      for (const [key, value] of httpResponse.headers) {
        switch (key.trim().toLowerCase()) {
          case 'ic-certificate':
            {
              const fields = value.split(/,/);
              for (const f of fields) {
                const [_0, name, b64Value] = [...f.match(/^(.*)=:(.*):$/)].map(x => x.trim());
                const value = base64Arraybuffer.decode(b64Value);

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

        headers.append(key, value);
      }

      const body = new Uint8Array(httpResponse.body);
      const identity = decodeBody(body, encoding);

      let bodyValid = false;
      if (certificate && tree) {
        // Try to validate the body as is.
        bodyValid = await validateBody(
          maybeCanisterId,
          url.pathname,
          body.buffer,
          certificate,
          tree,
          agent,
          shouldFetchRootKey,
        );

        if (!bodyValid) {
          // If that didn't work, try to validate its identity version. This is for
          // backward compatibility.
          bodyValid = await validateBody(
            maybeCanisterId,
            url.pathname,
            identity.buffer,
            certificate,
            tree,
            agent,
            isLocal,
          );
        }
      }
      if (bodyValid) {
        return new Response(identity.buffer, {
          status: httpResponse.status_code,
          headers,
        });
      } else {
        console.error('BODY DOES NOT PASS VERIFICATION');
        return new Response('Body does not pass verification', { status: 500 });
      }
    } catch (e) {
      console.error('Failed to fetch response:', e);
      return new Response(`Failed to fetch response: ${String(e)}`, {
        status: 500,
      });
    }
  }

  // Last check. IF this is not part of the same domain, then we simply let it load as is.
  // The same domain will always load using our service worker, and not the same domain
  // would load by reference. If you want security for your users at that point you
  // should use SRI to make sure the resource matches.
  if (!url.hostname.endsWith(swDomains)|| url.hostname.endsWith(`raw.${swDomains}`)) {
    console.log("Direct call ...");
    // todo: Do we need to check for headers and certify the content here?
    return await fetch(request);
  }

  console.error(`URL ${JSON.stringify(url.toString())} did not resolve to a canister ID.`);
  return new Response('Could not find the canister ID.', { status: 404 });
}
