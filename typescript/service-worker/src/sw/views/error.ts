import errorPageHtml from 'html-loader?{"minimize":{"removeComments":false}}!./error.html';
import logger from '../../logger';
import { responseVerificationFailedResponse } from '../requests';

export interface ErrorResponseProps {
  isNavigation: boolean;
  error: unknown;
  request: Request;
  requestId?: string;
  response?: Response;
}

const format = <T>(obj: T): string => JSON.stringify(obj, null, 2);

const genericMsg = (msg: string): string => `
<div role="doc-subtitle">
  ${msg}
</div>
`;

const couldNotConnectMsg = `
<div role="doc-subtitle">
  <p>
    There was an issue connecting to the Internet Computer network.
    <br />
    Please check your Internet connection and try again.  
  </p>
</div>
`;

const reloadServiceWorkerSection = `
<hr />
<p>
  Click
  <button
    class="anchor reload-btn"
    href="#"
    onclick="this.disabled=true;reloadServiceWorker()"
  >
    here
  </button>
  to reload the page, if this issue persists, please feel free to reach out on
  <a
    href="https://forum.dfinity.org/"
    target="_blank"
    rel="noopener noreferrer"
    class="anchor"
  >the Internet Computer forum</a>.
</p>
`;

const getDisplayMessage = (err: unknown): string => {
  if (err instanceof TypeError) {
    return couldNotConnectMsg;
  }

  return genericMsg(String(err));
};

const chevron =
  '<svg class="chevron" width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M15.5 7.75L10.25 13L5 7.75" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"></path></svg>';

const clipboard =
  '<svg class="clipboard" width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" clip-rule="evenodd" d="M6.75 3C5.23207 3 4 4.22862 4 5.74826V14.75H5.5V5.74826C5.5 5.05875 6.05879 4.5 6.75 4.5H12.75V3H6.75ZM8.75 7.25H13.75C14.0261 7.25 14.25 7.47386 14.25 7.75V15.75C14.25 16.0261 14.0261 16.25 13.75 16.25H8.75C8.47386 16.25 8.25 16.0261 8.25 15.75V7.75C8.25 7.47386 8.47386 7.25 8.75 7.25ZM6.75 7.75C6.75 6.64543 7.64543 5.75 8.75 5.75H13.75C14.8546 5.75 15.75 6.64543 15.75 7.75V15.75C15.75 16.8546 14.8546 17.75 13.75 17.75H8.75C7.64543 17.75 6.75 16.8546 6.75 15.75V7.75Z" fill="currentColor"></path></svg>';

const collapsibleContent = (title: string, msg: string): string => `
<div class="collapsible-container">
  <div class="collapsible-trigger" title="Show error details" aria-label="Show error details">
    ${title}

    <button
      type="button"
      class="copy-to-clipboard"
      title="Copy to clipboard"
      aria-label="Copy to clipboard"
    >${clipboard}</button>

    <span class="copy-to-clipboard-feedback">Copied!</span>

    <span class="spacer"></span>

    ${chevron}
  </div>

  <div class="collapsible-content">
    ${msg}

  </div>
</div>
`;

const getErrorDetails = async (props: ErrorResponseProps): Promise<string> => {
  let errorDetails = '<textarea readonly>';

  errorDetails += 'Timestamp: ' + new Date().toUTCString();
  if (props.requestId) {
    errorDetails += '\nRequest-ID: ' + props.requestId;
  }

  errorDetails +=
    '\n\nRequest: ' +
    format({
      method: props.request.method,
      url: props.request.url,
      origin: location.origin,
    });

  if (props.response) {
    errorDetails +=
      '\n\nResponse: ' +
      format({
        status: props.response.status,
        statusText: props.response.statusText,
        body: await props.response.text(),
      });
  }

  errorDetails += '</textarea>';

  return collapsibleContent('Error details', errorDetails);
};

const logProps = (props: ErrorResponseProps): void => {
  logger.error('Error', props.error);
  logger.error('Request', props.request);

  if (props.requestId) {
    logger.error('RequestID', props.requestId);
  }

  if (props.response) {
    logger.error('Response', props.response);
  }
};

const afterContentSection = (props: ErrorResponseProps): string => {
  if (!props.response) {
    return reloadServiceWorkerSection;
  }

  if (
    props.response.status !== responseVerificationFailedResponse.status &&
    props.response.statusText !== responseVerificationFailedResponse.statusText
  ) {
    return reloadServiceWorkerSection;
  }

  return '';
};

export const handleErrorResponse = async (
  props: ErrorResponseProps
): Promise<Response> => {
  logProps(props);

  if (props.isNavigation) {
    const displayMessage = getDisplayMessage(props.error);
    const extraDetails = await getErrorDetails(props);
    const afterContent = afterContentSection(props);

    return new Response(
      errorPageHtml
        .replace('<!--{{content}}-->', displayMessage)
        .replace('<!--{{afterContent}}-->', afterContent)
        .replace('<!--{{extraDetailsContent}}-->', extraDetails),
      {
        status: 502,
        headers: {
          'content-type': 'text/html',
        },
      }
    );
  }

  const errorMessage = String(props.error);
  return new Response(errorMessage, {
    status: 502,
    statusText: errorMessage,
  });
};
