import errorPageHtml from 'html-loader?{"minimize":{"removeComments":false}}!./error.html';

export interface ErrorResponseProps {
  isNavigation: boolean;
  error: unknown;
}

const escapeHTML = (htmlStr: string): string => {
  return htmlStr
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
};

export const handleErrorResponse = async (
  props: ErrorResponseProps
): Promise<Response> => {
  const errorMessage = String(props.error);

  if (props.isNavigation) {
    return new Response(
      errorPageHtml.replace('<!--{{message}}-->', escapeHTML(errorMessage)),
      {
        status: 502,
        headers: {
          'content-type': 'text/html',
        },
      }
    );
  }

  return new Response(errorMessage, {
    status: 502,
  });
};
