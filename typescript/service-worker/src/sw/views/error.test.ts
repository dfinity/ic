import { handleErrorResponse } from './error';

describe('Error page', () => {
  it('show text plain response when not in navigate mode', async () => {
    const response = await handleErrorResponse({
      isNavigation: false,
      error: new Error('some unknown error'),
      request: new Request('https://nns.ic0.app/'),
    });

    expect(response.status).toEqual(502);
    expect(response.headers.get('content-type')).toEqual(
      'text/plain;charset=UTF-8'
    );
  });

  it('show text html response when in navigate mode', async () => {
    const response = await handleErrorResponse({
      isNavigation: true,
      error: new Error('some unknown error'),
      request: new Request('https://nns.ic0.app/'),
    });

    expect(response.status).toEqual(502);
    expect(response.headers.get('content-type')).toEqual('text/html');
  });

  it('show text html page with error message', async () => {
    const error = new Error('some unknown error');
    const response = await handleErrorResponse({
      isNavigation: true,
      error,
      request: new Request('https://nns.ic0.app/'),
    });

    expect(await response.text()).toContain(String(error));
  });
});
