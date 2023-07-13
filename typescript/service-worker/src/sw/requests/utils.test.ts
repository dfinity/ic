import { HttpDetailsResponse } from '@dfinity/agent';
import { getBoundaryNodeRequestId } from './utils';
import { HTTPHeaders } from './typings';

describe('Utils', () => {
  it('should extract boundary node request-id', async () => {
    const requestId = '5f21402d-b76f-998c-ef54-3d0da2e02174';
    const details: HttpDetailsResponse = {
      ok: true,
      status: 200,
      statusText: 'ok',
      headers: [[HTTPHeaders.BoundaryNodeRequestId, requestId]],
    };

    expect(getBoundaryNodeRequestId(details)).toEqual(requestId);
  });
});
