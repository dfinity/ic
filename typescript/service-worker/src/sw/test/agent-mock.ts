import { HttpAgent, ApiQueryResponse } from '@dfinity/agent';

export function createAgentMock(
  queryResponses: ApiQueryResponse[] = []
): jest.Mocked<HttpAgent> {
  const agentMock: Partial<jest.Mocked<HttpAgent>> = {
    call: jest.fn(),
    createReadStateRequest: jest.fn(),
    fetchRootKey: jest.fn(),
    getPrincipal: jest.fn(),
    invalidateIdentity: jest.fn(),
    query: jest.fn(),
    readState: jest.fn(),
    replaceIdentity: jest.fn(),
    status: jest.fn(),
    addTransform: jest.fn(),
    syncTime: jest.fn(),
    rootKey: new Uint8Array(),
  };

  for (const response of queryResponses) {
    agentMock.query?.mockResolvedValueOnce(response);
  }

  return agentMock as jest.Mocked<HttpAgent>;
}
