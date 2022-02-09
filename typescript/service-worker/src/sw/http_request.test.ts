import { handleRequest, fetchBody } from './http_request';
import fetch from 'jest-fetch-mock';
import { Cbor, QueryResponseStatus, QueryRequest, HttpAgent } from '@dfinity/agent';
import { IDL } from '@dfinity/candid';
import { Principal } from '@dfinity/principal';

beforeEach(() => {
    fetch.resetMocks();
})

it('should set content-type: application/cbor and x-content-type-options: nosniff on calls to /api', async () => {
    let response = await handleRequest(new Request('https://example.com/api/foo'));

    expect(response.headers.get('x-content-type-options')).toEqual('nosniff');
    expect(response.headers.get('content-type')).toEqual('application/cbor');
});

describe('fetchBody should return body "as is"', () => {
    it('when streaming_strategy is undefined with empty body', async () => {
        const emptyBody = await fetchBody(canisterId, agent, { body: [] });
    
        expect([].join()).toEqual(emptyBody.join());
    });
    
    it('when streaming_strategy is undefined with some body', async () => {
        const body = [1, 2, 3];
        const fetchedBody = await fetchBody(canisterId, agent, { body });
    
        expect(fetchedBody.join()).toEqual(body.join());
    });

    it('when streaming_strategy exists, but empty', async () => {
        const body = [1, 2, 3];
        const fetchedBody = await fetchBody(canisterId, agent, { body, streaming_strategy: [] });
    
        expect(fetchedBody.join()).toEqual(body.join());
    });
    
    it('when streaming_strategy has wrong root signature', async () => {
        // Note: this case is impossible because signature is managed by IDL
        const body = [1, 2, 3];
        const fetchedBody = await fetchBody(canisterId, agent, { body, streaming_strategy: [ { notHandledKey: '' } ] });
    
        expect(fetchedBody.join()).toEqual(body.join());
    });

    it('when streaming_strategy has wrong Callback content', async () => {
        // Note: this case is impossible because signature is managed by IDL
        const body = [1, 2, 3];
        const fetchedBody = await fetchBody(canisterId, agent, {
            body,
            streaming_strategy: [{
                Callback: {
                    callback: [],
                    token: undefined,
                }
            }]
        });
    
        expect(fetchedBody.join()).toEqual(body.join());
    });

    it('when streaming_strategy is good, but query method raises error (wrong response)', async () => {
        fetch.mockResponseOnce(async () => '');

        const body = [1, 2, 3];
        const fetchedBody = await fetchBody(canisterId, agent, {
            body,
            streaming_strategy: [{
                Callback: {
                    callback: [Principal.anonymous(), 'callback_method_name'],
                    token: {
                        key: '/some/file.txt',
                        sha256: [],
                        index: BigInt(1),
                        content_encoding: ''
                    },
                }
            }]
        });

        expect(fetchedBody.join()).toEqual(body.join());
    });
});

describe('fetchBody should return concatenated body', () => {
    it('should make correct query request for chunk', async () => {
        let fetchRequest: QueryRequest | null = null;
        fetch.mockResponseOnce(async (request) => {
            fetchRequest = decodeRequest(request);
            return encodeResponse({ token: [], body: [] }) as any;
        });

        const fetchedBody = await fetchBody(canisterId, agent, {
            body: [1, 2, 3],
            streaming_strategy: [{
                Callback: {
                    callback: [canisterId, 'callback_method_name'],
                    token: {
                        key: '',
                        sha256: [],
                        index: BigInt(1),
                        content_encoding: ''
                    },
                }
            }]
        });

        expect(fetchRequest).not.toBeNull();
        expect(fetchRequest.request_type).toEqual('query');
        expect(Principal.fromUint8Array(fetchRequest.canister_id as unknown as Uint8Array).toString())
            .toEqual(canisterId.toString());
        expect(fetchRequest.method_name).toEqual('callback_method_name');

        expect(fetchedBody.join()).toEqual([1, 2, 3].join());
    });

    it('should merge 2 chunks', async () => {
        fetch.mockResponseOnce(async () => encodeResponse({ token: [], body: [4, 5] }) as any);

        const fetchedBody = await fetchBody(canisterId, agent, {
            body: [1, 2, 3],
            streaming_strategy: [{
                Callback: {
                    callback: [canisterId, 'callback_method_name'],
                    token: {
                        key: '',
                        sha256: [],
                        index: BigInt(1),
                        content_encoding: ''
                    },
                }
            }]
        });

        expect(fetchedBody.join()).toEqual([1, 2, 3, 4, 5].join());
    });
    
    it('should merge N chunks', async () => {
        const tokens = [
            {
                body: [1, 2, 3],
                token: [{ key: '', sha256: [], index: BigInt(1), content_encoding: '' }],
            },
            {
                body: [4, 5],
                token: [{ key: '', sha256: [], index: BigInt(2), content_encoding: '' }],
            },
            {
                body: [6, 7],
                token: [{ key: '', sha256: [], index: BigInt(3), content_encoding: '' }],
            },
            {
                body: [8, 9],
                token: [],
            },
        ];

        fetch.mockResponse(async (request) => {
            const { arg } = decodeRequest(request);
            const index = Number(arg.index);

            return encodeResponse(tokens[index]) as any;
        });

        const fetchedBody = await fetchBody(canisterId, agent, {
            body: tokens[0].body,
            streaming_strategy: [{
                Callback: {
                    callback: [canisterId, 'callback_method_name'],
                    token: tokens[0].token[0],
                }
            }]
        });

        expect(fetchedBody.join()).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9].join());
    });
});

const canisterId = Principal.anonymous();
const agent = new HttpAgent({ host: 'http://localhost' });

const encodeResponse = (mockedResponse: any) => {
    const arg = IDL.encode([StreamingCallbackHttpResponse], [mockedResponse]);

    const body = Cbor.encode({
        status: QueryResponseStatus.Replied,
        reply: { arg }
    });

    return { body };
};

const decodeRequest = (request: Request) => {
    const decodedCborRequest = Cbor.decode<{content: QueryRequest}>(request.body as unknown as ArrayBuffer).content;
    
    return {
        ...decodedCborRequest,
        arg: IDL.decode([StreamingCallbackToken], decodedCborRequest.arg)[0] as any
    };
};

const StreamingCallbackToken = IDL.Record({
    key: IDL.Text,
    sha256: IDL.Opt(IDL.Vec(IDL.Nat8)),
    index: IDL.Nat,
    content_encoding: IDL.Text,
});

const StreamingCallbackHttpResponse = IDL.Record({
    token: IDL.Opt(StreamingCallbackToken),
    body: IDL.Vec(IDL.Nat8),
});