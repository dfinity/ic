import {
  HttpResponse,
  StreamingCallbackHttpResponse,
  StreamingStrategy,
  Token,
} from '../../http-interface/canister_http_interface_types';
import { streamingCallbackHttpResponseType } from '../../http-interface/canister_http_interface';
import { IDL } from '@dfinity/candid';
import {
  HttpAgent,
  QueryResponse,
  QueryResponseStatus,
  concat,
} from '@dfinity/agent';
import { Principal } from '@dfinity/principal';

const MAX_CALLBACKS = 1000;

export async function streamBody(
  agent: HttpAgent,
  httpResponse: HttpResponse,
  canisterId: Principal
): Promise<Uint8Array> {
  // if we do streaming, body contains the first chunk
  let buffer = new ArrayBuffer(0);
  buffer = concat(buffer, httpResponse.body);

  if (httpResponse.streaming_strategy.length !== 0) {
    const remainingChunks = await streamRemainingChunks(
      agent,
      canisterId,
      httpResponse.streaming_strategy[0]
    );

    buffer = concat(buffer, remainingChunks);
  }

  return new Uint8Array(buffer);
}

async function streamRemainingChunks(
  agent: HttpAgent,
  canisterId: Principal,
  streamingStrategy: StreamingStrategy
): Promise<ArrayBuffer> {
  let buffer = new ArrayBuffer(0);
  let tokenOpt: Token | undefined = streamingStrategy.Callback.token;
  const callBackFunc = streamingStrategy.Callback.callback[1];

  let currentCallback = 1;
  while (tokenOpt) {
    if (currentCallback > MAX_CALLBACKS) {
      throw new Error('Exceeded streaming callback limit');
    }

    const callbackResponse = await queryNextChunk(
      tokenOpt,
      agent,
      canisterId,
      callBackFunc
    );

    switch (callbackResponse.status) {
      case QueryResponseStatus.Replied: {
        const [callbackData] = IDL.decode(
          [streamingCallbackHttpResponseType],
          callbackResponse.reply.arg
        );

        if (isStreamingCallbackResponse(callbackData)) {
          buffer = concat(buffer, callbackData.body);
          [tokenOpt] = callbackData.token;
        } else {
          throw new Error('Unexpected callback response: ' + callbackData);
        }

        break;
      }

      case QueryResponseStatus.Rejected: {
        throw new Error('Streaming callback error: ' + callbackResponse);
      }
    }

    currentCallback += 1;
  }

  return buffer;
}

function queryNextChunk(
  token: Token,
  agent: HttpAgent,
  canisterId: Principal,
  callBackFunc: string
): Promise<QueryResponse> {
  const tokenType = token.type();
  // unbox primitive values
  const tokenValue =
    typeof token.valueOf === 'function' ? token.valueOf() : token;
  const callbackArg = IDL.encode([tokenType], [tokenValue]);
  return agent.query(canisterId, {
    methodName: callBackFunc,
    arg: callbackArg,
  });
}

function isStreamingCallbackResponse(
  response: unknown
): response is StreamingCallbackHttpResponse {
  return (
    typeof response === 'object' &&
    response !== null &&
    'body' in response &&
    'token' in response
  );
}
