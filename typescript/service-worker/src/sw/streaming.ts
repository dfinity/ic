import {
  StreamingCallbackHttpResponse,
  StreamingStrategy,
  Token,
} from '../http-interface/canister_http_interface_types';
import { streamingCallbackHttpResponseType } from '../http-interface/canister_http_interface';
import { IDL } from '@dfinity/candid';
import { HttpAgent, QueryResponseStatus } from '@dfinity/agent';
import { Principal } from '@dfinity/principal';

const MAX_CALLBACKS = 1000;

export async function streamContent(
  agent: HttpAgent,
  canisterId: Principal,
  streamingStrategy: StreamingStrategy
): Promise<Array<number>> {
  let buffer = [];
  let tokenOpt = [streamingStrategy.Callback.token];
  const [, callBackFunc] = streamingStrategy.Callback.callback;

  let currentCallback = 1;
  while (tokenOpt.length !== 0) {
    if (currentCallback > MAX_CALLBACKS) {
      throw new Error('Exceeded streaming callback limit');
    }
    const callbackResponse = await queryNextChunk(
      tokenOpt[0],
      agent,
      canisterId,
      callBackFunc
    );
    switch (callbackResponse.status) {
      case QueryResponseStatus.Replied: {
        const callbackData = IDL.decode(
          [streamingCallbackHttpResponseType],
          callbackResponse.reply.arg
        )[0];
        if (isStreamingCallbackResponse(callbackData)) {
          buffer = buffer.concat(callbackData.body);
          tokenOpt = callbackData.token;
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
) {
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
