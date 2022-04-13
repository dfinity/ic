import { IDL } from '@dfinity/candid';

const tokenType = IDL.Unknown;
export const streamingCallbackHttpResponseType = IDL.Record({
  token: IDL.Opt(tokenType),
  body: IDL.Vec(IDL.Nat8),
});
export const idlFactory = ({ IDL }) => {
  const HeaderField = IDL.Tuple(IDL.Text, IDL.Text);
  const HttpRequest = IDL.Record({
    url: IDL.Text,
    method: IDL.Text,
    body: IDL.Vec(IDL.Nat8),
    headers: IDL.Vec(HeaderField),
  });
  const StreamingStrategy = IDL.Variant({
    Callback: IDL.Record({
      token: tokenType,
      callback: IDL.Func(
        [tokenType],
        [streamingCallbackHttpResponseType],
        ['query']
      ),
    }),
  });
  const HttpResponse = IDL.Record({
    body: IDL.Vec(IDL.Nat8),
    headers: IDL.Vec(HeaderField),
    streaming_strategy: IDL.Opt(StreamingStrategy),
    status_code: IDL.Nat16,
  });
  return IDL.Service({
    http_request: IDL.Func([HttpRequest], [HttpResponse], ['query']),
  });
};
export const init = ({ IDL }) => {
  return [];
};
