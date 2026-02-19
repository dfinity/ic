export const idlFactory = ({ IDL }) => {
  const ByteBuf = IDL.Record({ 'inner' : IDL.Vec(IDL.Nat8) });
  const Result = IDL.Variant({ 'Ok' : ByteBuf, 'Err' : IDL.Text });
  const AccessRights = IDL.Variant({
    'Read' : IDL.Null,
    'ReadWrite' : IDL.Null,
    'ReadWriteManage' : IDL.Null,
  });
  const Result_1 = IDL.Variant({
    'Ok' : IDL.Vec(IDL.Tuple(IDL.Principal, AccessRights)),
    'Err' : IDL.Text,
  });
  const Result_2 = IDL.Variant({
    'Ok' : IDL.Opt(AccessRights),
    'Err' : IDL.Text,
  });
  return IDL.Service({
    'get_accessible_shared_key_ids' : IDL.Func(
        [],
        [IDL.Vec(IDL.Tuple(IDL.Principal, ByteBuf))],
        ['query'],
      ),
    'get_encrypted_vetkey' : IDL.Func(
        [IDL.Principal, ByteBuf, ByteBuf],
        [Result],
        [],
      ),
    'get_shared_user_access_for_key' : IDL.Func(
        [IDL.Principal, ByteBuf],
        [Result_1],
        ['query'],
      ),
    'get_user_rights' : IDL.Func(
        [IDL.Principal, ByteBuf, IDL.Principal],
        [Result_2],
        ['query'],
      ),
    'get_vetkey_verification_key' : IDL.Func([], [ByteBuf], []),
    'remove_user' : IDL.Func(
        [IDL.Principal, ByteBuf, IDL.Principal],
        [Result_2],
        [],
      ),
    'set_user_rights' : IDL.Func(
        [IDL.Principal, ByteBuf, IDL.Principal, AccessRights],
        [Result_2],
        [],
      ),
  });
};
export const init = ({ IDL }) => { return []; };
