export const idlFactory = ({ IDL }) => {
  const ledger_type = IDL.Variant({ 'ICP' : IDL.Null, 'ICRC1' : IDL.Null });
  const init_args = IDL.Record({
    'is_mint' : IDL.Bool,
    'ledger_type' : ledger_type,
    'ledger_canister' : IDL.Principal,
  });
  return IDL.Service({
    'account_identifier' : IDL.Func([], [IDL.Text], ['query']),
    'transfer_icp' : IDL.Func([IDL.Text], [], []),
    'transfer_icrc1' : IDL.Func([IDL.Principal], [], []),
  });
};
export const init = ({ IDL }) => {
  const ledger_type = IDL.Variant({ 'ICP' : IDL.Null, 'ICRC1' : IDL.Null });
  const init_args = IDL.Record({
    'is_mint' : IDL.Bool,
    'ledger_type' : ledger_type,
    'ledger_canister' : IDL.Principal,
  });
  return [init_args];
};
