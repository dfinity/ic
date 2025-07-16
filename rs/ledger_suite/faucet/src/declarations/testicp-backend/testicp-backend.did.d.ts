import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export interface init_args {
  'is_mint' : boolean,
  'ledger_type' : ledger_type,
  'ledger_canister' : Principal,
}
export type ledger_type = { 'ICP' : null } |
  { 'ICRC1' : null };
export interface _SERVICE {
  'account_identifier' : ActorMethod<[], string>,
  'transfer_icp' : ActorMethod<[string], undefined>,
  'transfer_icrc1' : ActorMethod<[Principal], undefined>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
