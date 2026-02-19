import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export type AccessRights = { 'Read' : null } |
  { 'ReadWrite' : null } |
  { 'ReadWriteManage' : null };
export interface ByteBuf { 'inner' : Uint8Array | number[] }
export type Result = { 'Ok' : ByteBuf } |
  { 'Err' : string };
export type Result_1 = { 'Ok' : Array<[Principal, AccessRights]> } |
  { 'Err' : string };
export type Result_2 = { 'Ok' : [] | [AccessRights] } |
  { 'Err' : string };
export interface _SERVICE {
  'get_accessible_shared_key_ids' : ActorMethod<
    [],
    Array<[Principal, ByteBuf]>
  >,
  'get_encrypted_vetkey' : ActorMethod<[Principal, ByteBuf, ByteBuf], Result>,
  'get_shared_user_access_for_key' : ActorMethod<
    [Principal, ByteBuf],
    Result_1
  >,
  'get_user_rights' : ActorMethod<[Principal, ByteBuf, Principal], Result_2>,
  'get_vetkey_verification_key' : ActorMethod<[], ByteBuf>,
  'remove_user' : ActorMethod<[Principal, ByteBuf, Principal], Result_2>,
  'set_user_rights' : ActorMethod<
    [Principal, ByteBuf, Principal, AccessRights],
    Result_2
  >,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
