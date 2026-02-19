import { Principal } from "@dfinity/principal";
import { ActorSubclass, HttpAgent } from "@dfinity/agent";
import { createActor } from "../declarations/ic_vetkeys_encrypted_maps_canister/index";
import {
    _SERVICE as _DEFAULT_ENCRYPTED_MAPS_SERVICE,
    AccessRights,
    ByteBuf,
    EncryptedMapData,
} from "../declarations/ic_vetkeys_encrypted_maps_canister/ic_vetkeys_encrypted_maps_canister.did";
import { EncryptedMapsClient } from "./index";

export class DefaultEncryptedMapsClient implements EncryptedMapsClient {
    actor: ActorSubclass<_DEFAULT_ENCRYPTED_MAPS_SERVICE>;

    constructor(agent: HttpAgent, canisterId: string) {
        this.actor = createActor(canisterId, { agent: agent });
    }

    get_accessible_shared_map_names(): Promise<[Principal, ByteBuf][]> {
        return this.actor.get_accessible_shared_map_names();
    }

    get_shared_user_access_for_map(
        owner: Principal,
        mapName: ByteBuf,
    ): Promise<{ Ok: Array<[Principal, AccessRights]> } | { Err: string }> {
        return this.actor.get_shared_user_access_for_map(owner, mapName);
    }

    get_owned_non_empty_map_names(): Promise<Array<ByteBuf>> {
        return this.actor.get_owned_non_empty_map_names();
    }

    get_all_accessible_encrypted_values(): Promise<
        [[Principal, ByteBuf], [ByteBuf, ByteBuf][]][]
    > {
        return this.actor.get_all_accessible_encrypted_values();
    }

    get_all_accessible_encrypted_maps(): Promise<Array<EncryptedMapData>> {
        return this.actor.get_all_accessible_encrypted_maps();
    }

    get_encrypted_value(
        mapOwner: Principal,
        mapName: ByteBuf,
        mapKey: ByteBuf,
    ): Promise<{ Ok: [] | [ByteBuf] } | { Err: string }> {
        return this.actor.get_encrypted_value(mapOwner, mapName, mapKey);
    }

    get_encrypted_values_for_map(
        mapOwner: Principal,
        mapName: ByteBuf,
    ): Promise<{ Ok: Array<[ByteBuf, ByteBuf]> } | { Err: string }> {
        return this.actor.get_encrypted_values_for_map(mapOwner, mapName);
    }

    get_encrypted_vetkey(
        mapOwner: Principal,
        mapName: ByteBuf,
        transportKey: ByteBuf,
    ): Promise<{ Ok: ByteBuf } | { Err: string }> {
        return this.actor.get_encrypted_vetkey(mapOwner, mapName, transportKey);
    }

    insert_encrypted_value(
        mapOwner: Principal,
        mapName: ByteBuf,
        mapKey: ByteBuf,
        data: ByteBuf,
    ): Promise<{ Ok: [] | [ByteBuf] } | { Err: string }> {
        return this.actor.insert_encrypted_value(
            mapOwner,
            mapName,
            mapKey,
            data,
        );
    }

    remove_encrypted_value(
        mapOwner: Principal,
        mapName: ByteBuf,
        mapKey: ByteBuf,
    ): Promise<{ Ok: [] | [ByteBuf] } | { Err: string }> {
        return this.actor.remove_encrypted_value(mapOwner, mapName, mapKey);
    }

    remove_map_values(
        mapOwner: Principal,
        mapName: ByteBuf,
    ): Promise<{ Ok: Array<ByteBuf> } | { Err: string }> {
        return this.actor.remove_map_values(mapOwner, mapName);
    }

    get_vetkey_verification_key(): Promise<ByteBuf> {
        return this.actor.get_vetkey_verification_key();
    }

    set_user_rights(
        owner: Principal,
        mapName: ByteBuf,
        user: Principal,
        userRights: AccessRights,
    ): Promise<{ Ok: [] | [AccessRights] } | { Err: string }> {
        return this.actor.set_user_rights(owner, mapName, user, userRights);
    }

    get_user_rights(
        owner: Principal,
        mapName: ByteBuf,
        user: Principal,
    ): Promise<{ Ok: [] | [AccessRights] } | { Err: string }> {
        return this.actor.get_user_rights(owner, mapName, user);
    }

    remove_user(
        owner: Principal,
        mapName: ByteBuf,
        user: Principal,
    ): Promise<{ Ok: [] | [AccessRights] } | { Err: string }> {
        return this.actor.remove_user(owner, mapName, user);
    }
}
