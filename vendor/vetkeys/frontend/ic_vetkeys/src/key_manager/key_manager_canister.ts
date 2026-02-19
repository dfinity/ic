import { Principal } from "@dfinity/principal";
import { ActorSubclass, HttpAgent } from "@dfinity/agent";
import { createActor } from "../declarations/ic_vetkeys_manager_canister/index.js";
import {
    _SERVICE as _DEFAULT_KEY_MANAGER_SERVICE,
    AccessRights,
    ByteBuf,
} from "../declarations/ic_vetkeys_manager_canister/ic_vetkeys_manager_canister.did.js";
import { KeyManagerClient } from "./index";

export class DefaultKeyManagerClient implements KeyManagerClient {
    canisterId: string;
    actor: ActorSubclass<_DEFAULT_KEY_MANAGER_SERVICE>;
    verificationKey: ByteBuf | undefined = undefined;

    constructor(agent: HttpAgent, canisterId: string) {
        this.canisterId = canisterId;
        this.actor = createActor(canisterId, { agent });
    }

    get_accessible_shared_key_ids(): Promise<[Principal, ByteBuf][]> {
        return this.actor.get_accessible_shared_key_ids();
    }

    set_user_rights(
        owner: Principal,
        vetkeyName: ByteBuf,
        user: Principal,
        userRights: AccessRights,
    ): Promise<{ Ok: [] | [AccessRights] } | { Err: string }> {
        return this.actor.set_user_rights(owner, vetkeyName, user, userRights);
    }

    get_user_rights(
        owner: Principal,
        vetkeyName: ByteBuf,
        user: Principal,
    ): Promise<{ Ok: [] | [AccessRights] } | { Err: string }> {
        return this.actor.get_user_rights(owner, vetkeyName, user);
    }

    remove_user(
        owner: Principal,
        vetkeyName: ByteBuf,
        user: Principal,
    ): Promise<{ Ok: [] | [AccessRights] } | { Err: string }> {
        return this.actor.remove_user(owner, vetkeyName, user);
    }

    async get_encrypted_vetkey(
        keyOwner: Principal,
        vetkeyName: ByteBuf,
        transportKey: ByteBuf,
    ): Promise<{ Ok: ByteBuf } | { Err: string }> {
        return await this.actor.get_encrypted_vetkey(
            keyOwner,
            vetkeyName,
            transportKey,
        );
    }

    async get_vetkey_verification_key(): Promise<ByteBuf> {
        if (this.verificationKey) {
            return this.verificationKey;
        } else {
            this.verificationKey =
                await this.actor.get_vetkey_verification_key();
            return this.verificationKey;
        }
    }
}
