import "./init.ts";
import { type ActorSubclass, type HttpAgentOptions } from "@dfinity/agent";
import { EncryptedMaps } from "@dfinity/vetkeys/encrypted_maps";
import { createEncryptedMaps } from "./encrypted_maps";
import type { Principal } from "@dfinity/principal";
import { createActor } from "../declarations/password_manager_with_metadata";
import type { _SERVICE } from "../declarations/password_manager_with_metadata/password_manager_with_metadata.did";
import { passwordFromContent, type PasswordModel } from "../lib/password";
import { vaultFromContent, type VaultModel } from "../lib/vault";

export class PasswordManager {
    /// The actor class representing the full interface of the canister.
    private readonly canisterClient: ActorSubclass<_SERVICE>;
    // TODO: inaccessible API are get, instert and remove
    readonly encryptedMaps: EncryptedMaps;

    constructor(
        canisterClient: ActorSubclass<_SERVICE>,
        encryptedMaps: EncryptedMaps,
    ) {
        this.canisterClient = canisterClient;
        this.encryptedMaps = encryptedMaps;
    }

    async setPassword(
        owner: Principal,
        vault: string,
        passwordName: string,
        password: Uint8Array,
        tags: string[],
        url: string,
    ): Promise<{ Ok: null } | { Err: string }> {
        const encryptedPassword = await this.encryptedMaps.encryptFor(
            owner,
            new TextEncoder().encode(vault),
            new TextEncoder().encode(passwordName),
            password,
        );
        const maybeError =
            await this.canisterClient.insert_encrypted_value_with_metadata(
                owner,
                stringToBytebuf(vault),
                stringToBytebuf(passwordName),
                { inner: encryptedPassword },
                tags,
                url,
            );
        if ("Err" in maybeError) {
            return maybeError;
        } else {
            return { Ok: null };
        }
    }

    async getDecryptedVaults(owner: Principal): Promise<VaultModel[]> {
        const vaultsSharedWithMe =
            await this.encryptedMaps.getAccessibleSharedMapNames();
        const vaultsOwnedByMeResult =
            await this.encryptedMaps.getOwnedNonEmptyMapNames();

        const vaultIds = new Array<[Principal, Uint8Array]>();
        for (const vaultName of vaultsOwnedByMeResult) {
            vaultIds.push([owner, vaultName]);
        }
        for (const [otherOwner, vaultName] of vaultsSharedWithMe) {
            vaultIds.push([otherOwner, vaultName]);
        }

        const vaults = [];

        for (const [otherOwner, vaultName] of vaultIds) {
            const result =
                await this.canisterClient.get_encrypted_values_for_map_with_metadata(
                    otherOwner,
                    { inner: vaultName },
                );
            if ("Err" in result) {
                throw new Error(result.Err);
            }

            const passwords = new Array<[string, PasswordModel]>();
            const vaultNameString = new TextDecoder().decode(vaultName);
            for (const [
                passwordNameBytebuf,
                encryptedData,
                passwordMetadata,
            ] of result.Ok) {
                const passwordNameBytes = Uint8Array.from(
                    passwordNameBytebuf.inner,
                );
                const passwordNameString = new TextDecoder().decode(
                    passwordNameBytes,
                );
                const data = await this.encryptedMaps.decryptFor(
                    otherOwner,
                    vaultName,
                    passwordNameBytes,
                    Uint8Array.from(encryptedData.inner),
                );

                const passwordContent = new TextDecoder().decode(data);
                const password = passwordFromContent(
                    otherOwner,
                    vaultNameString,
                    passwordNameString,
                    passwordContent,
                    passwordMetadata,
                );
                passwords.push([passwordNameString, password]);
            }

            const usersResult = await this.encryptedMaps
                .getSharedUserAccessForMap(otherOwner, vaultName)
                .catch(() => []);

            vaults.push(
                vaultFromContent(
                    otherOwner,
                    vaultNameString,
                    passwords,
                    usersResult,
                ),
            );
        }

        return vaults;
    }

    async removePassword(
        owner: Principal,
        vault: string,
        passwordName: string,
    ): Promise<{ Ok: null } | { Err: string }> {
        const maybeError =
            await this.canisterClient.remove_encrypted_value_with_metadata(
                owner,
                stringToBytebuf(vault),
                stringToBytebuf(passwordName),
            );
        if ("Err" in maybeError) {
            return maybeError;
        } else {
            return { Ok: null };
        }
    }
}

export async function createPasswordManager(
    agentOptions?: HttpAgentOptions,
): Promise<PasswordManager> {
    if (!process.env.CANISTER_ID_PASSWORD_MANAGER_WITH_METADATA) {
        console.error(
            "CANISTER_ID_PASSWORD_MANAGER_WITH_METADATA is not defined",
        );
        throw new Error(
            "CANISTER_ID_PASSWORD_MANAGER_WITH_METADATA is not defined",
        );
    }

    const host =
        process.env.DFX_NETWORK === "ic"
            ? `https://${process.env.CANISTER_ID_PASSWORD_MANAGER_WITH_METADATA}.ic0.app`
            : "http://localhost:8000";
    const hostOptions = { host };

    if (!agentOptions) {
        agentOptions = hostOptions;
    } else {
        agentOptions.host = hostOptions.host;
    }

    const encryptedMaps = await createEncryptedMaps({ ...agentOptions });
    const canisterClient = createActor(
        process.env.CANISTER_ID_PASSWORD_MANAGER_WITH_METADATA,
        { agentOptions },
    );

    return new PasswordManager(canisterClient, encryptedMaps);
}

function stringToBytebuf(str: string): { inner: Uint8Array } {
    return { inner: new TextEncoder().encode(str) };
}
