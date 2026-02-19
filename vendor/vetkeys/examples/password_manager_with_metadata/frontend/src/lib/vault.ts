import type { Principal } from "@dfinity/principal";
import type { PasswordModel } from "./password";
import type { AccessRights } from "@dfinity/vetkeys/encrypted_maps";

export interface VaultModel {
    owner: Principal;
    name: string;
    passwords: Array<[string, PasswordModel]>;
    users: Array<[Principal, AccessRights]>;
}

export function vaultFromContent(
    owner: Principal,
    name: string,
    passwords: Array<[string, PasswordModel]>,
    users: Array<[Principal, AccessRights]>,
): VaultModel {
    return { owner, name, passwords, users };
}

export function summarize(vault: VaultModel, maxLength = 1500) {
    let text =
        "Owner: " +
        vault.owner.toString() +
        ", " +
        vault.users.length +
        " users";
    text += ", " + vault.passwords.length + " passwords.\n";

    return text.slice(0, maxLength) + (text.length > maxLength ? "..." : "");
}
