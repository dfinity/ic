import type { Principal } from "@dfinity/principal";
import type { PasswordMetadata } from "../declarations/password_manager_with_metadata/password_manager_with_metadata.did";

export interface PasswordModel {
    owner: Principal;
    parentVaultName: string;
    passwordName: string;
    content: string;
    metadata: PasswordMetadata;
}

export function passwordFromContent(
    owner: Principal,
    parentVaultName: string,
    passwordName: string,
    content: string,
    metadata: PasswordMetadata,
): PasswordModel {
    return {
        owner,
        parentVaultName,
        passwordName,
        content,
        metadata,
    };
}

export function summarize(password: PasswordModel, maxLength = 50) {
    const text = password.content.replace(/<[^>]+>/, "");
    return text.slice(0, maxLength) + (text.length > maxLength ? "..." : "");
}
