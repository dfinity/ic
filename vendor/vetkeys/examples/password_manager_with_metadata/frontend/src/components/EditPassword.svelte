<script lang="ts">
    import { replace, location, link } from "svelte-spa-router";
    import { Editor, placeholder } from "typewriter-editor";
    import { type PasswordModel } from "../lib/password";
    import { vaultsStore, refreshVaults, setPassword } from "../store/vaults";
    import Header from "./Header.svelte";
    import PasswordEditor from "./PasswordEditor.svelte";
    // @ts-expect-error: svelte-icons have some problems with ts declarations
    import Trash from "svelte-icons/fa/FaTrash.svelte";
    import { addNotification, showError } from "../store/notifications";
    import { auth } from "../store/auth";
    import Spinner from "./Spinner.svelte";
    import { onDestroy } from "svelte";
    import { Principal } from "@dfinity/principal";
    import type { AccessRights } from "@dfinity/vetkeys/encrypted_maps";

    export let currentRoute = "";
    const unsubscribe = location.subscribe((value) => {
        currentRoute = decodeURI(value);
    });
    onDestroy(unsubscribe);

    export let parentVaultOwner = "";
    let parentVaultOwnerPrincipal = Principal.managementCanister();
    export let parentVaultName = "";
    export let passwordName = "";
    export let url = "";
    let tagsInput = "";
    export let tags: string[] = [];

    let originalPassword: PasswordModel;

    let editor: Editor;
    let updating = false;
    let deleting = false;
    let accessRights: AccessRights = { Read: null };

    // Convert between string and array when the input changes
    export function handleTagsInput() {
        // Split the input string by commas, trim whitespace, and filter empty strings
        tags = [
            ...new Set(
                tagsInput
                    .split(",")
                    .map((tag) => tag.trim())
                    .filter((tag) => tag !== ""),
            ),
        ];
    }

    async function save() {
        if (
            $auth.state !== "initialized" ||
            $vaultsStore.state !== "loaded" ||
            parentVaultOwner.length === 0 ||
            !originalPassword
        ) {
            return;
        }

        let move = false;

        if (
            parentVaultName !== originalPassword.parentVaultName ||
            parentVaultOwnerPrincipal.compareTo(originalPassword.owner) !== "eq"
        ) {
            move = true;
            // user should have access in the new vault
            const vault = $vaultsStore.list.find(
                (v) =>
                    v.owner.compareTo(parentVaultOwnerPrincipal) === "eq" &&
                    v.name === parentVaultName,
            );
            const me = $auth.client.getIdentity().getPrincipal();
            if (
                parentVaultOwnerPrincipal.compareTo(me) !== "eq" &&
                (!vault ||
                    !vault.users.find((u) => u[0].compareTo(me) === "eq") ||
                    "Read" in
                        (
                            vault.users.find(
                                (u) => u[0].compareTo(me) === "eq",
                            ) as [Principal, AccessRights]
                        )[1])
            ) {
                addNotification({
                    type: "error",
                    message: "unauthorized",
                });
                return;
            }
        } else if (passwordName != originalPassword.passwordName) {
            move = true;
        } else {
            move = false;
        }
        const html = editor.getText();
        updating = true;

        if (move) {
            await $auth.passwordManager
                .removePassword(
                    originalPassword.owner,
                    originalPassword.parentVaultName,
                    originalPassword.passwordName,
                )
                .catch((e) => {
                    deleting = false;
                    showError(
                        e as Error,
                        "Could not delete password for moving it.",
                    );
                    return;
                });

            await setPassword(
                parentVaultOwnerPrincipal,
                parentVaultName,
                passwordName,
                html,
                url,
                tags,
                $auth.passwordManager,
            )
                .catch((e) => {
                    showError(e as Error, "Could not update password.");
                })
                .finally(() => {
                    updating = false;
                });
        } else {
            await setPassword(
                parentVaultOwnerPrincipal,
                parentVaultName,
                passwordName,
                html,
                url,
                tags,
                $auth.passwordManager,
            )
                .catch((e) => {
                    showError(e as Error, "Could not update password.");
                })
                .finally(() => {
                    updating = false;
                });
        }

        addNotification({
            type: "success",
            message: "Password saved successfully",
        });

        await refreshVaults(
            $auth.client.getIdentity().getPrincipal(),
            $auth.passwordManager,
        ).catch((e) => showError(e as Error, "Could not refresh passwords."));

        if (move) {
            void replace(
                "/edit/vaults/" +
                    parentVaultOwner +
                    "/" +
                    parentVaultName +
                    "/" +
                    passwordName,
            );
        }
    }

    async function deletePassword() {
        if ($auth.state !== "initialized") {
            return;
        }
        deleting = true;
        await $auth.passwordManager
            .removePassword(
                parentVaultOwnerPrincipal,
                parentVaultName,
                passwordName,
            )
            .catch((e) => {
                deleting = false;
                showError(e as Error, "Could not delete password.");
            });

        await refreshVaults(
            $auth.client.getIdentity().getPrincipal(),
            $auth.passwordManager,
        )
            .catch((e) => showError(e as Error, "Could not refresh passwords."))
            .finally(() => {
                addNotification({
                    type: "success",
                    message: "Password deleted successfully",
                });
                void replace("/vaults");
            });
    }

    $: {
        if (
            $vaultsStore.state === "loaded" &&
            passwordName.length === 0 &&
            currentRoute.split("/").length > 2 &&
            $auth.state === "initialized"
        ) {
            const split = currentRoute.split("/");
            parentVaultOwner = split[split.length - 3];
            parentVaultOwnerPrincipal = Principal.fromText(parentVaultOwner);
            parentVaultName = split[split.length - 2];
            passwordName = split[split.length - 1];
            const targetVault = $vaultsStore.list.find(
                (v) =>
                    v.owner.compareTo(Principal.fromText(parentVaultOwner)) ===
                        "eq" && v.name === parentVaultName,
            );

            if (targetVault) {
                const searchedForPassword = targetVault.passwords.find(
                    (p) => p[0] === passwordName,
                );

                if (searchedForPassword) {
                    originalPassword = { ...searchedForPassword[1] };
                    url = originalPassword.metadata.url;
                    tags = originalPassword.metadata.tags;
                    tagsInput = tags.join(", ");
                }

                const myPrincipal = $auth.client.getIdentity().getPrincipal();

                if (parentVaultOwnerPrincipal.compareTo(myPrincipal) === "eq") {
                    accessRights = { ReadWriteManage: null };
                } else {
                    let foundAccessRights = targetVault.users.find(
                        (u) => u[0].compareTo(myPrincipal) === "eq",
                    );
                    if (foundAccessRights) {
                        accessRights = foundAccessRights[1];
                    }
                }
                editor = new Editor({
                    modules: {
                        placeholder: placeholder("Start typing..."),
                    },
                    html: originalPassword.content,
                });
            }
        }
    }
</script>

{#if parentVaultName.length > 0}
    <Header>
        <span slot="title"> Edit password </span>
        <button
            slot="actions"
            class="btn btn-ghost {deleting ? 'loading' : ''} {'Read' in
                accessRights}
                ? 'hidden'
                : ''}"
            on:click={deletePassword}
            disabled={updating || deleting}
        >
            {#if !deleting}
                <span class="h-6 w-6 p-1"><Trash /></span>
            {/if}

            {deleting ? "Deleting..." : ""}
        </button>
    </Header>
    <main class="p-4">
        {#if $vaultsStore.state === "loaded"}
            <div class="mb-3">
                <input
                    type="text"
                    bind:value={parentVaultOwner}
                    placeholder="Enter vault owner"
                    class="input input-bordered mb-3 w-full"
                />
                <input
                    type="text"
                    bind:value={parentVaultName}
                    placeholder="Enter vault name"
                    class="input input-bordered w-full"
                />
                <input
                    type="text"
                    bind:value={passwordName}
                    placeholder="Enter password name"
                    class="input input-bordered w-full"
                />
                <input
                    type="text"
                    bind:value={url}
                    placeholder="Enter optional URL"
                    class="input input-bordered w-full"
                />
                <input
                    type="text"
                    bind:value={tagsInput}
                    on:input={handleTagsInput}
                    placeholder="Enter optional tags (comma-separated)"
                    class="input input-bordered w-full"
                />
            </div>
            <PasswordEditor
                {editor}
                disabled={updating || deleting}
                class="mb-3"
            />
            <div class="mb-1 text-sm text-gray-500">
                Created: {new Date(
                    Number(originalPassword.metadata.creation_date) / 1000000,
                )}
            </div>
            <div class="mb-1 text-sm text-gray-500">
                Last modified: {new Date(
                    Number(originalPassword.metadata.last_modification_date) /
                        1000000,
                )}
            </div>
            <div class="mb-1 text-sm text-gray-500">
                Number of modifications: {originalPassword.metadata
                    .number_of_modifications}
            </div>
            <div class="mb-1 text-sm text-gray-500">
                Last modification by: {originalPassword.metadata.last_modified_principal.toText()}
            </div>
            <a
                href={`/vaults/${parentVaultOwner}/${parentVaultName}`}
                use:link
                class="btn btn-primary"
            >
                Back
            </a>

            <button
                class="btn btn-primary mt-4 {updating ? 'loading' : ''}"
                disabled={updating || deleting}
                on:click={save}>{updating ? "Saving..." : "Save"}</button
            >
            <hr class="mt-10" />
        {:else if $vaultsStore.state === "loading"}
            Loading password...
        {/if}
    </main>
{:else}
    <Header>
        <span slot="title"> Edit password </span>
    </Header>
    <main class="p-4">
        {#if $vaultsStore.state === "loading"}
            <Spinner />
            Loading password...
        {:else if $vaultsStore.state === "loaded"}
            <div class="alert alert-error">Could not find password.</div>
        {/if}
    </main>
{/if}
