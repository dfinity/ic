<script lang="ts">
    import { replace, location, link } from "svelte-spa-router";
    import { Editor, placeholder } from "typewriter-editor";
    import { type PasswordModel } from "../lib/password";
    import {
        vaultsStore,
        refreshVaults,
        updatePassword,
    } from "../store/vaults";
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
        currentRoute = value;
    });
    onDestroy(unsubscribe);

    export let vaultOwner = "";

    let editedPassword: PasswordModel = {
        parentVaultName: "",
        owner: Principal.managementCanister(),
        passwordName: "",
        content: "",
    };
    let originalPassword: PasswordModel;
    let editor: Editor;
    let updating = false;
    let deleting = false;
    let accessRights: AccessRights = { Read: null };

    async function save() {
        if (
            $auth.state !== "initialized" ||
            $vaultsStore.state !== "loaded" ||
            vaultOwner.length === 0 ||
            !originalPassword
        ) {
            return;
        }

        editedPassword.owner = Principal.fromText(vaultOwner);

        let move = false;

        if (
            editedPassword.parentVaultName !==
                originalPassword.parentVaultName ||
            editedPassword.owner.compareTo(originalPassword.owner) !== "eq"
        ) {
            move = true;
            // user should have access in the new vault
            const vault = $vaultsStore.list.find(
                (v) =>
                    v.owner.compareTo(editedPassword.owner) === "eq" &&
                    v.name === editedPassword.parentVaultName,
            );
            const me = $auth.client.getIdentity().getPrincipal();
            const accessRights =
                vault && vault.users.find((u) => u[0].compareTo(me) === "eq");
            const authorized = accessRights && "Read" in accessRights[1];

            if (editedPassword.owner.compareTo(me) !== "eq" && !authorized) {
                addNotification({
                    type: "error",
                    message: "unauthorized",
                });
                return;
            }
        } else if (
            editedPassword.passwordName != originalPassword.passwordName
        ) {
            move = true;
        } else {
            move = false;
        }
        const html = editor.getText();
        updating = true;

        if (move) {
            await $auth.encryptedMaps
                .removeEncryptedValue(
                    originalPassword.owner,
                    new TextEncoder().encode(originalPassword.parentVaultName),
                    new TextEncoder().encode(originalPassword.passwordName),
                )
                .catch((e) => {
                    deleting = false;
                    showError(e, "Could not delete password for moving it.");
                    return;
                });

            await updatePassword(
                {
                    ...editedPassword,
                    content: html,
                },
                $auth.encryptedMaps,
            )
                .catch((e) => {
                    showError(e, "Could not update password.");
                })
                .finally(() => {
                    updating = false;
                });
        } else {
            await updatePassword(
                {
                    ...editedPassword,
                    content: html,
                },
                $auth.encryptedMaps,
            )
                .catch((e) => {
                    showError(e, "Could not update password.");
                })
                .finally(() => {
                    updating = false;
                });
        }

        addNotification({
            type: "success",
            message: "Password saved successfully",
        });

        await refreshVaults($auth.encryptedMaps).catch((e) =>
            showError(e, "Could not refresh passwords."),
        );

        if (move) {
            void replace(
                "/edit/vaults/" +
                    editedPassword.owner.toText() +
                    "/" +
                    editedPassword.parentVaultName +
                    "/" +
                    editedPassword.passwordName,
            );
        }
    }

    async function deletePassword() {
        if ($auth.state !== "initialized") {
            return;
        }
        deleting = true;
        await $auth.encryptedMaps
            .removeEncryptedValue(
                editedPassword.owner,
                new TextEncoder().encode(editedPassword.parentVaultName),
                new TextEncoder().encode(editedPassword.passwordName),
            )
            .catch((e) => {
                deleting = false;
                showError(e, "Could not delete password.");
            });

        await refreshVaults($auth.encryptedMaps)
            .catch((e) => showError(e, "Could not refresh passwords."))
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
            editedPassword.passwordName.length === 0 &&
            currentRoute.split("/").length > 2 &&
            $auth.state === "initialized"
        ) {
            const split = currentRoute.split("/");
            vaultOwner = split[split.length - 3];
            const parentVaultName = split[split.length - 2];
            const passwordName = split[split.length - 1];
            const searchedForPassword = $vaultsStore.list
                .find(
                    (v) =>
                        v.owner.compareTo(Principal.fromText(vaultOwner)) ===
                            "eq" && v.name === parentVaultName,
                )
                ?.passwords.find((p) => p[0] === passwordName);

            if (searchedForPassword) {
                editedPassword = { ...searchedForPassword[1] };
            }

            const myPrincipal = $auth.client.getIdentity().getPrincipal();

            if (editedPassword.owner.compareTo(myPrincipal) === "eq") {
                accessRights = { ReadWriteManage: null };
            } else {
                const foundAccessRights = $vaultsStore.list
                    .find(
                        (v) =>
                            v.owner.compareTo(editedPassword.owner) === "eq" &&
                            v.name === editedPassword.parentVaultName,
                    )
                    ?.users.find((u) => u[0].compareTo(myPrincipal) === "eq");

                if (foundAccessRights) {
                    accessRights = foundAccessRights[1];
                }
            }

            editor = new Editor({
                modules: {
                    placeholder: placeholder("Start typing..."),
                },
                html: editedPassword.content,
            });

            originalPassword = { ...editedPassword };
        }
    }
</script>

{#if editedPassword.parentVaultName.length > 0}
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
                <span class="w-6 h-6 p-1"><Trash /></span>
            {/if}

            {deleting ? "Deleting..." : ""}
        </button>
    </Header>
    <main class="p-4">
        {#if $vaultsStore.state === "loaded"}
            <div class="mb-3">
                <input
                    type="text"
                    bind:value={vaultOwner}
                    placeholder="Enter vault owner"
                    class="input input-bordered w-full mb-3"
                />
                <input
                    type="text"
                    bind:value={editedPassword.parentVaultName}
                    placeholder="Enter vault name"
                    class="input input-bordered w-full"
                />
                <input
                    type="text"
                    bind:value={editedPassword.passwordName}
                    placeholder="Enter password name"
                    class="input input-bordered w-full"
                />
            </div>
            <PasswordEditor
                {editor}
                disabled={updating || deleting}
                class="mb-3"
            />

            <a
                href={`/vaults/${editedPassword.owner.toText()}/${editedPassword.parentVaultName}`}
                use:link
                class="btn btn-primary"
            >
                Back
            </a>

            <button
                class="btn mt-4 btn-primary {updating ? 'loading' : ''}"
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
