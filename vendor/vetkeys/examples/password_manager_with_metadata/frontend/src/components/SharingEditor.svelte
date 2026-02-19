<script lang="ts">
    import type { VaultModel } from "../lib/vault";
    import { auth } from "../store/auth";
    import {
        addUser,
        refreshVaults,
        removeUser,
        vaultsStore,
    } from "../store/vaults";
    import { addNotification, showError } from "../store/notifications";
    import { Principal } from "@dfinity/principal";
    import type { AccessRights } from "@dfinity/vetkeys/encrypted_maps";

    export let editedVault: VaultModel;
    export let canManage = false;
    export let currentRoute = "";

    let newSharing: string = "";
    let newSharingInput: HTMLInputElement;
    let adding = false;
    let removing = false;

    async function add() {
        if ($auth.state !== "initialized") {
            throw new Error("not logged in");
        }
        adding = true;
        let accessRights: AccessRights = { Read: null };

        const selectElement = document.getElementById(
            "access-rights-select",
        ) as HTMLSelectElement;
        const selectedIndex = selectElement.selectedIndex;
        const selectedValue = selectElement.options[selectedIndex].value;

        if (selectedValue === "ReadWrite") {
            accessRights = { ReadWrite: null };
        } else if (selectedValue === "ReadWriteManage") {
            accessRights = { ReadWriteManage: null };
        }

        try {
            await addUser(
                editedVault.owner,
                editedVault.name,
                Principal.fromText(newSharing),
                accessRights,
                $auth.passwordManager,
            );
            addNotification({
                type: "success",
                message: "User successfully added",
            });
            editedVault.users.push([
                Principal.fromText(newSharing),
                accessRights,
            ]);
            newSharing = "";
            newSharingInput.focus();
        } catch (e) {
            showError(e as Error, "Could not add user.");
        } finally {
            adding = false;
        }
        await refreshVaults(
            $auth.client.getIdentity().getPrincipal(),
            $auth.passwordManager,
        ).catch((e: Error) => showError(e, "Could not refresh vaults."));
    }

    async function remove(sharing: Principal) {
        if ($auth.state !== "initialized") {
            throw new Error("not logged in");
        }
        removing = true;
        try {
            await removeUser(
                editedVault.owner,
                editedVault.name,
                sharing,
                $auth.passwordManager,
            );
            editedVault.users = editedVault.users.filter((user) =>
                user[0].compareTo(sharing),
            );
            addNotification({
                type: "success",
                message: "User successfully removed",
            });
        } catch (e) {
            showError(e as Error, "Could not remove user.");
        } finally {
            removing = false;
        }
        await refreshVaults(
            $auth.client.getIdentity().getPrincipal(),
            $auth.passwordManager,
        ).catch((e: Error) => showError(e, "Could not refresh vaults."));
    }

    function onKeyPress(e: KeyboardEvent) {
        if (
            e.key === "Enter" &&
            !editedVault.users.find(
                (user) =>
                    user[0].compareTo(Principal.fromText(newSharing)) === "eq",
            )
        ) {
            void add();
        }
    }

    export function accessRightsToString(ar: AccessRights) {
        if ("ReadWriteManage" in ar) {
            return "read, write, manage";
        } else if ("ReadWrite" in ar) {
            return "read, write";
        } else if ("Read" in ar) {
            return "read";
        } else {
            throw new Error("unknown access rights");
        }
    }

    $: {
        if ($vaultsStore.state === "loaded" && !editedVault) {
            const split = currentRoute.split("/");
            const vaultOwnewr = Principal.fromText(split[split.length - 2]);
            const vaultName = split[split.length - 1];
            const vault = $vaultsStore.list.find(
                (vault) =>
                    vault.owner === vaultOwnewr && vault.name === vaultName,
            );
            if (vault) {
                editedVault = vault;
            }
        }
    }
</script>

<p class="text-lg font-bold">Users</p>
{#if canManage}
    <p class="mt-1">
        Add users by their principal to allow them viewing or editing the vault.
    </p>
{:else}
    <p class="mt-3">
        This vault is <span class="font-bold">shared</span> with you. It is
        owned by
        <span class="font-bold italic">{editedVault.owner}</span>.
    </p>
    <p class="mt-3">Users with whom the vault is shared:</p>
{/if}
<div class="mt-2 flex flex-wrap space-x-2">
    {#each editedVault.users as sharing (sharing[0].toText())}
        <button
            class="btn btn-outline btn-sm flex items-center"
            on:click={() => {
                void (async () => {
                    await remove(sharing[0]);
                })();
            }}
            disabled={adding || removing || !canManage}
        >
            <span>{accessRightsToString(sharing[1])} {sharing[0].toText()}</span
            >
            <svg
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                class="inline-block h-4 w-4 stroke-current"
            >
                <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M6 18L18 6M6 6l12 12"
                />
            </svg>
        </button>
    {/each}
    <input
        bind:value={newSharing}
        placeholder="Add principal..."
        class="h-8 w-auto rounded-lg bg-transparent px-3 text-base {adding ||
        removing
            ? 'opacity-50'
            : ''} 
          {!canManage ? 'hidden' : ''}"
        bind:this={newSharingInput}
        on:keypress={onKeyPress}
        disabled={adding}
    />
    <select
        name="access-rights"
        id="access-rights-select"
        disabled={(newSharing !== "" &&
            !!editedVault.users.find(
                (user) =>
                    user[0].compareTo(Principal.fromText(newSharing)) === "eq",
            )) ||
            adding ||
            removing}
        hidden={!canManage}
    >
        <option value="Read">read</option>
        <option value="ReadWrite">read-write</option>
        <option value="ReadWriteManage">read-write-manage</option>
    </select>
    <button
        class="btn btn-ghost btn-sm
          {!canManage ? 'hidden' : ''}
          {adding || removing ? 'loading' : ''}"
        on:click={add}
        disabled={(newSharing !== "" &&
            !!editedVault.users.find(
                (user) =>
                    user[0].compareTo(Principal.fromText(newSharing)) === "eq",
            )) ||
            adding ||
            removing}
        >{adding ? "Adding..." : removing ? "Removing... " : "Add"}</button
    >
</div>
