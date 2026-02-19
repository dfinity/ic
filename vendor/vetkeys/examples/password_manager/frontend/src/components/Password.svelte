<script lang="ts">
    import { type PasswordModel, summarize } from "../lib/password";
    import { link, location } from "svelte-spa-router";
    import { vaultsStore } from "../store/vaults";
    import { Principal } from "@dfinity/principal";
    import { onDestroy } from "svelte";
    import Spinner from "./Spinner.svelte";
    import Header from "./Header.svelte";

    export let currentRoute = "";
    const unsubscribe = location.subscribe((value) => {
        currentRoute = value;
    });
    onDestroy(unsubscribe);

    export let password: PasswordModel = {
        parentVaultName: "",
        owner: Principal.anonymous(),
        passwordName: "",
        content: "",
    };

    export let passwordSummary = "";

    $: {
        if (
            $vaultsStore.state === "loaded" &&
            password.passwordName.length === 0 &&
            currentRoute.split("/").length > 2
        ) {
            const split = currentRoute.split("/");
            const vaultOwner = Principal.fromText(split[split.length - 3]);
            const parentVaultName = split[split.length - 2];
            const passwordName = split[split.length - 1];
            const searchedForPassword = $vaultsStore.list
                .find(
                    (v) =>
                        v.owner.compareTo(vaultOwner) === "eq" &&
                        v.name === parentVaultName,
                )
                .passwords.find((p) => p[0] === passwordName);

            if (searchedForPassword) {
                password = searchedForPassword[1];
                passwordSummary += summarize(password);
            } else {
                passwordSummary =
                    "could not find password " +
                    passwordName +
                    " in vault " +
                    parentVaultName +
                    " owned by " +
                    vaultOwner.toText();
            }
        }
    }
</script>

<Header>
    <span slot="title" class="flex items-center gap-2 h-full">
        Password: {password.passwordName}
    </span>
    <svelte:fragment slot="actions">
        {#if $vaultsStore.state === "loaded" && $vaultsStore.list.length > 0}
            <a class="btn btn-primary" href="/" use:link>New password</a>
        {/if}
    </svelte:fragment>
</Header>

<main class="p-4 pb-24 relative min-h-screen flex flex-col">
    {#if $vaultsStore.state === "loading"}
        <Spinner />
        Loading password...
    {:else if $vaultsStore.state === "loaded"}
        {#if password.parentVaultName === ""}
            <div class="text-center pt-8 italic">
                There is no such password in this vault.
            </div>
            <div class="text-center pt-8">
                <a href="/" use:link class="btn btn-primary"
                    >Add a new password</a
                >
            </div>
        {:else}
            <div
                class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 max-w-7xl"
            >
                <div class="pointer-events-none">
                    <h2 class="text-lg font-bold mb-2 line-clamp-3">
                        {password.passwordName}: "{password.content}"
                    </h2>
                </div>
            </div>
        {/if}
        <div class="flex-grow"></div>
        <div class="text-center">
            <a
                href={`/vaults/${password.owner.toText()}/${password.parentVaultName}`}
                use:link
                class="btn btn-primary"
            >
                Go back to vault
            </a>
        </div>
    {/if}
</main>
