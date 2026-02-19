<script lang="ts">
    import { type VaultModel } from "../lib/vault";
    import { vaultsStore } from "../store/vaults";
    import Header from "./Header.svelte";
    import Password from "./Password.svelte";
    import Spinner from "./Spinner.svelte";
    import { link } from "svelte-spa-router";

    let filter = "";
    let filteredVaults: VaultModel[];

    $: searchIndex =
        $vaultsStore.state === "loaded"
            ? $vaultsStore.list.map((vault) => {
                  const div = document.createElement("div");
                  div.innerHTML = Array.from(vault.passwords.values())
                      .map((password) => password[0])
                      .join(" xx ");
                  const content = div.innerText;
                  return [content].join("/#delimiter#/").toLowerCase();
              })
            : [];

    $: {
        if ($vaultsStore.state === "loaded") {
            if (filter.length > 0) {
                filteredVaults = $vaultsStore.list.filter((_, i) => {
                    return searchIndex[i].includes(filter.toLowerCase());
                });
            } else {
                filteredVaults = $vaultsStore.list;
            }
        }
    }
</script>

<Header>
    <span slot="title"> Your passwords </span>
    <svelte:fragment slot="actions">
        {#if $vaultsStore.state === "loaded" && $vaultsStore.list.length > 0}
            <a class="btn btn-primary" use:link href="/">New Password</a>
        {/if}
    </svelte:fragment>
</Header>
<main class="p-4">
    {#if $vaultsStore.state === "loading"}
        <Spinner />
        Loading passwords...
    {:else if $vaultsStore.state === "loaded"}
        {#if $vaultsStore.list.length > 0}
            <div class="mb-6">
                <input
                    bind:value={filter}
                    class="bg-transparent text-base {filter.length > 0
                        ? 'border'
                        : ''} h-8 rounded-lg px-3"
                    placeholder="Filter notes..."
                />
            </div>

            <div
                class="grid max-w-7xl grid-cols-1 gap-3 sm:grid-cols-2 md:grid-cols-3"
            >
                {#each filteredVaults as vault (vault.name)}
                    {#each Array.from(vault.passwords.map((password) => password[1])) as password ((password.owner, password.parentVaultName, password.passwordName))}
                        <Password {password} />
                    {/each}
                {/each}
            </div>
        {:else}
            <div class="pt-8 text-center italic">You don't have any notes.</div>
            <div class="pt-8 text-center">
                <a href="/" use:link class="btn btn-primary">Add a note</a>
            </div>
        {/if}
    {:else if $vaultsStore.state === "error"}
        <div class="alert alert-error">Could not load passwords.</div>
    {/if}
</main>
