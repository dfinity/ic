<script lang="ts">
    import { type VaultModel } from "../lib/vault";
    import { vaultsStore } from "../store/vaults";
    import Header from "./Header.svelte";
    import Spinner from "./Spinner.svelte";
    import { link } from "svelte-spa-router";

    let filter = "";
    let filteredVaults: VaultModel[];

    $: searchIndex =
        $vaultsStore.state === "loaded"
            ? $vaultsStore.list.map((vault) => {
                  const div = document.createElement("div");
                  div.innerHTML += vault.name;

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
    <span slot="title"> Your vaults </span>
    <svelte:fragment slot="actions">
        {#if $vaultsStore.state === "loaded" && $vaultsStore.list.length > 0}
            <a class="btn btn-primary" href="/" use:link>New password</a>
        {/if}
    </svelte:fragment>
</Header>
<main class="p-4">
    {#if $vaultsStore.state === "loading"}
        <Spinner />
        Loading vaults...
    {:else if $vaultsStore.state === "loaded"}
        {#if $vaultsStore.list.length > 0}
            <div class="mb-6">
                <input
                    bind:value={filter}
                    class="bg-transparent text-base {filter.length > 0
                        ? 'border'
                        : ''} h-8 rounded-lg px-3"
                    placeholder="Filter vaults by name..."
                />
            </div>

            <div
                class="grid max-w-7xl grid-cols-1 gap-3 sm:grid-cols-2 md:grid-cols-3"
            >
                {#each filteredVaults as vault ([vault.owner, vault.name])}
                    <a
                        class="bg-base rounded-md border border-base-300 p-4 transition-transform
hover:-translate-y-2 dark:border-base-300 dark:bg-base-100"
                        use:link
                        href={`/vaults/${vault.owner.toText()}/${vault.name}`}
                    >
                        <div class="pointer-events-none">
                            <h2 class="mb-2 line-clamp-3 text-lg font-bold">
                                "{vault.name}" owned by {vault.owner}
                            </h2>
                        </div>
                    </a>
                {/each}
            </div>
        {:else}
            <div class="pt-8 text-center italic">
                You don't have any vaults.
            </div>
            <div class="pt-8 text-center">
                <a href="/" use:link class="btn btn-primary"
                    >Add a new password</a
                >
            </div>
        {/if}
    {:else if $vaultsStore.state === "error"}
        <div class="alert alert-error">Could not load vaults.</div>
    {/if}
</main>
