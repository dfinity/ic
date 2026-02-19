<script lang="ts">
    import Router from "svelte-spa-router";
    import "../store/vaults";
    import Password from "./Password.svelte";
    import NewPassword from "./NewPassword.svelte";
    import Vaults from "./Vaults.svelte";
    import Vault from "./Vault.svelte";
    import EditVault from "./EditVault.svelte";
    import EditPassword from "./EditPassword.svelte";
    import { wrap } from "svelte-spa-router/wrap";
    import SidebarLayout from "./SidebarLayout.svelte";

    const routes = {
        "/": wrap({ component: NewPassword }),
        "/vaults": wrap({ component: Vaults }),
        "/vaults/:vaultOwner/:VaultName": wrap({ component: Vault }),
        "/edit/vaults/:vaultOwner/:VaultName": wrap({ component: EditVault }),
        "/vaults/:vaultOwner/:VaultName/:passwordName": wrap({
            component: Password,
        }),
        "/edit/vaults/:vaultOwner/:VaultName/:passwordName": wrap({
            component: EditPassword,
        }),
    };
</script>

<SidebarLayout>
    <Router {routes} />
</SidebarLayout>
