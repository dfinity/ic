<script lang="ts">
    import Hero from "./components/Hero.svelte";
    import LayoutAuthenticated from "./components/LayoutAuthenticated.svelte";
    import Notifications from "./components/Notifications.svelte";
    import { auth } from "./store/auth";
</script>

{#if $auth.state === "initialized"}
    <LayoutAuthenticated />
{:else}
    <Hero auth={$auth} />
{/if}
<Notifications />
