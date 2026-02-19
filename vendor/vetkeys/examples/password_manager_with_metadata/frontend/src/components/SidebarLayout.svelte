<script lang="ts">
    import { auth, logout } from "../store/auth";
    // @ts-expect-error: svelte-icons have some problems with ts declarations
    import FaPlusSquare from "svelte-icons/fa/FaPlusSquare.svelte";
    // @ts-expect-error: svelte-icons have some problems with ts declarations
    import GoDatabase from "svelte-icons/go/GoDatabase.svelte";
    // @ts-expect-error: svelte-icons have some problems with ts declarations
    import FaDoorOpen from "svelte-icons/fa/FaDoorOpen.svelte";
    import Disclaimer from "./Disclaimer.svelte";
    import { Principal } from "@dfinity/principal";
    import { link } from "svelte-spa-router";
</script>

<div class="drawer-mobile drawer bg-base-200 lg:drawer-open">
    <input id="my-drawer-3" type="checkbox" class="drawer-toggle" />
    <div class="drawer-content flex flex-col lg:!z-[1000]">
        <div class="flex-1">
            <slot />
        </div>
        <Disclaimer />
    </div>
    <div class="drawer-side">
        <label for="my-drawer-3" class="drawer-overlay" />
        <aside
            class="flex h-full w-64 flex-col justify-between border-r
    border-base-300 bg-base-100 text-base-content sm:w-80"
        >
            <div
                class="sticky h-16 border-b border-base-300 py-4 pl-5 text-2xl font-bold text-primary dark:text-white"
            >
                VetKD Password Manager
            </div>
            <div class="border-b">
                <div class="pl-4">My Principal:</div>
                <div class="pl-4">
                    {$auth.state === "initialized"
                        ? $auth.client.getIdentity().getPrincipal().toText()
                        : Principal.anonymous().toText()}
                </div>
            </div>
            <ul
                class="menu flex w-full flex-1 flex-col overflow-y-auto bg-base-100 p-4"
            >
                <li>
                    <a href="/" use:link>
                        <span class="mr-2 h-6 w-6 p-1">
                            <FaPlusSquare />
                        </span>
                        New password
                    </a>
                </li>
                <li>
                    <a href="/vaults" use:link>
                        <span class="mr-2 h-6 w-6 p-1">
                            <GoDatabase />
                        </span>
                        Your vaults</a
                    >
                </li>
                <li class="flex-1 bg-transparent" />
                <li>
                    <button on:click={() => logout()}>
                        <span class="mr-2 h-6 w-6 p-1">
                            <FaDoorOpen />
                        </span>
                        Log out</button
                    >
                </li>
            </ul>
            <div class="px-5 pb-4">
                <img
                    src="/img/ic-badge-powered-by-crypto_transparent-white-text.png"
                    alt="Powered by the Internet Computer"
                    class="hidden dark:inline"
                />
                <img
                    src="/img/ic-badge-powered-by-crypto_transparent-dark-text.png"
                    alt="Powered by the Internet Computer"
                    class="inline dark:hidden"
                />
            </div>
        </aside>
    </div>
</div>
