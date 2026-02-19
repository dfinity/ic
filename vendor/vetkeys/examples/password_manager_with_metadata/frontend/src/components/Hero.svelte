<script lang="ts">
    import { type AuthState, login } from "../store/auth";
    import DisclaimerCopy from "./DisclaimerCopy.svelte";
    import Spinner from "./Spinner.svelte";

    export let auth: Extract<
        AuthState,
        {
            state: "initializing-auth" | "initialized" | "anonymous" | "error";
        }
    >;
</script>

<div class="hero min-h-screen content-start pt-8 sm:content-center sm:pt-0">
    <div class="hero-content text-center">
        <div class="max-w-xl">
            <h1
                class="mb-5 text-4xl font-bold text-primary sm:text-5xl dark:text-white"
            >
                Password Manager
            </h1>
            <p class="mb-5 text-xl font-semibold">
                Your private passwords on the Internet Computer.
            </p>
            <p class="mb-5">
                A safe place to store your personal lists, thoughts, ideas or
                passphrases and much more...
            </p>

            {#if auth.state === "initializing-auth"}
                <div class="mt-8 text-lg font-semibold">
                    <Spinner />
                    Initializing...
                </div>
            {:else if auth.state === "anonymous"}
                <button class="btn btn-primary" on:click={() => login()}
                    >Please login to start storing passwords</button
                >
            {:else if auth.state === "error"}
                <div class="mt-8 text-lg font-semibold">An error occurred.</div>
            {/if}

            <div class="mb-12 mt-8 text-xs opacity-75 sm:mb-32 sm:mt-12">
                <DisclaimerCopy />
            </div>
        </div>
    </div>
    <div class="fixed bottom-0 left-0 right-0 pb-4 text-center sm:pb-8">
        <img
            src="/img/ic-badge-powered-by-crypto_label-stripe-white-text.png"
            alt="Powered by the Internet Computer"
            class="hidden h-4 dark:inline"
        />
        <img
            src="/img/ic-badge-powered-by-crypto_label-stripe-dark-text.png"
            alt="Powered by the Internet Computer"
            class="inline h-4 dark:hidden"
        />
    </div>
</div>
