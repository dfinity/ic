<script lang="ts">
	import { login } from '$lib/stores/auth.svelte';
	import DisclaimerCopy from './DisclaimerCopy.svelte';
	import Spinner from './Spinner.svelte';
	import { auth } from '$lib/stores/auth.svelte';
</script>

<div class="flex min-h-screen flex-col items-center justify-start pt-8 sm:justify-center sm:pt-0">
	<div class="flex max-w-xl flex-col items-center text-center">
		<div class="max-w-xl">
			<h1 class="text-primary mb-5 text-4xl font-bold sm:text-5xl">
				Encrypted Chat using vetKeys
			</h1>
			<p class="mb-5 text-xl font-semibold">Your private chat on the Internet Computer.</p>
			<p class="mb-5">A safe place to store your personal messages and much more...</p>

			{#if auth.state.label === 'initializing-auth'}
				<div class="mt-8 text-lg font-semibold">
					<Spinner />
					Initializing...
				</div>
			{:else if auth.state.label === 'anonymous'}
				<button onclick={() => login()} class="btn btn-lg variant-filled-primary animate-fade-in">
					Please login to start chatting
				</button>
			{:else if auth.state.label === 'error'}
				<div class="mt-8 text-lg font-semibold">An error occurred.</div>
			{/if}

			<div class="mb-12 mt-8 text-xs opacity-75 sm:mb-32 sm:mt-12">
				<DisclaimerCopy />
			</div>
		</div>
	</div>
</div>
