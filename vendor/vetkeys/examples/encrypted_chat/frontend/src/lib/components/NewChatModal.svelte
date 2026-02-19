<script lang="ts">
	import { X, Plus, Users, User } from 'lucide-svelte';
	import Card from './ui/Card.svelte';
	import Button from './ui/Button.svelte';
	import { chatUIActions } from '$lib/stores/chat.svelte';
	/** @type {{ show: boolean }} */
	let { show = $bindable(false) } = $props();

	let tab: 'direct' | 'group' = $state('direct');

	// Direct chat form
	let directPrincipal = $state('');
	let directRotationMinutes = $state(60);
	let directExpirationMinutes = $state(1440);

	// Group chat form
	let groupPrincipalsText = $state('');
	let groupRotationMinutes = $state(60);
	let groupExpirationMinutes = $state(1440);

	function close() {
		show = false;
	}

	async function createDirect() {
		await chatUIActions.createDirectChat(
			directPrincipal,
			directRotationMinutes,
			directExpirationMinutes
		);
		close();
	}

	async function createGroup() {
		const principals = groupPrincipalsText.split(/[\s,]+/).filter(Boolean);
		await chatUIActions.createGroupChat(principals, groupRotationMinutes, groupExpirationMinutes);
		close();
	}
</script>

{#if show}
	<div
		class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 backdrop-blur-sm"
		role="dialog"
		aria-modal="true"
	>
		<Card
			class="w-full max-w-lg rounded-xl bg-white shadow-2xl ring-1 ring-black/10"
		>
			<div class="p-6 md:p-8">
				<div
					class="mb-4 flex items-center justify-between border-b border-black/5 pb-4"
				>
					<h3 class="text-lg font-semibold">Create Chat</h3>
					<button class="variant-ghost-surface btn-icon" onclick={close} aria-label="Close">
						<X class="h-5 w-5" />
					</button>
				</div>

				<div class="mb-4 flex gap-2">
					<button
						class="btn {tab === 'direct' ? 'variant-filled-primary' : 'variant-ghost-surface'}"
						onclick={() => (tab = 'direct')}
					>
						<User class="h-4 w-4" />
						<span class="ml-1">Direct</span>
					</button>
					<button
						class="btn {tab === 'group' ? 'variant-filled-primary' : 'variant-ghost-surface'}"
						onclick={() => (tab = 'group')}
					>
						<Users class="h-4 w-4" />
						<span class="ml-1">Group</span>
					</button>
				</div>

				{#if tab === 'direct'}
					<div class="space-y-3">
						<label class="block text-sm">
							<span class="mb-1 block font-medium">Receiver Principal</span>
							<input
								class="w-full rounded-md border bg-white px-3 py-2"
								bind:value={directPrincipal}
								placeholder="aaaaa-aa"
							/>
						</label>
						<div class="grid grid-cols-2 gap-3">
							<label class="block text-sm">
								<span class="mb-1 block font-medium">Symmetric Key Ratchet (min)</span>
								<input
									type="number"
									min="0"
									class="w-full rounded-md border bg-white px-3 py-2"
									bind:value={directRotationMinutes}
								/>
							</label>
							<label class="block text-sm">
								<span class="mb-1 block font-medium">Message Expiration (min)</span>
								<input
									type="number"
									min="0"
									class="w-full rounded-md border bg-white px-3 py-2"
									bind:value={directExpirationMinutes}
								/>
							</label>
						</div>
						<div class="flex justify-end gap-2">
							<Button onclick={createDirect} disabled={!directPrincipal.trim()}>
								<Plus class="h-4 w-4" />
								<span class="ml-1">Create</span>
							</Button>
						</div>
					</div>
				{:else}
					<div class="space-y-3">
						<label class="block text-sm">
							<span class="mb-1 block font-medium">Participant Principals</span>
							<textarea
								rows="3"
								class="w-full rounded-md border bg-white px-3 py-2"
								bind:value={groupPrincipalsText}
								placeholder="comma or space separated principals"
							></textarea>
						</label>
						<div class="grid grid-cols-2 gap-3">
							<label class="block text-sm">
								<span class="mb-1 block font-medium">Symmetric Key Ratchet (min)</span>
								<input
									type="number"
									min="0"
									class="w-full rounded-md border bg-white px-3 py-2"
									bind:value={groupRotationMinutes}
								/>
							</label>
							<label class="block text-sm">
								<span class="mb-1 block font-medium">Message Expiration (min)</span>
								<input
									type="number"
									min="0"
									class="w-full rounded-md border bg-white px-3 py-2"
									bind:value={groupExpirationMinutes}
								/>
							</label>
						</div>
						<div class="flex justify-end gap-2">
							<Button onclick={createGroup}>
								<Plus class="h-4 w-4" />
								<span class="ml-1">Create Group</span>
							</Button>
						</div>
					</div>
				{/if}
			</div>
		</Card>
	</div>
{/if}
