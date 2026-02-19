<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { UserMinus, X, Save, Users } from 'lucide-svelte';
	import type { GroupChat } from '../types';
	import { getMyPrincipal } from '$lib/stores/auth.svelte';
	import { Principal } from '@dfinity/principal';
	import Card from './ui/Card.svelte';
	import Button from './ui/Button.svelte';

	export let show = false;
	export let groupChat: GroupChat;

	const dispatch = createEventDispatcher<{
		close: void;
		save: { addUsers: string[]; removeUsers: string[] };
	}>();

	let selectedToAdd: string[] = [];
	let selectedToRemove: string[] = [];

	// Text input for adding multiple principals
	let principalsInput = '';
	let validPrincipalStrings: string[] = [];
	let invalidPrincipalTokens: string[] = [];

	// Reactively parse and validate principals from text input
	$: {
		const rawTokens = principalsInput
			.split(/[\s,;\n\r]+/)
			.map((t) => t.trim())
			.filter((t) => t.length > 0);
		const uniqueTokens = Array.from(new Set(rawTokens));
		const nextValid: string[] = [];
		const nextInvalid: string[] = [];
		for (const token of uniqueTokens) {
			try {
				// Validate deserialization. Keep original string for dispatching.
				Principal.fromText(token);
				nextValid.push(token);
			} catch {
				nextInvalid.push(token);
			}
		}
		validPrincipalStrings = nextValid;
		invalidPrincipalTokens = nextInvalid;
	}

	// Total adds including typed principals
	$: totalAddCount = selectedToAdd.length + validPrincipalStrings.length;
	$: canSave =
		(totalAddCount > 0 || selectedToRemove.length > 0) && invalidPrincipalTokens.length === 0;

	function toggleRemoveUser(userId: string) {
		console.log(`toggleRemoveUser: ${userId}`);
		if (selectedToRemove.includes(userId)) {
			selectedToRemove = selectedToRemove.filter((id) => id !== userId);
		} else {
			selectedToRemove = [...selectedToRemove, userId];
		}
	}

	function handleSave() {
		// Block saving if any invalid principals are present
		if (invalidPrincipalTokens.length > 0) {
			return;
		}
		const combinedAddUsers = Array.from(new Set([...selectedToAdd, ...validPrincipalStrings]));
		dispatch('save', {
			addUsers: combinedAddUsers,
			removeUsers: selectedToRemove
		});
		handleClose();
	}

	function handleClose() {
		show = false;
		selectedToAdd = [];
		selectedToRemove = [];
		principalsInput = '';
		validPrincipalStrings = [];
		invalidPrincipalTokens = [];
		dispatch('close');
	}

	function canRemoveUser(userId: Principal): boolean {
		// Can't remove current user or admin
		return userId.toText() !== getMyPrincipal().toText();
	}
</script>

{#if show}
	<!-- Backdrop -->
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 backdrop-blur-sm">
		<!-- Modal -->
		<Card
			class="w-full max-w-2xl rounded-xl bg-white shadow-2xl ring-1 ring-black/10"
		>
			<div class="p-6 md:p-8">
				<!-- Header -->
				<div
					class="mb-4 flex items-center justify-between border-b border-black/5 pb-4"
				>
					<div class="flex items-center gap-3">
						<Users class="h-6 w-6" />
						<h2 class="text-lg font-semibold">Manage Group</h2>
						<span class="text-surface-600-300-token truncate text-sm">{groupChat.name}</span>
					</div>
					<button class="variant-ghost-surface btn-icon" onclick={handleClose} aria-label="Close">
						<X class="h-5 w-5" />
					</button>
				</div>

				<!-- Content -->
				<div class="max-h-[60vh] space-y-6 overflow-y-auto">
					<!-- Current Members -->
					<div>
						<h3 class="mb-3 font-semibold">Current Members ({groupChat.participants.length})</h3>
						<div class="space-y-2">
							{#each groupChat.participants as member (member.principal)}
								<div
									class="bg-surface-200-700-token flex items-center justify-between rounded-lg p-3"
								>
									<div class="flex items-center gap-3">
										<div
											class="avatar bg-primary-500 flex h-8 w-8 items-center justify-center rounded-full text-sm"
										>
											{member.avatar || '👤'}
										</div>
										<div>
											<p class="text-sm font-medium">{member.name}</p>
											<div class="text-surface-600-300-token flex items-center gap-2 text-xs">
												<div
													class="h-2 w-2 rounded-full {member.isOnline
														? 'bg-success-500'
														: 'bg-surface-400'}"
												></div>
												{#if member.principal.toText() === getMyPrincipal().toText()}
													<span class="bg-surface-400 rounded px-2 py-0.5 text-xs text-white"
														>Me</span
													>
												{/if}
											</div>
										</div>
									</div>

									{#if canRemoveUser(member.principal)}
										<button
											class="variant-ghost-error btn-icon"
											onclick={() => toggleRemoveUser(member.principal.toText())}
											class:variant-filled-error={selectedToRemove.includes(
												member.principal.toText()
											)}
											title="Remove from group"
										>
											<UserMinus class="h-4 w-4" />
										</button>
									{/if}
								</div>
							{/each}
						</div>
					</div>

					<!-- Add by Principal Text Input -->
					<div>
						<h3 class="mb-3 font-semibold">Add by Principal</h3>
						<div class="space-y-2">
							<textarea
								class="border-surface-300-600-token w-full rounded-lg border p-3 text-sm focus:outline-none"
								class:border-error-500={invalidPrincipalTokens.length > 0}
								rows="3"
								bind:value={principalsInput}
								placeholder="Enter one or more principals separated by commas or whitespace"
							></textarea>

							{#if invalidPrincipalTokens.length > 0}
								<div class="text-error-500 text-xs">
									Invalid principals:
									<div class="mt-1 flex flex-wrap gap-1">
										{#each invalidPrincipalTokens as t (t)}
											<span class="bg-error-500/10 text-error-600 rounded px-2 py-0.5">{t}</span>
										{/each}
									</div>
								</div>
							{:else if validPrincipalStrings.length > 0}
								<div class="text-surface-600-300-token text-xs">
									Will add {validPrincipalStrings.length} principal{validPrincipalStrings.length !==
									1
										? 's'
										: ''}
								</div>
							{/if}
						</div>
					</div>

					<!-- Summary -->
					{#if totalAddCount > 0 || selectedToRemove.length > 0}
						<div class="border-primary-500/20 bg-primary-500/10 rounded-lg border p-4">
							<h4 class="mb-2 text-sm font-semibold">Changes Summary</h4>
							<div class="space-y-1 text-sm">
								{#if totalAddCount > 0}
									<p class="text-success-500">
										+ {totalAddCount} member{totalAddCount !== 1 ? 's' : ''} to add
									</p>
								{/if}
								{#if selectedToRemove.length > 0}
									<p class="text-error-500">
										- {selectedToRemove.length} member{selectedToRemove.length !== 1 ? 's' : ''} to remove
									</p>
								{/if}
							</div>
						</div>
					{/if}
				</div>

				<!-- Footer -->
				<div class="mt-4 flex justify-end gap-2">
					<Button variant="ghost" onclick={handleClose} aria-label="Cancel">
						<X class="h-4 w-4" />
						<span class="ml-1">Cancel</span>
					</Button>
					<Button onclick={handleSave} disabled={!canSave} aria-label="Save Changes">
						<Save class="h-4 w-4" />
						<span class="ml-1">Save Changes</span>
					</Button>
				</div>
			</div>
		</Card>
	</div>
{/if}
