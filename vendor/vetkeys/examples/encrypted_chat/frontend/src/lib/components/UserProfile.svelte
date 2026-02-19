<script lang="ts">
	import { Settings, X, Check, LogOut } from 'lucide-svelte';
	import { userConfig, chatUIActions } from '../stores/chat.svelte';
	import { auth, getMyPrincipal, logout } from '$lib/stores/auth.svelte';
	import type { User } from '$lib/types';

	const currentUser = $derived<{ state: User | null }>({
		state: {
			...getDummyCurrentUser(),
			name:
				auth.state.label === 'initialized'
					? auth.state.client.getIdentity().getPrincipal().toString()
					: ''
		}
	});

	function getDummyCurrentUser(): User {
		return {
			principal: getMyPrincipal(),
			name: 'You',
			avatar: '👤',
			isOnline: true
		};
	}

	let showConfig = $state(false);
	let configForm = $state({
		cacheRetentionDays: 7
	});

	$effect(() => {
		if (userConfig.state) {
			configForm.cacheRetentionDays = userConfig.state.cacheRetentionDays;
		}
	});

	function toggleConfig() {
		showConfig = !showConfig;
	}

	async function saveConfig() {
		await chatUIActions.updateUserConfig(configForm);
		showConfig = false;
	}

	function handleBackdropClick(event: MouseEvent) {
		if (event.target === event.currentTarget) {
			showConfig = false;
		}
	}
</script>

<div class="user-profile border-surface-300-600-token border-b p-4">
	<div class="flex items-center justify-between">
		<div class="flex items-center gap-3">
			<div
				class="avatar bg-primary-500 flex h-10 w-10 items-center justify-center rounded-full text-lg"
			>
				{currentUser.state?.avatar || '👤'}
			</div>
			<div>
				<h3 class="text-sm font-semibold">Name: ---<br /></h3>
				<h4 class="text-xs font-semibold">{currentUser.state?.name}</h4>
			</div>
		</div>
		<div class="flex items-center gap-2">
			<button class="variant-ghost-surface btn-icon" onclick={logout} aria-label="Logout">
				<LogOut class="h-5 w-6" />
			</button>
		</div>
	</div>
</div>

<!-- Settings Modal -->
{#if showConfig}
	<!-- Backdrop -->
	<div
		class="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm"
		onclick={handleBackdropClick}
		role="button"
		tabindex="-1"
		onkeydown={() => {}}
	></div>

	<!-- Modal -->
	<div class="fixed inset-0 z-50 flex items-center justify-center p-4">
		<div
			class="config-modal w-full max-w-md rounded-2xl border border-gray-200 bg-white shadow-2xl"
		>
			<!-- Header -->
			<div
				class="flex items-center justify-between border-b border-gray-200 p-6"
			>
				<h3 class="text-lg font-semibold text-gray-900">Settings</h3>
				<button
					class="rounded-lg p-1 text-gray-400 transition-colors hover:bg-gray-100 hover:text-gray-600"
					onclick={() => (showConfig = false)}
					aria-label="Close settings"
				>
					<X class="h-5 w-5" />
				</button>
			</div>

			<!-- Content -->
			<div class="space-y-4 p-6">
				<div>
					<label
						for="cache-retention"
						class="mb-2 block text-sm font-medium text-gray-700"
					>
						Cache Retention (days)
					</label>
					<input
						id="cache-retention"
						type="number"
						min="1"
						max="365"
						bind:value={configForm.cacheRetentionDays}
						class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-gray-900 outline-none transition-all focus:border-transparent focus:ring-2 focus:ring-blue-500"
						placeholder="7"
					/>
					<p class="mt-1 text-xs text-gray-500">
						How long to keep symmetric key cache before automatic cleanup
					</p>
				</div>
			</div>

			<!-- Footer -->
			<div
				class="flex items-center justify-end gap-3 border-t border-gray-200 p-6"
			>
				<button
					class="rounded-lg px-4 py-2 text-gray-700 transition-colors hover:bg-gray-100"
					onclick={() => (showConfig = false)}
				>
					Cancel
				</button>
				<button
					class="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-white transition-colors hover:bg-blue-700"
					onclick={saveConfig}
				>
					<Check class="h-4 w-4" />
					Save
				</button>
			</div>
		</div>
	</div>
{/if}

<style>
	.user-profile {
		background: var(--color-surface-100);
	}

	.config-modal {
		animation: modalSlideIn 0.2s ease-out;
	}

	@keyframes modalSlideIn {
		from {
			opacity: 0;
			transform: scale(0.95);
		}
		to {
			opacity: 1;
			transform: scale(1);
		}
	}
</style>
