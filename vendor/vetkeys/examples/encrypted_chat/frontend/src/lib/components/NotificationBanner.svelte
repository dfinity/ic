<script lang="ts">
	import { onMount } from 'svelte';
	import { fly } from 'svelte/transition';
	import { X, AlertTriangle, Info, CheckCircle, XCircle } from 'lucide-svelte';
	import { notifications, chatUIActions } from '../stores/chat.svelte';
	import { chatStorageService } from '../services/chatStorage';
	import type { Notification } from '../types';

	let showDisclaimer = false;

	onMount(async () => {
		const dismissed = await chatStorageService.isDisclaimerDismissed();
		showDisclaimer = !dismissed;
	});

	async function dismissDisclaimer() {
		showDisclaimer = false;
		await chatStorageService.setDisclaimerDismissed();
	}

	function getNotificationIcon(type: Notification['type']) {
		switch (type) {
			case 'warning':
				return AlertTriangle;
			case 'error':
				return XCircle;
			case 'success':
				return CheckCircle;
			default:
				return Info;
		}
	}

	function getNotificationColor(type: Notification['type']) {
		switch (type) {
			case 'warning':
				return 'variant-filled-warning';
			case 'error':
				return 'variant-filled-error';
			case 'success':
				return 'variant-filled-success';
			default:
				return 'variant-filled-primary';
		}
	}
</script>

<!-- Disclaimer Banner - Bottom Overlay -->
{#if showDisclaimer}
	<div
		class="fixed bottom-0 left-0 right-0 z-50 border-t-2 border-orange-400 bg-orange-100 shadow-lg"
		transition:fly={{ y: 100, duration: 300 }}
	>
		<div class="flex items-center gap-3 p-3">
			<AlertTriangle class="h-5 w-5 text-orange-600" />
			<div class="flex-1">
				<span class="text-sm text-orange-800">
					<strong>Disclaimer:</strong> This sample dapp is intended exclusively for experimental purposes.
					You are advised not to use this dapp for storing your critical data such as keys or passwords.
				</span>
			</div>
			<button
				class="rounded p-1 text-orange-600 transition-colors hover:text-orange-800"
				onclick={dismissDisclaimer}
				aria-label="Dismiss disclaimer"
			>
				<X class="h-4 w-4" />
			</button>
		</div>
	</div>
{/if}

<!-- Notification Stack -->
<div class="fixed right-4 top-4 z-40 max-w-sm space-y-2">
	{#each notifications.state as notification (notification.id)}
		<div
			class="alert {getNotificationColor(notification.type)} shadow-lg"
			transition:fly={{ x: 300, duration: 300 }}
		>
			<svelte:component this={getNotificationIcon(notification.type)} class="h-5 w-5" />
			<div class="alert-message flex-1">
				<h4 class="font-semibold">{notification.title}</h4>
				<p class="text-sm opacity-90">{notification.message}</p>
			</div>
			{#if notification.isDismissible}
				<div class="alert-actions">
					<button
						class="variant-soft btn-icon"
						onclick={() => chatUIActions.dismissNotification(notification.id)}
						aria-label="Dismiss notification"
					>
						<X class="h-4 w-4" />
					</button>
				</div>
			{/if}
		</div>
	{/each}
</div>
