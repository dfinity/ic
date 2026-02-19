<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { Clock, Users, User, Loader2, AlertCircle, CheckCircle } from 'lucide-svelte';
	import type { Chat } from '../types';

	export let chat: Chat;
	export let isSelected = false;

	const dispatch = createEventDispatcher<{
		select: string;
	}>();

	function handleClick() {
		dispatch('select', chat.idStr);
	}

	function getDisplayName(): string {
		return chat.name;
	}

	function getStatusColor(): string {
		if (!chat.isReady) return 'status-error';
		if (chat.isUpdating) return 'status-updating';
		return 'status-ready';
	}

	function getStatusIcon() {
		if (!chat.isReady) return AlertCircle;
		if (chat.isUpdating) return Loader2;
		return CheckCircle;
	}
</script>

<button
	class="chat-item w-full overflow-hidden p-3 text-left transition-all duration-200 {isSelected
		? 'selected'
		: 'hover:bg-surface-100-800-token'}"
	onclick={handleClick}
>
	<div class="flex items-center gap-3">
		<!-- Avatar -->
		<div class="relative">
			<div
				class="avatar from-primary-500 to-primary-600 flex h-12 w-12 items-center justify-center rounded-full bg-gradient-to-br text-lg text-white shadow-sm"
			>
		<!-- TODO -->
			</div>
			<!-- Status indicator -->
			<div class="absolute -bottom-1 -right-1">
				<div
					class="h-4 w-4 rounded-full {getStatusColor()} flex items-center justify-center shadow-sm"
				>
					<svelte:component this={getStatusIcon()} class="h-2.5 w-2.5 text-white" />
				</div>
			</div>
		</div>

		<!-- Chat info -->
		<div class="min-w-0 flex-1 overflow-hidden">
			<div class="mb-1 flex items-center justify-between">
				<h3 class="text-surface-900-100-token truncate text-sm font-semibold">
					{getDisplayName()}
				</h3>
				<div class="flex items-center gap-2">
					{#if chat.type === 'group'}
						<Users class="text-surface-500-400-token h-3 w-3" />
					{:else}
						<User class="text-surface-500-400-token h-3 w-3" />
					{/if}
				</div>
			</div>

			<div class="flex items-center justify-between">
				<p class="text-surface-600-300-token truncate text-sm">
					{#if chat.lastMessage}
						{chat.lastMessage.content}
					{:else}
						No messages yet
					{/if}
				</p>

			{#if chat.unreadCount > 0}
				<div
					class="unread-badge flex h-5 min-w-[20px] items-center justify-center rounded-full px-2 py-1 text-xs text-white"
				>
					{chat.unreadCount > 99 ? '99+' : chat.unreadCount}
				</div>
			{/if}
			</div>

			<!-- Chat status info -->
			<div class="mt-1 flex items-center gap-2">
				{#if chat.disappearingMessagesDuration > 0}
					<div
						class="status-chip flex items-center gap-1 rounded-full bg-gradient-to-r from-amber-100 to-amber-200 px-2 py-0.5 text-xs text-amber-800 shadow-sm"
					>
						<Clock class="h-3 w-3" />
						{chat.disappearingMessagesDuration}d
					</div>
				{/if}
			</div>
		</div>
	</div>
</button>

<style>
	.chat-item {
		margin: 2px 0px;
		padding: 12px 16px;
		border-radius: 12px;
		border: 1px solid var(--color-surface-200);
		background: var(--color-surface-50);
		transition: all 0.2s ease;
		position: relative;
	}

	.chat-item:hover {
		background: var(--color-surface-100);
		border-color: var(--color-surface-300);
		box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
		transform: translateY(-1px);
	}

	:global(.dark) .chat-item {
		background: var(--color-surface-800);
		border-color: var(--color-surface-700);
	}

	:global(.dark) .chat-item:hover {
		background: var(--color-surface-700);
		border-color: var(--color-surface-600);
		box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
	}

	.chat-item.selected {
		background: linear-gradient(135deg, var(--color-primary-50), var(--color-primary-100));
		border-color: var(--color-primary-200);
		border-left: 4px solid var(--color-primary-500);
		box-shadow: 0 4px 16px rgba(59, 130, 246, 0.15);
		transform: translateY(-1px);
	}

	:global(.dark) .chat-item.selected {
		background: linear-gradient(135deg, var(--color-primary-900), var(--color-primary-800));
		border-color: var(--color-primary-700);
		box-shadow: 0 4px 16px rgba(59, 130, 246, 0.25);
	}

	.status-ready {
		background: linear-gradient(135deg, #10b981, #059669);
	}

	.status-updating {
		background: linear-gradient(135deg, #f59e0b, #d97706);
		animation: pulse 2s infinite;
	}

	.status-error {
		background: linear-gradient(135deg, #ef4444, #dc2626);
	}

	@keyframes pulse {
		0%,
		100% {
			opacity: 1;
		}
		50% {
			opacity: 0.7;
		}
	}

	.unread-badge {
		font-size: 10px;
		line-height: 1;
		font-weight: 700;
		background: linear-gradient(135deg, #3b82f6, #2563eb);
		box-shadow:
			0 2px 8px rgba(59, 130, 246, 0.4),
			0 0 0 2px rgba(255, 255, 255, 0.9);
		animation: badge-pulse 2s ease-in-out infinite;
	}

	:global(.dark) .unread-badge {
		background: linear-gradient(135deg, #60a5fa, #3b82f6);
		box-shadow:
			0 2px 8px rgba(59, 130, 246, 0.6),
			0 0 0 2px rgba(0, 0, 0, 0.3);
	}

	@keyframes badge-pulse {
		0%,
		100% {
			transform: scale(1);
		}
		50% {
			transform: scale(1.05);
			filter: brightness(1.1);
		}
	}

	.status-chip {
		font-size: 10px;
		line-height: 1;
		font-weight: 500;
	}

	:global(.dark) .status-chip {
		background: linear-gradient(135deg, #92400e, #78350f);
		color: #fef3c7;
	}

	.avatar {
		transition: transform 0.2s ease;
	}

	.chat-item:hover .avatar {
		transform: scale(1.05);
	}
</style>
