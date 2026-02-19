<script lang="ts">
	import { chats, selectedChatId, messages } from '../stores/chat.svelte';
	import MessageBubble from './MessageBubble.svelte';
	import type { Message, User } from '../types';
	import { SvelteDate } from 'svelte/reactivity';
	import { auth, getMyPrincipal } from '$lib/stores/auth.svelte';
	import { chatIdToString } from '$lib/utils';
	import type { ChatId } from '../../declarations/encrypted_chat/encrypted_chat.did';

	let messagesContainer: HTMLDivElement | undefined = $state(undefined);
	let autoScroll = $state(true);

	const selectedChat = $derived(
		selectedChatId.state
			? (chats.state.find(
					(chat) => selectedChatId.state && chat.idStr === chatIdToString(selectedChatId.state)
				) ?? null)
			: null
	);

	const selectedChatMessages = $derived(setSelectedChatMessages());

	// Scroll to bottom when new messages arrive (after DOM updates)
	$effect(() => {
		if (autoScroll && messagesContainer) {
			requestAnimationFrame(() => {
				if (!messagesContainer) return;
				messagesContainer.scrollTop = messagesContainer.scrollHeight;
			});
		}
	});

	$effect(() => {
		console.log(
			'selectedChatMessages',
			selectedChatMessages.map((m) => m.messageId)
		);
	});

	function setSelectedChatMessages(): Message[] {
		if (!selectedChatId.state) return [];
		const selectedChatIdStr = chatIdToString(selectedChatId.state);
		return messages.state[selectedChatIdStr] ?? [];
	}

	// Check if user has scrolled up (disable auto-scroll)
	function handleScroll() {
		if (!messagesContainer) return;

		const { scrollTop, scrollHeight, clientHeight } = messagesContainer;
		const isAtBottom = scrollTop + clientHeight >= scrollHeight - 50;
		autoScroll = isAtBottom;
	}

	function scrollToBottom() {
		if (messagesContainer) {
			requestAnimationFrame(() => {
				if (!messagesContainer) return;
				messagesContainer.scrollTop = messagesContainer.scrollHeight;
				autoScroll = true;
			});
		}
	}

	function getSender(message: Message): User | null {
		if (!selectedChat) return null;

		console.log(
			`getSender: message.senderId=${message.senderId} selectedChat.participants=${JSON.stringify(
				selectedChat.participants
			)}`
		);

		return (
			selectedChat.participants.find((p) => p.principal.toString() === message.senderId) || null
		);
	}

	function isOwnMessage(message: Message): boolean {
		if (auth.state.label !== 'initialized') throw new Error('Unexpectedly not authenticated');
		return message.senderId === getMyPrincipal().toString();
	}

	function shouldShowAvatar(message: Message, index: number): boolean {
		if (isOwnMessage(message)) return false;
		if (index === 0) return true;

		const prevMessage = selectedChatMessages[index - 1];
		return prevMessage.senderId !== message.senderId;
	}

	function shouldShowTimestamp(message: Message, index: number): boolean {
		if (index === selectedChatMessages.length - 1) return true;

		const nextMessage = selectedChatMessages[index + 1];
		const timeDiff = nextMessage.timestamp.getTime() - message.timestamp.getTime();

		// Show timestamp if next message is more than 5 minutes later
		return timeDiff > 5 * 60 * 1000;
	}

	function formatDateSeparator(date: Date): string {
		const today = new SvelteDate();
		const yesterday = new SvelteDate(today);
		yesterday.setDate(yesterday.getDate() - 1);

		if (date.toDateString() === today.toDateString()) {
			return 'Today';
		} else if (date.toDateString() === yesterday.toDateString()) {
			return 'Yesterday';
		} else {
			return date.toLocaleDateString();
		}
	}

	function shouldShowDateSeparator(message: Message, index: number): boolean {
		if (index === 0) return true;

		const prevMessage = selectedChatMessages[index - 1];
		const messageDate = message.timestamp;
		const prevDate = prevMessage.timestamp;

		return messageDate.toDateString() !== prevDate.toDateString();
	}

	// Get participant info for display
	function getParticipantInfo(): string {
		if (!selectedChat) return '';

		if (auth.state.label !== 'initialized') throw new Error('Unexpectedly not authenticated');
		const myPrincipal = auth.state.client.getIdentity().getPrincipal();

		if (selectedChat.type === 'direct') {
			const otherUser = selectedChat.participants.find(
				(p) => p.principal.toString() !== myPrincipal.toString()
			);
			return otherUser ? `This is the beginning of your conversation with ${otherUser.name}` : '';
		}

		return `This is the beginning of the ${selectedChat.name} group chat`;
	}
</script>

<div class="message-history flex min-h-0 flex-1 flex-col">
	{#if selectedChat}
		<div
			bind:this={messagesContainer}
			onscroll={handleScroll}
			class="messages-container scrollbar-thin flex-1 overflow-y-auto"
		>
			{#if selectedChatMessages.length === 0}
				<!-- Empty state -->
				<div
					class="empty-state flex h-full flex-col items-center justify-center p-8 pt-12 text-center"
				>
					<div
						class="avatar bg-primary-500 mb-4 flex h-16 w-16 items-center justify-center rounded-full text-2xl"
					>
						{#if selectedChat.type === 'direct'}
							{selectedChat.participants.find(
								(p) => p.principal.toString() !== getMyPrincipal().toString()
							)?.avatar || '👤'}
						{:else}
							{selectedChat.avatar || '👥'}
						{/if}
					</div>
					<h3 class="mb-2 text-lg font-semibold">
						{#if selectedChat.type === 'direct'}
							{selectedChat.participants.find(
								(p) => p.principal.toString() !== getMyPrincipal().toString()
							)?.name || 'Me'}
						{:else}
							{selectedChat.name}
						{/if}
					</h3>
					<p class="text-surface-600-300-token mb-4 max-w-md">
						{getParticipantInfo()}
					</p>
					{#if selectedChat.disappearingMessagesDuration > 0}
						<div class="alert variant-ghost-warning">
							<span class="text-sm">
								🕐 Messages disappear after {selectedChat.disappearingMessagesDuration} day{selectedChat.disappearingMessagesDuration !==
								1
									? 's'
									: ''}
							</span>
						</div>
					{/if}
				</div>
			{:else}
				<!-- Messages -->
				<div class="messages-list py-4">
					{#each selectedChatMessages as message, index (message.messageId)}
						<!-- Date separator -->
						{#if shouldShowDateSeparator(message, index)}
							<div class="date-separator flex items-center justify-center py-4">
								<div
									class="bg-surface-200-700-token text-surface-600-300-token rounded-full px-3 py-1 text-xs"
								>
									{formatDateSeparator(message.timestamp)}
								</div>
							</div>
						{/if}

						<!-- Message -->
						<div class="message-enter">
							<MessageBubble
								{message}
								sender={getSender(message)}
								isOwnMessage={isOwnMessage(message)}
								showAvatar={shouldShowAvatar(message, index)}
								showTimestamp={shouldShowTimestamp(message, index)}
								isGroupChat={selectedChat?.type === 'group'}
							/>
						</div>
					{/each}
				</div>
			{/if}
		</div>

		<!-- Scroll to bottom button -->
		{#if !autoScroll}
			<div class="scroll-to-bottom absolute bottom-20 right-4">
				<button
					class="variant-filled-primary btn rounded-full"
					onclick={scrollToBottom}
					title="Scroll to bottom"
				>
					↓
				</button>
			</div>
		{/if}
	{:else}
		<!-- No chat selected -->
		<div class="no-chat-selected flex h-full flex-col items-center justify-center p-8 text-center">
			<div
				class="bg-surface-200-700-token mb-6 flex h-24 w-24 items-center justify-center rounded-full text-4xl"
			>
				💬
			</div>
			<h2 class="mb-2 text-xl font-bold">Welcome to VetKeys Chat</h2>
			<p class="text-surface-600-300-token mb-6 max-w-md">
				Select a conversation from the sidebar to start chatting securely with end-to-end
				encryption.
			</p>
			<div class="text-surface-600-300-token space-y-2 text-sm">
				<div class="flex items-center gap-2">
					<span>🔒</span>
					<span>End-to-end encrypted messages</span>
				</div>
				<div class="flex items-center gap-2">
					<span>🔑</span>
					<span>Automatic key rotation</span>
				</div>
				<div class="flex items-center gap-2">
					<span>⏰</span>
					<span>Disappearing messages support</span>
				</div>
			</div>
		</div>
	{/if}
</div>

<style>
	.message-history {
		position: relative;
	}

	.messages-container {
		scroll-behavior: smooth;
	}

	.scroll-to-bottom {
		z-index: 10;
	}

	.date-separator {
		margin: 8px 0;
	}

	:global(.dark) .empty-state,
	:global(.dark) .no-chat-selected {
		background: var(--color-surface-900);
	}
</style>
