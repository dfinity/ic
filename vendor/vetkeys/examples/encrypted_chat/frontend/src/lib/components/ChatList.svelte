<script lang="ts">
	import { chats, selectedChatId, chatUIActions } from '../stores/chat.svelte';
	import ChatListItem from './ChatListItem.svelte';
	import UserProfile from './UserProfile.svelte';
	import Button from './ui/Button.svelte';
	import NewChatModal from './NewChatModal.svelte';
	import { chatIdToString, chatIdFromString } from '$lib/utils';

	let showNewChat = $state(false);

	function handleSelect(e: CustomEvent<string>) {
		const chatId = e.detail;
		chatUIActions.selectChat(chatIdFromString(chatId));
	}
</script>

<div class="chat-list glass-effect flex h-full flex-col border-r border-white/20 backdrop-blur-xl">
	<!-- User Profile -->
	<UserProfile />

	<!-- Chat List Header -->
	<div class="border-b border-white/10 p-6">
		<h2
			class="bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-xl font-bold text-transparent"
		>
			Chats
		</h2>
		<p class="mt-1 text-sm font-medium text-gray-500">
			{chats.state.length} conversation{chats.state.length !== 1 ? 's' : ''}
		</p>
		<div class="mt-3 flex gap-2">
			<Button size="sm" variant="filled" onclick={() => (showNewChat = true)}>New Chat</Button>
		</div>
	</div>

	<!-- Chat List -->
	<div class="scrollbar-thin flex-1 overflow-y-auto p-2">
		{#each chats.state as chat (chat.idStr)}
			<ChatListItem
				{chat}
				isSelected={
				selectedChatId.state
					? chatIdToString(selectedChatId.state) === chat.idStr
					: false}
				on:select={handleSelect}
			/>
		{:else}
			<div class="p-8 text-center text-surface-600-500">
				<p class="text-lg mb-2">No chats yet</p>
				<p class="text-sm">Your conversations will appear here</p>
			</div>
		{/each}
	</div>
</div>

<NewChatModal bind:show={showNewChat} />

<style>
	.chat-list {
		width: 320px;
		min-width: 280px;
	}

	@media (max-width: 768px) {
		.chat-list {
			width: 50%;
			min-width: 50%;
		}
	}
</style>
