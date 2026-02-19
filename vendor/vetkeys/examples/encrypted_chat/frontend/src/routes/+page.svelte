<script lang="ts">
	import { onMount } from 'svelte';
	import ChatList from '$lib/components/ChatList.svelte';
	import ChatInterface from '$lib/components/ChatInterface.svelte';
	import {
		isLoading,
		selectedChatId,
		chatUIActions,
		initVetKeyReactions
	} from '$lib/stores/chat.svelte';
	import Hero from '$lib/components/Hero.svelte';
	import { auth } from '$lib/stores/auth.svelte';

	let isMobile = $state(false);
	let showMobileChatList = $derived(isMobile && selectedChatId);

	onMount(() => {
		// Check if mobile
		const checkMobile = () => {
			isMobile = window.innerWidth < 768;
		};

		checkMobile();
		window.addEventListener('resize', checkMobile);

		return () => {
			window.removeEventListener('resize', checkMobile);
		};
	});

	onMount(() => {
		const interval = setInterval(() => {
			(async () => {
				if (auth.state.label === 'initialized') {
					await chatUIActions.refreshChats();
					await chatUIActions.loadChatMessages();
				}
			})().catch(console.error);
		}, 500);

		return () => clearInterval(interval);
	});

	onMount(() => {
		initVetKeyReactions();
	});

	function handleMobileBackToChatList() {
		showMobileChatList = true;
	}
</script>

<svelte:head>
	<title>Encrypted Chat using vetKeys</title>
	<meta name="description" content="Secure encrypted chat application using VetKeys" />
</svelte:head>

{#if auth.state.label !== 'initialized'}
	<Hero />
{:else if isLoading.state}
	<!-- Loading state -->
	<div
		class="loading-screen flex h-full items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100"
	>
		<div class="animate-fade-in text-center">
			<div
				class="mx-auto mb-6 h-16 w-16 animate-spin rounded-full border-4 border-blue-500 border-t-transparent shadow-lg"
			></div>
			<h2
				class="mb-3 bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-xl font-bold text-transparent"
			>
				Loading vetKeys Chat
			</h2>
			<p class="font-medium text-gray-600">
				Initializing secure communication...
			</p>
			<div class="mt-4 flex justify-center space-x-1">
				<div class="h-2 w-2 animate-bounce rounded-full bg-blue-500"></div>
				<div
					class="h-2 w-2 animate-bounce rounded-full bg-blue-500"
					style="animation-delay: 0.1s"
				></div>
				<div
					class="h-2 w-2 animate-bounce rounded-full bg-blue-500"
					style="animation-delay: 0.2s"
				></div>
			</div>
		</div>
	</div>
{:else}
	<!-- Main chat interface -->
	<div
		class="chat-container flex h-full bg-gradient-to-br from-gray-50 via-blue-50 to-indigo-50"
	>
		<!-- Chat List Sidebar (Desktop) or Full Screen (Mobile) -->
		<div
			class="chat-list-wrapper width-full {isMobile
				? showMobileChatList
					? 'block'
					: 'hidden'
				: 'block'}"
		>
			<ChatList />
		</div>

		<!-- Chat Interface (Desktop) or Full Screen when chat selected (Mobile) -->
		<div
			class="chat-interface-wrapper flex-1 {isMobile
				? showMobileChatList
					? 'hidden'
					: 'block'
				: 'block'}"
		>
			<ChatInterface {isMobile} onMobileBack={handleMobileBackToChatList} />
		</div>
	</div>
{/if}

<style lang="postcss">
	@reference "tailwindcss";
</style>
