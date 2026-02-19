<script lang="ts">
	import { Download, File } from 'lucide-svelte';
	import Button from './ui/Button.svelte';
	import type { Message, User } from '../types';
	import * as base64 from 'base64-js';

	let {
		message,
		sender = null,
		isOwnMessage = false,
		showAvatar = true,
		showTimestamp = true,
		isGroupChat = false
	}: {
		message: Message;
		sender: User | null;
		isOwnMessage: boolean;
		showAvatar: boolean;
		showTimestamp: boolean;
		isGroupChat: boolean;
	} = $props();

	function formatTime(date: Date): string {
		return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
	}

	function formatFileSize(bytes: number): string {
		if (bytes === 0) return '0 B';
		const k = 1024;
		const sizes = ['B', 'KB', 'MB', 'GB'];
		const i = Math.floor(Math.log(bytes) / Math.log(k));
		return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
	}

	function downloadFile() {
		if (!message.fileData) return;

		const blob = new Blob([new Uint8Array(message.fileData.data)], { type: message.fileData.type });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = message.fileData.name;
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		URL.revokeObjectURL(url);
	}

	function isImageFile(type: string): boolean {
		return type.startsWith('image/');
	}

	// Convert emoji shortcodes to actual emojis (simple implementation)
	function parseEmojis(text: string): string {
		const emojiMap: { [key: string]: string } = {
			':smile:': '😊',
			':heart:': '❤️',
			':thumbs_up:': '👍',
			':fire:': '🔥',
			':rocket:': '🚀',
			':check:': '✅',
			':x:': '❌',
			':warning:': '⚠️',
			':info:': 'ℹ️',
			':question:': '❓',
			':exclamation:': '❗',
			':lock:': '🔒',
			':unlock:': '🔓',
			':key:': '🔑'
		};

		let result = text;
		for (const [shortcode, emoji] of Object.entries(emojiMap)) {
			result = result.replace(new RegExp(shortcode, 'g'), emoji);
		}
		return result;
	}

	// Generate a consistent color for a user based on their name
	function getUserColor(userName: string): string {
		if (!userName) return 'bg-gray-500';

		// Predefined color palette for better visual consistency
		const colors = [
			'bg-purple-500',
			'bg-blue-500',
			'bg-green-500',
			'bg-yellow-500',
			'bg-red-500',
			'bg-indigo-500',
			'bg-pink-500',
			'bg-teal-500',
			'bg-orange-500',
			'bg-cyan-500',
			'bg-lime-500',
			'bg-rose-500'
		];

		// Simple hash function for consistency
		let hash = 0;
		for (let i = 0; i < userName.length; i++) {
			hash = userName.charCodeAt(i) + ((hash << 5) - hash);
		}
		const index = Math.abs(hash) % colors.length;
		return colors[index];
	}

	// Get message bubble color classes
	function getMessageBubbleClasses(): string {
		if (isOwnMessage) {
			return 'own-message';
		} else if (isGroupChat && sender) {
			return `other-message group-message ${getUserColor(sender.name)}`;
		} else {
			return 'other-message';
		}
	}
</script>

<div
	class="message-container flex gap-3 px-4 py-2 {isOwnMessage ? 'flex-row-reverse' : 'flex-row'}"
>
	<!-- Avatar -->
	{#if showAvatar && !isOwnMessage}
		<div
			class="avatar bg-primary-500 flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full text-sm"
		>
			{sender?.avatar || '👤'}
		</div>
	{:else if showAvatar && isOwnMessage}
		<div class="w-8"></div>
	{/if}

	<!-- Message content -->
	<div class="message-content max-w-[70%] {isOwnMessage ? 'text-right' : 'text-left'}">
		<!-- Sender name (for group chats when not own message) -->
		{#if !isOwnMessage && sender && showAvatar}
			<div class="text-surface-600-300-token mb-1 text-xs font-medium">
				{sender.name}
			</div>
		{/if}

		<!-- Message bubble -->
		<div
			class="message-bubble {getMessageBubbleClasses()} inline-block max-w-full break-words rounded-2xl px-3 py-2"
		>
			{#if message.fileData === undefined}
				<!-- eslint-disable-next-line svelte/no-at-html-tags -->
				<p class="whitespace-pre-wrap text-sm">{@html parseEmojis(message.content)}</p>
			{:else if message.fileData !== undefined}
				<div class="file-message">
					{#if isImageFile(message.fileData.type)}
						<div class="image-preview mb-2">
							<img
								src="data:{message.fileData.type};base64,{base64.fromByteArray(message.fileData.data)}"
								alt={message.fileData.name}
								class="h-auto max-w-full rounded-lg"
								style="max-height: 300px;"
							/>
						</div>
					{:else}
						<div class="file-icon mb-2">
							<File class="text-surface-600-300-token mx-auto h-8 w-8" />
						</div>
					{/if}

					<div class="file-info bg-surface-100-800-token rounded p-2">
						<div class="flex items-center justify-between">
							<div class="min-w-0 flex-1">
								<p class="truncate text-sm font-medium">{message.fileData.name}</p>
								<p class="text-xs">
									{formatFileSize(message.fileData.size)}
								</p>
							</div>
							<Button
								variant="ghost"
								size="sm"
								class="ml-2"
								onclick={downloadFile}
								aria-label="Download file"
							>
								<Download class="h-4 w-4" />
							</Button>
						</div>
					</div>
				</div>
			{/if}
		</div>

		<!-- Timestamp and status -->
		{#if showTimestamp}
			<div
				class="message-meta text-surface-600-300-token mt-1 text-xs {isOwnMessage
					? 'text-right'
					: 'text-left'}"
			>
				<span>{formatTime(message.timestamp)}</span>
				<span class="ml-1">🔒</span>
				<span class="ml-1 opacity-70"
					>vetKeyEpoch
					{message.vetkeyEpoch} SymmRatchetEpoch {message.symmetricRatchetEpoch}</span
				>
			</div>
		{/if}
	</div>
</div>

<style>
	.message-bubble.own-message {
		background: var(--color-primary-600);
		color: white;
		border: 1px solid var(--color-primary-700);
	}

	.message-bubble.other-message {
		background: var(--color-surface-200);
		color: var(--color-surface-900);
	}

	:global(.dark) .message-bubble.other-message {
		background: var(--color-surface-700);
		color: var(--color-surface-100);
	}

	/* Group chat message colors */
	.message-bubble.group-message {
		color: white !important;
		border: 1px solid rgba(255, 255, 255, 0.2);
	}

	/* User-specific colors for group chats */
	.message-bubble.bg-purple-500 {
		background: #8b5cf6;
	}
	.message-bubble.bg-blue-500 {
		background: #3b82f6;
	}
	.message-bubble.bg-green-500 {
		background: #10b981;
	}
	.message-bubble.bg-yellow-500 {
		background: #f59e0b;
	}
	.message-bubble.bg-red-500 {
		background: #ef4444;
	}
	.message-bubble.bg-indigo-500 {
		background: #6366f1;
	}
	.message-bubble.bg-pink-500 {
		background: #ec4899;
	}
	.message-bubble.bg-teal-500 {
		background: #14b8a6;
	}
	.message-bubble.bg-orange-500 {
		background: #f97316;
	}
	.message-bubble.bg-cyan-500 {
		background: #06b6d4;
	}
	.message-bubble.bg-lime-500 {
		background: #84cc16;
	}
	.message-bubble.bg-rose-500 {
		background: #f43f5e;
	}

	/* Dark mode variants */
	:global(.dark) .message-bubble.bg-purple-500 {
		background: #7c3aed;
	}
	:global(.dark) .message-bubble.bg-blue-500 {
		background: #2563eb;
	}
	:global(.dark) .message-bubble.bg-green-500 {
		background: #059669;
	}
	:global(.dark) .message-bubble.bg-yellow-500 {
		background: #d97706;
	}
	:global(.dark) .message-bubble.bg-red-500 {
		background: #dc2626;
	}
	:global(.dark) .message-bubble.bg-indigo-500 {
		background: #4f46e5;
	}
	:global(.dark) .message-bubble.bg-pink-500 {
		background: #db2777;
	}
	:global(.dark) .message-bubble.bg-teal-500 {
		background: #0d9488;
	}
	:global(.dark) .message-bubble.bg-orange-500 {
		background: #ea580c;
	}
	:global(.dark) .message-bubble.bg-cyan-500 {
		background: #0891b2;
	}
	:global(.dark) .message-bubble.bg-lime-500 {
		background: #65a30d;
	}
	:global(.dark) .message-bubble.bg-rose-500 {
		background: #e11d48;
	}

	.file-message {
		min-width: 200px;
	}

	.message-container {
		transition: all 0.2s ease;
		margin: 4px 0;
		border-radius: 8px;
	}

	.message-container:hover {
		background: var(--color-surface-100);
	}

	:global(.dark) .message-container:hover {
		background: var(--color-surface-800);
	}
</style>
