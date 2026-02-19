<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { Send, Paperclip, Smile, X } from 'lucide-svelte';
	import EmojiPicker from './EmojiPicker.svelte';
	import Button from './ui/Button.svelte';
	import Card from './ui/Card.svelte';
	import type { FileUpload } from '../types';

	export let disabled = false;
	export let placeholder = 'Type a message...';

	const dispatch = createEventDispatcher<{
		send: { content: string; file?: FileUpload };
	}>();

	let messageText = '';
	let showEmojiPicker = false;
	let fileInput: HTMLInputElement;
	let selectedFile: FileUpload | null = null;

	const MAX_FILE_SIZE_1_MB = 1_000 * 1024; // 100KB

	function handleSend() {
		const content = messageText.trim();
		if (!content && !selectedFile) return;

		dispatch('send', {
			content: content || (selectedFile ? `📎 ${selectedFile.file.name}` : ''),
			file: selectedFile || undefined
		});

		messageText = '';
		selectedFile = null;
		showEmojiPicker = false;
	}

	function handleKeydown(event: KeyboardEvent) {
		if (event.key === 'Enter' && !event.shiftKey) {
			event.preventDefault();
			handleSend();
		}
	}

	function handleFileSelect() {
		fileInput.click();
	}

	function handleFileChange(event: Event) {
		const target = event.target as HTMLInputElement;
		const file = target.files?.[0];

		if (!file) return;

		if (file.size > MAX_FILE_SIZE_1_MB) {
			selectedFile = {
				file,
				isValid: false,
				error: `File too large. Maximum size is ${MAX_FILE_SIZE_1_MB / (1024 * 1024)}MB.`
			};
			return;
		}

		selectedFile = {
			file,
			isValid: true
		};

		// Generate preview for images
		if (file.type.startsWith('image/')) {
			const reader = new FileReader();
			reader.onload = (e) => {
				if (selectedFile) {
					selectedFile.preview = e.target?.result as string;
				}
			};
			reader.readAsDataURL(file);
		}
	}

	function removeFile() {
		selectedFile = null;
		if (fileInput) {
			fileInput.value = '';
		}
	}

	function handleEmojiSelect(event: CustomEvent<string>) {
		const emoji = event.detail;
		messageText = messageText + emoji;
		showEmojiPicker = false;

		// Focus back on input
		const textarea = document.querySelector('.message-input') as HTMLTextAreaElement;
		if (textarea) {
			textarea.focus();
		}
	}

	function formatFileSize(bytes: number): string {
		if (bytes === 0) return '0 B';
		const k = 1024;
		const sizes = ['B', 'KB', 'MB', 'GB'];
		const i = Math.floor(Math.log(bytes) / Math.log(k));
		return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
	}
</script>

<div class="glass-effect border-t border-white/10 p-6 backdrop-blur-xl">
	<!-- File preview -->
	{#if selectedFile}
		<Card padding="sm" class="mb-3">
			<div class="flex items-start gap-3">
				{#if selectedFile.preview}
					<img src={selectedFile.preview} alt="Preview" class="h-16 w-16 rounded object-cover" />
				{:else}
					<div class="bg-surface-200-700 flex h-16 w-16 items-center justify-center rounded">
						<Paperclip class="h-6 w-6" />
					</div>
				{/if}

				<div class="min-w-0 flex-1">
					<p class="truncate text-sm font-medium">{selectedFile.file.name}</p>
					<p class="text-surface-500-400 text-xs">{formatFileSize(selectedFile.file.size)}</p>
					{#if !selectedFile.isValid && selectedFile.error}
						<p class="text-error-500 mt-1 text-xs">{selectedFile.error}</p>
					{/if}
				</div>

				<Button variant="ghost" size="sm" onclick={removeFile} aria-label="Remove file">
					<X class="h-4 w-4" />
				</Button>
			</div>
		</Card>
	{/if}

	<!-- Input area -->
	<div class="flex items-end gap-2">
		<!-- File input -->
		<input
			type="file"
			bind:this={fileInput}
			onchange={handleFileChange}
			accept="image/*,.pdf,.doc,.docx,.txt,.zip"
			style="display: none;"
		/>

		<!-- Message input -->
		<div class="relative flex-1">
			<textarea
				bind:value={messageText}
				onkeydown={handleKeydown}
				{placeholder}
				{disabled}
				rows="1"
				class="message-input w-full resize-none rounded-xl border border-gray-200/50 bg-white/80 px-4 py-3 pr-20 text-sm shadow-lg backdrop-blur-sm focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 focus:outline-none"
				style="min-height: 44px; max-height: 120px;"
			></textarea>

			<!-- Attachment and Emoji buttons -->
			<div class="absolute top-1/2 right-2 flex -translate-y-1/2 items-center gap-1">
				<!-- Attachment button -->
				<Button
					variant="ghost"
					size="sm"
					onclick={handleFileSelect}
					{disabled}
					title="Attach file (max {MAX_FILE_SIZE_1_MB / (1024 * 1024)}MB)"
					aria-label="Attach file"
				>
					<Paperclip class="h-4 w-4" />
				</Button>

				<!-- Emoji button -->
				<Button
					variant="ghost"
					size="sm"
					onclick={() => (showEmojiPicker = !showEmojiPicker)}
					{disabled}
					aria-label="Add emoji"
				>
					<Smile class="h-4 w-4" />
				</Button>
			</div>
		</div>

		<!-- Send button -->
		<div class="pb-2">
			<Button
				variant="filled"
				onclick={handleSend}
				disabled={disabled ||
					(!messageText.trim() && !selectedFile) ||
					!!(selectedFile && selectedFile.isValid === false)}
				aria-label="Send message"
			>
				<Send class="h-5 w-5" />
			</Button>
		</div>
	</div>
</div>

<!-- Emoji Picker -->
<EmojiPicker
	bind:show={showEmojiPicker}
	on:select={handleEmojiSelect}
	on:close={() => (showEmojiPicker = false)}
/>
