<script lang="ts">
	import { createEventDispatcher } from 'svelte';

	export let show = false;

	const dispatch = createEventDispatcher<{
		select: string;
		close: void;
	}>();

	const emojiCategories = {
		Faces: [
			'😀',
			'😃',
			'😄',
			'😁',
			'😆',
			'😅',
			'😂',
			'🤣',
			'😊',
			'😇',
			'🙂',
			'🙃',
			'😉',
			'😌',
			'😍',
			'🥰',
			'😘',
			'😗',
			'😙',
			'😚',
			'😋',
			'😛',
			'😝',
			'😜',
			'🤪',
			'🤨',
			'🧐',
			'🤓',
			'😎',
			'🤩'
		],
		Hands: [
			'👍',
			'👎',
			'👌',
			'🤌',
			'🤏',
			'✌️',
			'🤞',
			'🤟',
			'🤘',
			'🤙',
			'👈',
			'👉',
			'👆',
			'🖕',
			'👇',
			'☝️',
			'👋',
			'🤚',
			'🖐️',
			'✋',
			'🖖',
			'👏',
			'🙌',
			'🤲',
			'🤝',
			'🙏'
		],
		Objects: [
			'❤️',
			'🧡',
			'💛',
			'💚',
			'💙',
			'💜',
			'🖤',
			'🤍',
			'🤎',
			'💔',
			'❣️',
			'💕',
			'💞',
			'💓',
			'💗',
			'💖',
			'💘',
			'💝',
			'💟',
			'⚡',
			'💥',
			'💫',
			'⭐',
			'🌟',
			'✨',
			'💎',
			'🔥',
			'💯'
		],
		Symbols: [
			'✅',
			'❌',
			'⚠️',
			'🚀',
			'🔒',
			'🔓',
			'🔑',
			'🛡️',
			'⭐',
			'💫',
			'✨',
			'🎯',
			'🏆',
			'🎉',
			'🎊',
			'💡',
			'📢',
			'📣',
			'📯',
			'🔔',
			'🔕',
			'🆕',
			'🆓',
			'🆒',
			'🔥',
			'💯',
			'✔️',
			'❗',
			'❓',
			'ℹ️'
		]
	};

	function selectEmoji(emoji: string) {
		dispatch('select', emoji);
		show = false;
	}

	function closeModal() {
		dispatch('close');
		show = false;
	}

	// Close on outside click
	function handleOutsideClick(event: MouseEvent) {
		const target = event.target as Element;
		if (target && !target.closest('.emoji-picker')) {
			closeModal();
		}
	}
</script>

{#if show}
	<!-- Backdrop -->
	<div
		class="fixed inset-0 z-40 bg-black/25"
		onclick={handleOutsideClick}
		role="button"
		tabindex="-1"
		onkeydown={() => {}}
	></div>

	<!-- Emoji Picker -->
	<div
		class="emoji-picker fixed right-4 bottom-20 z-50 max-w-sm rounded-lg border border-gray-300 bg-white p-4 shadow-xl"
	>
		<div class="mb-4 flex items-center justify-between">
			<h3 class="text-sm font-semibold text-gray-800">Add Emoji</h3>
			<button
				class="flex h-8 w-8 items-center justify-center rounded text-xl text-gray-600 hover:bg-gray-100"
				onclick={closeModal}
				aria-label="Close emoji picker"
			>
				×
			</button>
		</div>

		<div class="emoji-grid max-h-64 overflow-y-auto scrollbar-hide">
			{#each Object.entries(emojiCategories) as [category, emojis] (category)}
				<div class="emoji-category mb-4">
					<h4 class="mb-2 text-xs font-medium text-gray-600">{category}</h4>
					<div class="grid grid-cols-8 gap-1">
						{#each emojis as emoji (emoji)}
							<button
								class="emoji-button flex h-8 w-8 items-center justify-center rounded text-lg transition-colors hover:bg-gray-100"
								onclick={() => selectEmoji(emoji)}
								title={emoji}
							>
								{emoji}
							</button>
						{/each}
					</div>
				</div>
			{/each}
		</div>

		<div class="mt-4 border-t border-gray-200 pt-3">
			<p class="text-xs text-gray-600">
				You can also type emoji shortcodes like <code>:smile:</code>, <code>:heart:</code>,
				<code>:rocket:</code>
			</p>
		</div>
	</div>
{/if}

<style>
	.emoji-picker {
		width: 320px;
		max-height: 400px;
	}

	.emoji-grid {
		scrollbar-width: none; /* Firefox */
		-ms-overflow-style: none; /* IE and Edge */
	}

	.emoji-grid::-webkit-scrollbar {
		display: none; /* Chrome, Safari, Opera */
	}

	.emoji-button:hover {
		transform: scale(1.1);
	}

	code {
		background: #f3f4f6;
		padding: 1px 4px;
		border-radius: 3px;
		font-size: 10px;
	}
</style>
