<script lang="ts">
    import type { Editor } from "typewriter-editor";
    import asRoot from "typewriter-editor/lib/asRoot.js";
    // @ts-expect-error: svelte-icons have some problems with ts declarations
    import BubbleMenu from "typewriter-editor/lib/BubbleMenu.svelte";
    // @ts-expect-error: svelte-icons have some problems with ts declarations
    import Heading from "svelte-icons/fa/FaHeading.svelte";
    // @ts-expect-error: svelte-icons have some problems with ts declarations
    import Bold from "svelte-icons/fa/FaBold.svelte";
    // @ts-expect-error: svelte-icons have some problems with ts declarations
    import Italic from "svelte-icons/fa/FaItalic.svelte";
    // @ts-expect-error: svelte-icons have some problems with ts declarations
    import FaListUl from "svelte-icons/fa/FaListUl.svelte";

    export let editor: Editor;
    export let disabled: boolean = false;

    let classNames: string = "";
    export { classNames as class };

    function focus(el: HTMLElement) {
        el.focus();
    }

    $: editor.enabled = !disabled;
</script>

<BubbleMenu for={null} {editor} let:commands offset={8}>
    <div class="btn-group">
        <button class="btn btn-sm" on:click={commands.header1}>
            <span class="h-6 w-6 p-1"><Heading /></span>
        </button>
        <button class="btn btn-sm" on:click={commands.bulletList}>
            <span class="h-6 w-6 p-1"><FaListUl /></span>
        </button>
        <button class="btn btn-sm" on:click={commands.bold}>
            <span class="h-6 w-6 p-1"><Bold /></span>
        </button>
        <button class="btn btn-sm" on:click={commands.italic}>
            <span class="h-6 w-6 p-1"><Italic /></span>
        </button>
    </div>
</BubbleMenu>

<div
    use:asRoot={editor}
    class="textarea min-h-[16rem] border-base-300 p-4 {classNames} {disabled
        ? 'opacity-50'
        : ''}"
    use:focus
/>

<style>
    .textarea :global(.placeholder) {
        position: relative;
    }
    .textarea :global(.placeholder::before) {
        position: absolute;
        left: 0;
        right: 0;
        opacity: 0.75;
        content: attr(data-placeholder);
    }

    .textarea :global(h1) {
        font-size: 2rem;
        margin-bottom: 12px;
    }
    .textarea :global(ul) {
        list-style: disc;
        padding-left: 24px;
    }
</style>
