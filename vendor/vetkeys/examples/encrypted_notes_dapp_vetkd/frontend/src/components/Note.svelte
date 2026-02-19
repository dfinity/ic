<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  import { NoteModel, summarize } from '../lib/note';

  export let note: NoteModel;

  const dispatch = createEventDispatcher<{
    tagclick: string;
  }>();

  $: contentSummary = summarize(note);
</script>

<a
  class="p-4 rounded-md border border-base-300 dark:border-base-300  bg-base dark:bg-base-100 hover:-translate-y-2 transition-transform"
  href={`/notes/edit/${note.id}`}
>
  <div class="pointer-events-none">
    <h2 class="text-lg font-bold mb-2 line-clamp-3">
      {#if note.title}
        {note.title}
      {:else}
        <span class="text-gray-500">Unnamed note</span>
      {/if}
    </h2>
    {contentSummary}
    {#if note.tags.length > 0}
      <div class="mt-4 ">
        {#each note.tags as tag}
          <button
            class="btn btn-outline btn-sm mr-2 mb-2 pointer-events-auto"
            on:click={(e) => {
              dispatch('tagclick', tag);
              e.stopPropagation();
              e.preventDefault();
            }}
          >
            {tag}
          </button>
        {/each}
      </div>
    {/if}
  </div>
</a>
