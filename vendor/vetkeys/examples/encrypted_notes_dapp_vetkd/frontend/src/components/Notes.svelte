<script lang="ts">
  import type { NoteModel } from '../lib/note';

  import { notesStore } from '../store/notes';
  import Header from './Header.svelte';
  import Note from './Note.svelte';
  import Spinner from './Spinner.svelte';

  let filter = '';
  let filteredNotes: NoteModel[];

  $: searchIndex =
    $notesStore.state === 'loaded'
      ? $notesStore.list.map((note) => {
          const div = document.createElement('div');
          div.innerHTML = note.content;
          const content = div.innerText;
          return [content, ...note.tags].join('/#delimiter#/').toLowerCase();
        })
      : [];

  $: {
    if ($notesStore.state === 'loaded') {
      if (filter.length > 0) {
        filteredNotes = $notesStore.list.filter((_, i) => {
          return searchIndex[i].includes(filter.toLowerCase());
        });
      } else {
        filteredNotes = $notesStore.list;
      }
    }
  }
</script>

<Header>
  <span slot="title"> Your notes </span>
  <svelte:fragment slot="actions">
    {#if $notesStore.state === 'loaded' && $notesStore.list.length > 0}
      <a class="btn btn-primary" href="/">New Note</a>
    {/if}
  </svelte:fragment>
</Header>
<main class="p-4">
  {#if $notesStore.state === 'loading'}
    <Spinner />
    Loading notes...
  {:else if $notesStore.state === 'loaded'}
    {#if $notesStore.list.length > 0}
      <div class="mb-6">
        <input
          bind:value={filter}
          class="bg-transparent text-base {filter.length > 0
            ? 'border'
            : ''} rounded-lg h-8 px-3 "
          placeholder="Filter notes..."
        />
      </div>

      <div
        class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 max-w-7xl"
      >
        {#each filteredNotes as note (note.id)}
          <Note {note} on:tagclick={(e) => (filter = e.detail)} />
        {/each}
      </div>
    {:else}
      <div class="text-center pt-8 italic">You don't have any notes.</div>
      <div class="text-center pt-8 ">
        <a href="/" class="btn btn-primary">Add a note</a>
      </div>
    {/if}
  {:else if $notesStore.state === 'error'}
    <div class="alert alert-error">Could not load notes.</div>
  {/if}
</main>
