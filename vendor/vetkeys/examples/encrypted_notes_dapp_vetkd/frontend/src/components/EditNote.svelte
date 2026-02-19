<script lang="ts">
  import { navigateTo } from 'svelte-router-spa';
  import type { CurrentRoute } from 'svelte-router-spa/types/components/route';
  import { Editor, placeholder } from 'typewriter-editor';
  import { extractTitle, NoteModel } from '../lib/note';
  import { notesStore, refreshNotes, updateNote, addUser, removeUser } from '../store/notes';
  import Header from './Header.svelte';
  import NoteEditor from './NoteEditor.svelte';
  import TagEditor from './TagEditor.svelte';
  import SharingEditor from './SharingEditor.svelte';
  import Trash from 'svelte-icons/fa/FaTrash.svelte';
  import { addNotification, showError } from '../store/notifications';
  import { auth } from '../store/auth';
  import Spinner from './Spinner.svelte';
  import DOMPurify from 'isomorphic-dompurify';

  export let currentRoute: CurrentRoute;

  let editedNote: NoteModel;
  let editor: Editor;
  let updating = false;
  let deleting = false;
  let ownedByMe;

  async function save() {
    if ($auth.state !== 'initialized') {
      return;
    }
    const html = DOMPurify.sanitize(editor.getHTML());
    updating = true;
    await updateNote(
      {
        ...editedNote,
        content: html,
        title: extractTitle(html),
        updatedAt: Date.now(),
      },
      $auth.actor,
      $auth.crypto
    )
      .catch((e) => {
        showError(e, 'Could not update note.');
      })
      .finally(() => {
        updating = false;
      });

    addNotification({ type: 'success', message: 'Note saved successfully' });

    await refreshNotes($auth.actor, $auth.crypto).catch((e) =>
      showError(e, 'Could not refresh notes.')
    );
  }

  async function deleteNote() {
    if ($auth.state !== 'initialized') {
      return;
    }
    deleting = true;
    await $auth.actor.delete_note(editedNote.id).catch((e) => {
      deleting = false;
      showError(e, 'Could not delete note.');
    });

    await refreshNotes($auth.actor, $auth.crypto)
      .catch((e) => showError(e, 'Could not refresh notes.'))
      .finally(() => {
        addNotification({
          type: 'success',
          message: 'Note deleted successfully',
        });
        navigateTo('/notes');
      });
  }

  function addTag(tag: string) {
    editedNote.tags = [...editedNote.tags, tag];
  }

  function removeTag(tag: string) {
    editedNote.tags = editedNote.tags.filter((t) => t !== tag);
  }

  function selfPrincipalString(): string {
    if ($auth.state !== 'initialized') {
      throw new Error('expected the auth.state to be initialized');
    }
    return $auth.client.getIdentity().getPrincipal().toString();
  }

  $: {
    if ($notesStore.state === 'loaded' && !editedNote) {
      const note = $notesStore.list.find(
        (note) => note.id.toString() === currentRoute.namedParams.id
      );

      if (note) {
        editedNote = { ...note };
        editor = new Editor({
          modules: {
            placeholder: placeholder('Start typing...'),
          },
          html: editedNote.content,
        });
        ownedByMe = note.owner == selfPrincipalString();
      }
    }
  }
</script>

{#if editedNote}
  <Header>
    <span slot="title"> Edit note </span>
    <button
      slot="actions"
      class="btn btn-ghost {deleting ? 'loading' : ''} {!ownedByMe ? 'hidden' : ''}"
      on:click={deleteNote}
      disabled={updating || deleting}
    >
      {#if !deleting}
        <span class="w-6 h-6 p-1"><Trash /></span>
      {/if}

      {deleting ? 'Deleting...' : ''}
    </button>
  </Header>
  <main class="p-4">
    {#if $notesStore.state === 'loaded'}
      <NoteEditor {editor} disabled={updating || deleting} class="mb-3" />
      <TagEditor
        tags={editedNote.tags}
        on:add={(e) => addTag(e.detail)}
        on:remove={(e) => removeTag(e.detail)}
        disabled={updating || deleting}
      />
      <button
        class="btn mt-4 btn-primary {updating ? 'loading' : ''}"
        disabled={updating || deleting}
        on:click={save}>{updating ? 'Saving...' : 'Save'}</button
      >
      <hr class="mt-10">
      <SharingEditor
        {editedNote}
        {ownedByMe}
      />
    {:else if $notesStore.state === 'loading'}
      Loading notes...
    {/if}
  </main>
{:else}
  <Header>
    <span slot="title"> Edit note </span>
  </Header>
  <main class="p-4">
    {#if $notesStore.state === 'loading'}
      <Spinner />
      Loading note...
    {:else if $notesStore.state === 'loaded'}
      <div class="alert alert-error">Could not find note.</div>
    {/if}
  </main>
{/if}
