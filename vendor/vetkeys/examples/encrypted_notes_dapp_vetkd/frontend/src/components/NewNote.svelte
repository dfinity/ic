<script lang="ts">
  import { onDestroy } from 'svelte';
  import { Editor, placeholder } from 'typewriter-editor';
  import { noteFromContent } from '../lib/note';
  import { auth } from '../store/auth';
  import { draft } from '../store/draft';
  import { addNote, refreshNotes } from '../store/notes';
  import { addNotification, showError } from '../store/notifications';
  import Header from './Header.svelte';
  import NoteEditor from './NoteEditor.svelte';
  import TagEditor from './TagEditor.svelte';
  import DOMPurify from 'isomorphic-dompurify';

  let creating = false;
  let tags: string[] = $draft.tags;

  const editor = new Editor({
    modules: {
      placeholder: placeholder('Start typing...'),
    },
    html: $draft.content,
  });

  async function add() {
    if ($auth.state !== 'initialized') {
      return;
    }
    creating = true;
    await addNote(
      noteFromContent(DOMPurify.sanitize(editor.getHTML()), tags, $auth.client.getIdentity().getPrincipal()),
      $auth.actor,
      $auth.crypto
    )
      .catch((e) => {
        showError(e, 'Could not add note.');
      })
      .finally(() => {
        creating = false;
      });

    // if creation was successful, reset the editor
    editor.setHTML('');
    tags = [];

    addNotification({ type: 'success', message: 'Note added successfully' });

    // refresh notes in the background
    refreshNotes($auth.actor, $auth.crypto).catch((e) =>
      showError(e, 'Could not refresh notes.')
    );
  }

  function saveDraft() {
    draft.set({
      content: DOMPurify.sanitize(editor.getHTML()),
      tags: tags,
    });
  }

  function addTag(tag: string) {
    tags = [...tags, tag];
  }

  function removeTag(tag: string) {
    tags = tags.filter((t) => t !== tag);
  }

  onDestroy(saveDraft);
</script>

<svelte:window on:beforeunload={saveDraft} />

<Header>
  <span slot="title"> New note </span>
</Header>

<main class="p-4">
  <NoteEditor {editor} class="mb-3" disabled={creating} />
  <TagEditor
    {tags}
    on:add={(e) => addTag(e.detail)}
    on:remove={(e) => removeTag(e.detail)}
    disabled={creating}
  />
  <button
    class="btn mt-6 btn-primary {creating ? 'loading' : ''}"
    disabled={creating}
    on:click={add}>{creating ? 'Adding...' : 'Add note'}</button
  >
</main>

<style>
</style>
