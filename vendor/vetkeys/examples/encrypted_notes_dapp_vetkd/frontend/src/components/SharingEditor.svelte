<script lang="ts">
  import { NoteModel } from '../lib/note';
  import { auth } from '../store/auth';
  import { addUser, refreshNotes, removeUser } from '../store/notes';
  import { addNotification, showError } from '../store/notifications';

  export let editedNote: NoteModel;
  export let ownedByMe = false;

  let newSharing = '';
  let newSharingInput: HTMLInputElement;
  let adding = false;
  let removing = false;

  async function add() {
    adding = true;
    try {
      await addUser(editedNote.id, newSharing, $auth.actor);
      addNotification({
        type: 'success',
        message: 'User successfully added',
      });
      editedNote.users = [...editedNote.users, newSharing];
      newSharing = '';
      newSharingInput.focus();
    } catch (e) {
      showError(e, 'Could not add user.');
    } finally {
      adding = false;
    }
    await refreshNotes($auth.actor, $auth.crypto).catch((e) =>
      showError(e, 'Could not refresh notes.')
    );
  }

  async function remove(sharing: string) {
    removing = true;
    try {
      await removeUser(editedNote.id, sharing, $auth.actor);
      editedNote.users = editedNote.users.filter((u) => u !== sharing);
      addNotification({
        type: 'success',
        message: 'User successfully removed',
      });
    } catch (e) {
      showError(e, 'Could not remove user.');
    } finally {
      removing = false;
    }
    await refreshNotes($auth.actor, $auth.crypto).catch((e) =>
      showError(e, 'Could not refresh notes.')
    );
  }

  function onKeyPress(e) {
    if (
      e.key === 'Enter' &&
      newSharing.trim().length > 0 &&
      !editedNote.users.includes(newSharing)
    ) {
      add();
    }
  }
</script>

<div class="flex flex-col flex-wrap mt-4">
  <p class="text-lg font-bold">Users</p>
  {#if ownedByMe}
    <p class="mt-1">
      Add users by their principal to allow them editing the note.
    </p>
  {:else}
    <p class="mt-3">
      This note is <span class="font-bold">shared</span> with you. It is owned
      by <span class="italic font-bold">{editedNote.owner}</span>.
    </p>
    <p class="mt-3">Users with whom the owner shared the note:</p>
  {/if}
  <div class="flex flex-wrap space-x-2 mt-2">
    {#each editedNote.users as sharing}
      <button
        class="btn btn-outline btn-sm flex items-center"
        on:click={() => {
          remove(sharing);
        }}
        disabled={adding || removing || !ownedByMe}
      >
        <span>{sharing}</span>
        <svg
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
          class="inline-block w-4 h-4 stroke-current"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M6 18L18 6M6 6l12 12"
          />
        </svg>
      </button>
    {/each}
    <input
      bind:value={newSharing}
      placeholder="Add principal..."
      class="bg-transparent text-base rounded-lg h-8 px-3 w-auto {adding ||
      removing
        ? 'opacity-50'
        : ''} 
        {!ownedByMe ? 'hidden' : ''}"
      bind:this={newSharingInput}
      on:keypress={onKeyPress}
      disabled={adding}
    />
    <button
      class="btn btn-sm btn-ghost
        {!ownedByMe ? 'hidden' : ''}
        {adding || removing ? 'loading' : ''}"
      on:click={add}
      disabled={newSharing.trim().length === 0 ||
        editedNote.users.includes(newSharing) ||
        adding ||
        removing}
      >{adding ? 'Adding...' : removing ? 'Removing... ' : 'Add'}</button
    >
  </div>
</div>
