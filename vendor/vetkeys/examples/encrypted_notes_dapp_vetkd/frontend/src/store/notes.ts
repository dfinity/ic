import { writable } from 'svelte/store';
import type { BackendActor } from '../lib/actor';
import type { EncryptedNote } from '../lib/backend';
import type { CryptoService } from '../lib/crypto';
import { deserialize, NoteModel, serialize } from '../lib/note';
import { auth } from './auth';
import { showError } from './notifications';

export const notesStore = writable<
  | {
      state: 'uninitialized';
    }
  | {
      state: 'loading';
    }
  | {
      state: 'loaded';
      list: NoteModel[];
    }
  | {
      state: 'error';
    }
>({ state: 'uninitialized' });

let notePollerHandle: ReturnType<typeof setInterval> | null;

async function decryptNotes(
  notes: EncryptedNote[],
  cryptoService: CryptoService
): Promise<NoteModel[]> {
  // When notes are initially created, they do not have (and cannot have) any
  // (encrypted) content yet because the note ID, which is needed to retrieve
  // the note-specific encryption key, is not known yet before the note is
  // created because the note ID is a return value of the call to create a note.
  // The (encrypted) note content is stored in the backend only by a second call
  // to the backend that updates the note's conent directly after the note is
  // created. This means that there is a short period of time where the note
  // already exists but doesn't have any (encrypted) content yet.
  // To avoid decryption errors for these notes, we skip deserializing (and thus
  // decrypting) these notes here.
  const notes_with_content = notes.filter((note) => note.encrypted_text != "");

  return await Promise.all(
    notes_with_content.map((encryptedNote) => deserialize(encryptedNote, cryptoService))
  );
}

function updateNotes(notes: NoteModel[]) {
  notesStore.set({
    state: 'loaded',
    list: notes,
  });
}

export async function refreshNotes(
  actor: BackendActor,
  cryptoService: CryptoService
) {
  const encryptedNotes = await actor.get_notes();

  const notes = await decryptNotes(encryptedNotes, cryptoService);
  updateNotes(notes);
}

export async function addNote(
  note: NoteModel,
  actor: BackendActor,
  crypto: CryptoService
) {
  const new_id: bigint = await actor.create_note();
  note.id = new_id;
  const encryptedNote = (await serialize(note, crypto)).encrypted_text;
  await actor.update_note(new_id, encryptedNote);
}
export async function updateNote(
  note: NoteModel,
  actor: BackendActor,
  crypto: CryptoService
) {
  const encryptedNote = await serialize(note, crypto);
  await actor.update_note(note.id, encryptedNote.encrypted_text);
}

export async function addUser(
  id: bigint,
  user: string,
  actor: BackendActor,
) {
  await actor.add_user(id, user);
}

export async function removeUser(
  id: bigint,
  user: string,
  actor: BackendActor,
) {
  await actor.remove_user(id, user);
}

auth.subscribe(async ($auth) => {
  if ($auth.state === 'initialized') {
    if (notePollerHandle !== null) {
      clearInterval(notePollerHandle);
      notePollerHandle = null;
    }

    notesStore.set({
      state: 'loading',
    });
    try {
      await refreshNotes($auth.actor, $auth.crypto).catch((e) =>
        showError(e, 'Could not poll notes.')
      );

      notePollerHandle = setInterval(async () => {
        await refreshNotes($auth.actor, $auth.crypto).catch((e) =>
          showError(e, 'Could not poll notes.')
        );
      }, 3000);
    } catch {
      notesStore.set({
        state: 'error',
      });
    }
  } else if ($auth.state === 'anonymous' && notePollerHandle !== null) {
    clearInterval(notePollerHandle);
    notePollerHandle = null;
    notesStore.set({
      state: 'uninitialized',
    });
  }
});
