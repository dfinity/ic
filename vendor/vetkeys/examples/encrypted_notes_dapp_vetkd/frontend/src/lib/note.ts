import type { EncryptedNote } from '../lib/backend';
import type { CryptoService } from './crypto';
import type { Principal } from '@dfinity/principal';

export interface NoteModel {
  id: bigint;
  title: string;
  content: string;
  createdAt: number;
  updatedAt: number;
  tags: Array<string>;
  owner: string;
  users: Array<string>;
}

type SerializableNoteModel = Omit<NoteModel, 'id' | 'owner' | 'users'>;

export function noteFromContent(content: string, tags: string[], self_principal: Principal): NoteModel {
  const title = extractTitle(content);
  const creationTime = Date.now();

  return {
    id: BigInt(0),
    title,
    content,
    createdAt: creationTime,
    updatedAt: creationTime,
    tags,
    owner: self_principal.toString(),
    users: [""],
  };
}

export async function serialize(
  note: NoteModel,
  cryptoService: CryptoService
): Promise<EncryptedNote> {
  const serializableNote: SerializableNoteModel = {
    title: note.title,
    content: note.content,
    createdAt: note.createdAt,
    updatedAt: note.updatedAt,
    tags: note.tags,
  };
  const encryptedNote = await cryptoService.encryptWithNoteKey(
    note.id,
    note.owner,
    JSON.stringify(serializableNote)
  );
  return {
    id: note.id,
    encrypted_text: encryptedNote,
    owner: note.owner,
    users: note.users,
  };
}

export async function deserialize(
  enote: EncryptedNote,
  cryptoService: CryptoService
): Promise<NoteModel> {
  const serializedNote = await cryptoService.decryptWithNoteKey(enote.id, enote.owner, enote.encrypted_text);
  const deserializedNote: SerializableNoteModel = JSON.parse(serializedNote);
  return {
    id: enote.id,
    owner: enote.owner,
    users: enote.users,
    ...deserializedNote,
  };
}

export function summarize(note: NoteModel, maxLength = 50) {
  const div = document.createElement('div');
  div.innerHTML = note.content;

  let text = div.innerText;
  const title = extractTitleFromDomEl(div);
  if (title) {
    text = text.replace(title, '');
  }

  return text.slice(0, maxLength) + (text.length > maxLength ? '...' : '');
}

function extractTitleFromDomEl(el: HTMLElement) {
  const title = el.querySelector('h1');
  if (title) {
    return title.innerText;
  }

  const blockElements = el.querySelectorAll(
    'h1,h2,p,li'
  ) as NodeListOf<HTMLElement>;
  for (const el of blockElements) {
    if (el.innerText?.trim().length > 0) {
      return el.innerText.trim();
    }
  }
  return '';
}

export function extractTitle(html: string) {
  const div = document.createElement('div');
  div.innerHTML = html;
  return extractTitleFromDomEl(div);
}
