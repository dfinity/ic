import { writable } from 'svelte/store';
import { auth } from './auth';

interface DraftModel {
  content: string;
  tags: string[];
}

let initialDraft: DraftModel = {
  content: '',
  tags: [],
};

try {
  const savedDraft: DraftModel = JSON.parse(localStorage.getItem('draft'));
  if ('content' in savedDraft && 'tags' in savedDraft) {
    initialDraft = savedDraft;
  }
} catch {}

export const draft = writable<DraftModel>(initialDraft);

draft.subscribe((draft) => {
  localStorage.setItem('draft', JSON.stringify(draft));
});

auth.subscribe(($auth) => {
  if ($auth.state === 'anonymous') {
    draft.set(initialDraft);
  }
});
