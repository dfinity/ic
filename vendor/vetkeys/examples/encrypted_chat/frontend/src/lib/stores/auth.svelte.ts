import { chatStorageService } from '$lib/services/chatStorage';
import { HttpAgent, type ActorSubclass } from '@dfinity/agent';
import { AuthClient } from '@dfinity/auth-client';
import type { Principal } from '@dfinity/principal';
import type { _SERVICE } from '../../declarations/encrypted_chat/encrypted_chat.did';
import { createActor } from '../../declarations/encrypted_chat';
import fetch from 'isomorphic-fetch';
import { DFX_NETWORK, CANISTER_ID_ENCRYPTED_CHAT } from '$env/static/public';

if (import.meta.env.SSR || typeof window === 'undefined') {
	const {
		indexedDB,
		IDBKeyRange,
		IDBRequest,
		IDBDatabase,
		IDBTransaction,
		IDBCursor,
		IDBIndex,
		IDBObjectStore,
		IDBOpenDBRequest
	} = await import('fake-indexeddb');
	globalThis.indexedDB = indexedDB;
	globalThis.IDBKeyRange = IDBKeyRange;
	globalThis.IDBDatabase = IDBDatabase;
	globalThis.IDBTransaction = IDBTransaction;
	globalThis.IDBRequest = IDBRequest;
	globalThis.IDBCursor = IDBCursor;
	globalThis.IDBIndex = IDBIndex;
	globalThis.IDBObjectStore = IDBObjectStore;
	globalThis.IDBOpenDBRequest = IDBOpenDBRequest;
}

export type AuthState =
	| {
			label: 'initializing-auth';
	  }
	| {
			label: 'anonymous';
			client: AuthClient;
	  }
	| {
			label: 'initialized';
			client: AuthClient;
	  }
	| {
			label: 'error';
			error: string;
	  };

export const auth = $state<{ state: AuthState }>({
	state: { label: 'initializing-auth' }
});

async function initAuth() {
	const client = await AuthClient.create();
	if (await client.isAuthenticated()) {
		auth.state = {
			label: 'initialized',
			client
		};
	} else {
		auth.state = {
			label: 'anonymous',
			client
		};
	}
}

void initAuth();

export async function login() {
	if (auth.state.label === 'anonymous') {
		const client = auth.state.client;
		await client.login({
			maxTimeToLive: BigInt(8 * 3600) * BigInt(1_000_000_000), // 8 hours
			identityProvider:
				DFX_NETWORK === 'ic'
					? 'https://identity.ic0.app/#authorize'
					: `http://rdmx6-jaaaa-aaaaa-aaadq-cai.localhost:4943/#authorize`,
			onSuccess: () => {
				authenticate(client);
			},
			onError: (e) => console.error('Failed to authenticate with internet identity: ' + e)
		});
	}
}

function authenticate(client: AuthClient) {
	auth.state = {
		label: 'initialized',
		client
	};
}

export async function logout() {
	if (auth.state.label === 'initialized') {
		await auth.state.client.logout();
		auth.state = {
			label: 'anonymous',
			client: auth.state.client
		};
		await chatStorageService.discardCacheCompletely();
	}
}

export function getMyPrincipal(): Principal {
	if (auth.state.label !== 'initialized') throw new Error('Unexpectedly not authenticated');
	if (!auth.state.client.getIdentity().getPrincipal()) {
		console.error('Unexpectedly not authenticated: undefined principal', auth.state.client.getIdentity().getPrincipal());
	}
	return auth.state.client.getIdentity().getPrincipal();
}

export function getActor(): ActorSubclass<_SERVICE> {
	if (auth.state.label === 'initialized') {
		const host = DFX_NETWORK === 'ic' ? 'https://ic0.app' : 'http://localhost:4943';
		const shouldFetchRootKey = DFX_NETWORK !== 'ic';
		const agent = HttpAgent.createSync({
			identity: auth.state.client.getIdentity(),
			fetch: fetch,
			host,
			shouldFetchRootKey
		});
		if (!CANISTER_ID_ENCRYPTED_CHAT) {
			throw new Error('CANISTER_ID_ENCRYPTED_CHAT is not set');
		} 
		return createActor(CANISTER_ID_ENCRYPTED_CHAT, { agent });
	} else {
		throw new Error('Not authenticated');
	}
}
