import {
	SymmetricRatchetState,
	type StorableSymmetricRatchetState as StorableSymmetricRatchetState
} from '$lib/crypto/symmetricRatchet';
import { storagePrefixes } from '../types';
import { get, keys, set } from 'idb-keyval';

// IndexedDB storage service for persistent key data
export class KeyStorageService {
	async getSymmetricRatchetState(
		chatIdStr: string,
		vetKeyEpochStr: string
	): Promise<SymmetricRatchetState | undefined> {
		console.log(
			`KeyStorageService: Getting key state for chat ${chatIdStr} vetkeyEpoch ${vetKeyEpochStr}`
		);
		const stateRecord = (await get([
			storagePrefixes.CHAT_EPOCH_KEY_PREFIX,
			chatIdStr,
			vetKeyEpochStr
		])) as StorableSymmetricRatchetState;
		if (!stateRecord) {
			return undefined;
		}
		console.log(
			`KeyStorageService.getSymmetricRatchetState: Got symmetric ratchet state for chat ${chatIdStr} vetkeyEpoch ${vetKeyEpochStr}: state`,
			stateRecord
		);
		return new SymmetricRatchetState(
			stateRecord.cryptoKey,
			stateRecord.symmetricRatchetEpoch,
			stateRecord.creationTime,
			stateRecord.rotationDuration
		);
	}

	async saveSymmetricRatchetState(
		chatIdStr: string,
		vetKeyEpochStr: string,
		state: SymmetricRatchetState
	) {
		console.log(
			`KeyStorageService: Saving key state for chat ${chatIdStr} vetkeyEpoch ${vetKeyEpochStr}: state`,
			state
		);
		await set(
			[storagePrefixes.CHAT_EPOCH_KEY_PREFIX, chatIdStr, vetKeyEpochStr],
			state.toStorable()
		);
	}

	async getAllSymmetricRatchetStates(): Promise<
		{ chatIdStr: string; vetKeyEpoch: bigint; state: SymmetricRatchetState }[]
	> {
		console.log(`KeyStorageService: Getting all symmetric key states`);
		const allKeys = await keys();
		const symmetricKeyStates: {
			chatIdStr: string;
			vetKeyEpoch: bigint;
			state: SymmetricRatchetState;
		}[] = [];
		for (const key of allKeys) {
			console.log(`KeyStorageService: getAllSymmetricRatchetStates key`, key);
			if (Array.isArray(key) && key[0] === storagePrefixes.CHAT_EPOCH_KEY_PREFIX) {
				const state = await this.getSymmetricRatchetState(key[1] as string, key[2] as string);
				if (state) {
					symmetricKeyStates.push({
						chatIdStr: key[1] as string,
						vetKeyEpoch: BigInt(key[2] as string),
						state
					});
				}
			}
		}
		return symmetricKeyStates;
	}

	async saveIbeDecryptionKey(keyBytes: Uint8Array) {
		console.log(`KeyStorageService: Saving IBE decryption key`);
		await set([storagePrefixes.CHAT_IBE_DECRYPTION_KEY_PREFIX], keyBytes);
	}

	async getIbeDecryptionKey(): Promise<Uint8Array | undefined> {
		console.log(`KeyStorageService: Getting IBE decryption key`);
		return await get([storagePrefixes.CHAT_IBE_DECRYPTION_KEY_PREFIX]);
	}
}

export const keyStorageService = new KeyStorageService();
