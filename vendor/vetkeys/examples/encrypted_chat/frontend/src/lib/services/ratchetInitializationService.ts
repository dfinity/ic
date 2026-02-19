import { deriveRootKeyBytes, SymmetricRatchetState } from '$lib/crypto/symmetricRatchet';
import type { ChatId } from '../../declarations/encrypted_chat/encrypted_chat.did';
import { getActor, getMyPrincipal } from '$lib/stores/auth.svelte';
import { stringifyBigInt, chatIdToString } from '$lib/utils';
import { canisterAPI } from './canisterApi';
import { keyStorageService } from './keyStorage';
import { EncryptedCanisterCacheService } from './encryptedCanisterCacheService';
import { VetKeyResharingService } from './vetKeyResharingService';

export class RatchetInitializationService {
	#vetKeyResharingService: VetKeyResharingService;
	#encryptedCanisterCacheService: EncryptedCanisterCacheService;

	constructor() {
		this.#vetKeyResharingService = new VetKeyResharingService();
		this.#encryptedCanisterCacheService = new EncryptedCanisterCacheService();
	}

	async initializeRatchetStateAndReshareAndCacheIfNeeded(
		chatId: ChatId,
		vetKeyEpoch: bigint
	): Promise<SymmetricRatchetState> {
		const metadata = await canisterAPI.getVetKeyEpochMetadata(getActor(), chatId, vetKeyEpoch);
		const creationTime = new Date(Number(metadata.creation_timestamp / 1_000_000n));
		const rotationDuration = new Date(
			Number(metadata.symmetric_key_rotation_duration / 1_000_000n)
		);
		console.log(
			`RatchetInitializationService.initializeRatchetStateAndReshareAndCacheIfNeeded: Initializing ratchet state for chat ${chatIdToString(chatId)} and vetKey epoch ${vetKeyEpoch.toString()} with creation time ${creationTime.toUTCString()} and rotation duration ${rotationDuration.toUTCString()}`
		);

		try {
			return await this.cryptoKeyStateFromLocalStorage(chatId, vetKeyEpoch);
		} catch (error) {
			console.info(
				`User doesn't have key in persistent storage for chat ${chatIdToString(chatId)} and vetKey epoch ${vetKeyEpoch.toString()}: `,
				error
			);
		}

		try {
			const keyState = await this.cryptoKeyStateFromRemoteCache(chatId, vetKeyEpoch);
			const symmetricRatchetState = new SymmetricRatchetState(
				keyState.key,
				keyState.symmetricKeyEpoch,
				creationTime,
				rotationDuration
			);

			keyStorageService
				.saveSymmetricRatchetState(
					chatIdToString(chatId),
					vetKeyEpoch.toString(),
					symmetricRatchetState
				)
				.catch((error) => {
					console.error(
						`Failed to save key state for chat ${chatIdToString(chatId)} vetkeyEpoch ${vetKeyEpoch.toString()}: `,
						error
					);
				});
			return symmetricRatchetState;
		} catch (error) {
			console.info(
				`User doesn't have key in remote cache for chat ${chatIdToString(chatId)} and vetKey epoch ${vetKeyEpoch.toString()}: `,
				error
			);
		}

		try {
			const keyState = await this.cryptoKeyStateFromResharedVetKey(chatId, vetKeyEpoch);
			return new SymmetricRatchetState(
				keyState.key,
				keyState.symmetricKeyEpoch,
				creationTime,
				rotationDuration
			);
		} catch (error) {
			console.info('Failed to fetch reshared IBE encrypted vetkey: ', error);
		}

		try {
			const keyState = await this.fetchAndReshareAndCacheVetKey(chatId, vetKeyEpoch);
			const symmetricRatchetState = new SymmetricRatchetState(
				keyState.key,
				keyState.symmetricKeyEpoch,
				creationTime,
				rotationDuration
			);
			keyStorageService
				.saveSymmetricRatchetState(
					chatIdToString(chatId),
					vetKeyEpoch.toString(),
					symmetricRatchetState
				)
				.catch((error) => {
					console.error(
						`Failed to save key state for chat ${chatIdToString(chatId)} vetkeyEpoch ${vetKeyEpoch.toString()}: `,
						error
					);
				});
			return symmetricRatchetState;
		} catch (error) {
			console.info('Failed to fetch vetkey: ', error);
		}

		throw new Error('Failed to initialize ratchet state');
	}

	async cryptoKeyStateFromLocalStorage(
		chatId: ChatId,
		vetKeyEpoch: bigint
	): Promise<SymmetricRatchetState> {
		return keyStorageService
			.getSymmetricRatchetState(chatIdToString(chatId), vetKeyEpoch.toString())
			.then((keyState) => {
				if (keyState) {
					console.log('Key state found in key storage: ', keyState);
					return keyState;
				} else {
					console.log(
						'Key state not found in key storage: ',
						chatIdToString(chatId),
						vetKeyEpoch.toString()
					);
					throw new Error('Key state not found in key storage');
				}
			});
	}

	cryptoKeyStateFromRemoteCache(
		chatId: ChatId,
		vetKeyEpoch: bigint
	): Promise<{ key: CryptoKey; symmetricKeyEpoch: bigint }> {
		return this.#encryptedCanisterCacheService
			.fetchAndDecryptFor(chatId, vetKeyEpoch)
			.then((epochKeyState) => {
				return importKeyStateFromBytes(epochKeyState);
			});
	}

	cryptoKeyStateFromResharedVetKey(
		chatId: ChatId,
		vetKeyEpoch: bigint
	): Promise<{ key: CryptoKey; symmetricKeyEpoch: bigint }> {
		return this.#vetKeyResharingService
			.fetchResharedIbeEncryptedVetKey(chatId, vetKeyEpoch)
			.then((resharedVetKey) => {
				console.log('successfully fetched reshared IBE encrypted vetkey: ', resharedVetKey);
				return importKeyStateFromBytes(
					deriveRootKeyAndDispatchCaching(chatId, vetKeyEpoch, resharedVetKey)
				);
			});
	}

	async fetchAndReshareAndCacheVetKey(
		chatId: ChatId,
		vetKeyEpoch: bigint
	): Promise<{ key: CryptoKey; symmetricKeyEpoch: bigint }> {
		const vetKey = await canisterAPI.getVetKey(getActor(), chatId, vetKeyEpoch);
		while (true) {
			console.log('waiting for vetKey epoch metadata in a loop');

			const meta = await canisterAPI.getVetKeyEpochMetadata(getActor(), chatId, vetKeyEpoch);

			const otherParticipants = meta.participants.filter(
				(p) => p.toString() !== getMyPrincipal().toString()
			);

			this.#vetKeyResharingService
				.reshareIbeEncryptedVetKeys(chatId, vetKeyEpoch, otherParticipants, vetKey.signatureBytes())
				.catch((error) => {
					console.error(
						`Failed to reshare IBE encrypted vetkeys for chat ${chatIdToString(chatId)} vetkeyEpoch ${meta.epoch_id.toString()}: `,
						error
					);
				});

			return await importKeyStateFromBytes(
				deriveRootKeyAndDispatchCaching(chatId, vetKeyEpoch, vetKey.signatureBytes())
			);
		}
	}
}

function deriveRootKeyAndDispatchCaching(
	chatId: ChatId,
	vetKeyEpoch: bigint,
	vetKeyBytes: Uint8Array
): { keyBytes: Uint8Array; symmetricKeyEpoch: bigint } {
	const rootKey = deriveRootKeyBytes(vetKeyBytes);
	console.log(
		`Computed rootKey=${stringifyBigInt(rootKey)} from vetKey=${stringifyBigInt(vetKeyBytes)}`
	);

	console.log('starting to store the root key in cache: ', rootKey);
	const vetKeyEncryptedCache = new EncryptedCanisterCacheService();
	const keyState = { keyBytes: rootKey, symmetricKeyEpoch: 0n };
	// await this future in background
	vetKeyEncryptedCache.encryptAndStoreFor(chatId, vetKeyEpoch, keyState).catch((error) => {
		console.error(
			`Failed to store root key in cache for chat ${chatIdToString(chatId)} vetkeyEpoch ${vetKeyEpoch.toString()}: `,
			error
		);
	});
	return keyState;
}

export async function importKeyStateFromBytes(params: {
	keyBytes: Uint8Array;
	symmetricKeyEpoch: bigint;
}): Promise<{ key: CryptoKey; symmetricKeyEpoch: bigint }> {
	const exportable = false;
	const key = await globalThis.crypto.subtle.importKey(
		'raw',
		new Uint8Array(params.keyBytes),
		'HKDF',
		exportable,
		['deriveKey', 'deriveBits']
	);
	return { key, symmetricKeyEpoch: params.symmetricKeyEpoch };
}
