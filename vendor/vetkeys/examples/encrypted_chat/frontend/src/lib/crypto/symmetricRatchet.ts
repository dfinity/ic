import { DerivedKeyMaterial, deriveSymmetricKey, type VetKey } from '@dfinity/vetkeys';
import {
	sizePrefixedBytesFromString,
	u8ByteUint8ArrayBigEndianToUBigInt,
	uBigIntTo8ByteUint8ArrayBigEndian
} from '../utils';
import { Principal } from '@dfinity/principal';

const DOMAIN_RATCHET_INIT = sizePrefixedBytesFromString('ic-vetkeys-chat-ratchet-init');
const DOMAIN_RATCHET_STEP = sizePrefixedBytesFromString('ic-vetkeys-chat-ratchet-step');
const DOMAIN_MESSAGE_ENCRYPTION = sizePrefixedBytesFromString(
	'ic-vetkeys-chat-message-encryption'
);

// Notes
//
// We need the following functionalities here:
// - Raw key
//   - Derive the root epoch key from a vetKey as bytes. Those bytes can be cached in a canister in encrypted form.
//   - Import bytes from a canister's decrypted cache.
//   - Eventually evolve the state to the needed epoch.
// - CryptoKey
//   - Store the epoch key in CryptoKey form in RAM and indexedDB.
//   - Evolve the crypto key.
//   - Peek at a future key without evolving the state, e.g., we encrypt our message with a key in the next epoch
//     but we are not sure if the canister holds a message that we will need to decrypt using the current key.
//   - Encrypt/decrypt messages using the crypto key.
//
// In summary, the raw key state allows to cache the key and the CryptoKey state allows to encrypt/decrypt messages.

export type StorableSymmetricRatchetState = {
	cryptoKey: CryptoKey;
	symmetricRatchetEpoch: bigint;
	creationTime: Date;
	rotationDuration: Date;
};

export class SymmetricRatchetState {
	#cryptoKey: CryptoKey;
	#symmetricRatchetEpoch: bigint;
	readonly #creationTime: Date;
	readonly #rotationDuration: Date;

	constructor(
		key: CryptoKey,
		symmetricRatchetEpoch: bigint,
		creationTime: Date,
		rotationDuration: Date
	) {
		this.#cryptoKey = key;
		this.#symmetricRatchetEpoch = symmetricRatchetEpoch;
		this.#creationTime = creationTime;
		this.#rotationDuration = rotationDuration;
	}

	toStorable(): StorableSymmetricRatchetState {
		return {
			cryptoKey: this.#cryptoKey,
			symmetricRatchetEpoch: this.#symmetricRatchetEpoch,
			creationTime: this.#creationTime,
			rotationDuration: this.#rotationDuration
		};
	}

	static async fromRawKeyState(
		rawKeyState: CacheableSymmetricRatchetState
	): Promise<SymmetricRatchetState> {
		const { key, symmetricKeyEpoch } = await importKeyFromBytes(
			rawKeyState.rawKey,
			rawKeyState.symmetricRatchetEpoch
		);
		return new SymmetricRatchetState(
			key,
			symmetricKeyEpoch,
			rawKeyState.creationTime,
			rawKeyState.rotationDuration
		);
	}

	async decryptAtTimeAndEvolveIfNeeded(
		sender: Principal,
		senderMessageId: bigint,
		message: Uint8Array,
		time: Date
	): Promise<Uint8Array> {
		if (time < this.#creationTime) {
			throw new Error('Cannot decrypt message before the state was created');
		}
		const expectedEpoch = this.getExpectedEpochAtTime(time);
		await this.evolveTo(expectedEpoch);
		const domainSeparator = messageEncryptionDomainSeparator(sender, senderMessageId);
		const derivedKeyMaterial = DerivedKeyMaterial.fromCryptoKey(this.#cryptoKey);
		return await derivedKeyMaterial.decryptMessage(message, domainSeparator);
	}

	async encryptNow(
		sender: Principal,
		senderMessageId: bigint,
		message: Uint8Array
	): Promise<{ encryptedBytes: Uint8Array; symmetricRatchetEpoch: bigint }> {
		const now = new Date(Date.now());
		if (now < this.#creationTime) {
			throw new Error('Cannot decrypt message before the state was created');
		}
		const expectedEpoch = this.getExpectedEpochAtTime(now);
		const neededSymmetricRatchetState = await this.peekAtEpoch(expectedEpoch);
		const domainSeparator = messageEncryptionDomainSeparator(sender, senderMessageId);
		const derivedKeyMaterial = DerivedKeyMaterial.fromCryptoKey(
			neededSymmetricRatchetState.#cryptoKey
		);
		const encryptedBytes = await derivedKeyMaterial.encryptMessage(message, domainSeparator);
		console.log(
			`SymmetricRatchetState.encryptNow: encrypted message symmetric ratchet epoch ${neededSymmetricRatchetState.#symmetricRatchetEpoch.toString()}`
		);
		return {
			encryptedBytes,
			symmetricRatchetEpoch: neededSymmetricRatchetState.#symmetricRatchetEpoch
		};
	}

	/// Evolve the state to the next epoch.
	async evolve() {
		const newCryptoKey = await deriveNextSymmetricRatchetEpochCryptoKey(
			this.#cryptoKey,
			this.#symmetricRatchetEpoch
		);

		this.#cryptoKey = newCryptoKey;
		this.#symmetricRatchetEpoch += 1n;
	}

	async evolveTo(desiredEpoch: bigint) {
		if (desiredEpoch < this.#symmetricRatchetEpoch) {
			throw new Error(
				`SymmetricRatchetState.evolveTo: desiredEpoch ${desiredEpoch.toString()} is less than the current epoch ${this.#symmetricRatchetEpoch.toString()}`
			);
		}
		if (desiredEpoch === this.#symmetricRatchetEpoch) {
			return;
		}
		while (desiredEpoch > this.#symmetricRatchetEpoch) {
			console.log(
				`SymmetricRatchetState.evolveTo: evolving from epoch ${this.#symmetricRatchetEpoch.toString()} to epoch ${desiredEpoch.toString()}`
			);
			await this.evolve();
		}
	}

	/// Peek at a future epoch without evolving the state.
	///
	/// Returns an error if desiredEpoch is less than the current epoch.
	async peekAtEpoch(desiredEpoch: bigint): Promise<SymmetricRatchetState> {
		if (desiredEpoch < this.#symmetricRatchetEpoch) {
			throw new Error(
				`Cannot peek at epoch ${desiredEpoch} because the current epoch is ${this.#symmetricRatchetEpoch}`
			);
		} else if (desiredEpoch === this.#symmetricRatchetEpoch) {
			return this;
		}
		const newSymmetricRatchetState = new SymmetricRatchetState(
			this.#cryptoKey,
			desiredEpoch,
			this.#creationTime,
			this.#rotationDuration
		);
		await newSymmetricRatchetState.evolveTo(desiredEpoch);
		return newSymmetricRatchetState;
	}

	getExpectedEpochAtTime(time: Date): bigint {
		if (time < this.#creationTime) {
			throw new Error('Cannot get expected epoch before the state was created');
		}

		const elapsedSinceCreation = time.getTime() - this.#creationTime.getTime();
		const result = BigInt(Math.floor(elapsedSinceCreation / this.#rotationDuration.getTime()));
		console.log(
			`SymmetricRatchetState.getExpectedEpochAtTime: now ${time.toUTCString()} creationTime ${this.#creationTime.toUTCString()} elapsedSinceCreation ${elapsedSinceCreation.toString()}ms expectedEpoch ${result.toString()}`
		);
		return result;
	}

	getCurrentEpoch(): bigint {
		return this.#symmetricRatchetEpoch;
	}

	getCreationTime(): Date {
		return this.#creationTime;
	}
}

/// Contains a raw key and the symmetric ratchet epoch.
///
/// The raw key can be exported e.g. to a canister's encrypted cache.
export class CacheableSymmetricRatchetState {
	rawKey: Uint8Array;
	symmetricRatchetEpoch: bigint;
	creationTime: Date;
	rotationDuration: Date;

	private constructor(
		rawKey: Uint8Array,
		symmetricRatchetEpoch: bigint,
		creationTime: Date,
		rotationDuration: Date
	) {
		this.rawKey = rawKey;
		this.symmetricRatchetEpoch = symmetricRatchetEpoch;
		this.creationTime = creationTime;
		this.rotationDuration = rotationDuration;
	}

	/// Evolve the state to the next epoch.
	evolve() {
		this.symmetricRatchetEpoch += 1n;
		const domainSeparator = new Uint8Array([
			...DOMAIN_RATCHET_STEP,
			...uBigIntTo8ByteUint8ArrayBigEndian(this.symmetricRatchetEpoch)
		]);
		const newRawKey = deriveSymmetricKey(this.rawKey, domainSeparator, 32);
		this.rawKey = newRawKey;
	}

	evolveTo(desiredEpoch: bigint) {
		if (desiredEpoch < this.symmetricRatchetEpoch) {
			throw new Error(
				`Cannot evolve to epoch ${desiredEpoch} because the current epoch is ${this.symmetricRatchetEpoch}`
			);
		}
		while (desiredEpoch > this.symmetricRatchetEpoch) {
			this.evolve();
		}
	}

	/// Peek at a future epoch without evolving the state.
	///
	/// Returns an error if desiredEpoch is less than the current epoch.
	peekAtEpoch(desiredEpoch: bigint): CacheableSymmetricRatchetState {
		const newState = new CacheableSymmetricRatchetState(
			structuredClone(this.rawKey),
			this.symmetricRatchetEpoch,
			this.creationTime,
			this.rotationDuration
		);
		newState.evolveTo(desiredEpoch);
		return newState;
	}

	toSymmetricRatchetState(): Promise<SymmetricRatchetState> {
		return SymmetricRatchetState.fromRawKeyState(this);
	}

	static initializeFromVetKey(
		vetKey: VetKey,
		creationTime: Date,
		rotationDuration: Date
	): CacheableSymmetricRatchetState {
		const vetKeyBytes = vetKey.signatureBytes();
		const rawKey = deriveSymmetricKey(vetKeyBytes, DOMAIN_RATCHET_INIT, 32);
		return new CacheableSymmetricRatchetState(rawKey, 0n, creationTime, rotationDuration);
	}

	serialize(): Uint8Array {
		return new Uint8Array([
			...this.rawKey,
			...uBigIntTo8ByteUint8ArrayBigEndian(this.symmetricRatchetEpoch),
			...uBigIntTo8ByteUint8ArrayBigEndian(BigInt(this.creationTime.getMilliseconds())),
			...uBigIntTo8ByteUint8ArrayBigEndian(BigInt(this.rotationDuration.getMilliseconds()))
		]);
	}

	static deserialize(bytes: Uint8Array): CacheableSymmetricRatchetState {
		if (bytes.length !== 32 + 3 * 8) {
			throw new Error('Invalid serialized state');
		}
		const rawKey = bytes.slice(0, 32);
		const symmetricRatchetEpoch = u8ByteUint8ArrayBigEndianToUBigInt(bytes.slice(32));
		const creationTime = new Date(Number(u8ByteUint8ArrayBigEndianToUBigInt(bytes.slice(32 + 8))));
		const rotationDuration = new Date(
			Number(u8ByteUint8ArrayBigEndianToUBigInt(bytes.slice(32 + 8 + 8)))
		);
		return new CacheableSymmetricRatchetState(
			rawKey,
			symmetricRatchetEpoch,
			creationTime,
			rotationDuration
		);
	}
}

export function vetKeyToSymmetricRatchetStateBytes(vetKey: VetKey): Uint8Array {
	const vetKeyBytes = vetKey.signatureBytes();
	return deriveSymmetricKey(vetKeyBytes, DOMAIN_RATCHET_INIT, 32);
}

async function deriveNextSymmetricRatchetEpochCryptoKey(
	epochKey: CryptoKey,
	currentSymmetricKeyEpoch: bigint
): Promise<CryptoKey> {
	console.log(`deriveNextEpochKey: ${currentSymmetricKeyEpoch.toString()}`);
	const exportable = false;
	const domainSeparator = new Uint8Array([
		...DOMAIN_RATCHET_STEP,
		...uBigIntTo8ByteUint8ArrayBigEndian(currentSymmetricKeyEpoch)
	]);
	const algorithm = {
		name: 'HKDF',
		hash: 'SHA-256',
		length: 32 * 8,
		info: domainSeparator,
		salt: new Uint8Array()
	};

	const rawKey = await globalThis.crypto.subtle.deriveBits(algorithm, epochKey, 8 * 32);

	return await globalThis.crypto.subtle.importKey('raw', rawKey, algorithm, exportable, [
		'deriveKey',
		'deriveBits'
	]);
}

async function importKeyFromBytes(
	keyBytes: Uint8Array,
	symmetricKeyEpoch: bigint
): Promise<{ key: CryptoKey; symmetricKeyEpoch: bigint }> {
	const exportable = false;
	const key = await globalThis.crypto.subtle.importKey(
		'raw',
		new Uint8Array(keyBytes),
		'HKDF',
		exportable,
		['deriveKey', 'deriveBits']
	);
	return { key, symmetricKeyEpoch: symmetricKeyEpoch };
}

export function messageEncryptionDomainSeparator(
	sender: Principal,
	senderMessageId: bigint
): Uint8Array {
	return new Uint8Array([
		...DOMAIN_MESSAGE_ENCRYPTION,
		...sender.toUint8Array(),
		...uBigIntTo8ByteUint8ArrayBigEndian(senderMessageId)
	]);
}

export function deriveRootKeyBytes(vetKeyBytes: Uint8Array): Uint8Array {
	return deriveSymmetricKey(vetKeyBytes, DOMAIN_RATCHET_INIT, 32);
}

// function deriveSymmetricRatchetRootKey(
// 	actor: ActorSubclass<_SERVICE>,
// 	chatId: ChatId,
// 	vetKeyEpoch: bigint,
// 	vetKeyBytes: Uint8Array
// ): { keyBytes: Uint8Array; symmetricKeyEpoch: bigint } {
// 	const rootKey = deriveSymmetricKey(vetKeyBytes, DOMAIN_RATCHET_INIT, 32);
// 	console.log(
// 		`Computed rootKey=${stringifyBigInt(rootKey)} from vetKey=${stringifyBigInt(vetKeyBytes)}`
// 	);

// 	console.log('starting to store the root key in cache: ', rootKey);
// 	const vetKeyEncryptedCache = new EncryptedCacheManager(getMyPrincipal(), actor);
// 	const keyState = { keyBytes: rootKey, symmetricKeyEpoch: 0n };
// 	// await this future in background
// 	vetKeyEncryptedCache.encryptAndStoreFor(chatId, vetKeyEpoch, keyState).catch((error) => {
// 		console.error(
// 			`Failed to store root key in cache for chat ${chatIdToString(chatId)} vetkeyEpoch ${vetKeyEpoch.toString()}: `,
// 			error
// 		);
// 	});
// 	return keyState;
// }

// async function symmetricRatchetUntil(
// 	chatId: ChatId,
// 	vetkeyEpoch: bigint,
// 	symmetricKeyEpoch: bigint
// ) {
// 	while ((await getCurrentSymmetricEpoch(chatId, vetkeyEpoch)) < symmetricKeyEpoch) {
// 		try {
// 			const currentSymmetricEpoch = await getCurrentSymmetricEpoch(chatId, vetkeyEpoch);
// 			const mapKey = chatIdVetKeyEpochToString(chatId, vetkeyEpoch);
// 			chatIdStringToEpochKeyState.set(mapKey, {
// 				status: 'ready',
// 				symmetricKeyEpoch: currentSymmetricEpoch + 1n,
// 				key: await symmetricRatchet(chatId, vetkeyEpoch, currentSymmetricEpoch)
// 			});
// 		} catch (error) {
// 			console.warn('symmetricRatchetUntil: ', error);
// 		}
// 	}
// }

// async function fastForwardSymmetricRatchetWithoutSavingUntil(
// 	chatId: ChatId,
// 	currentVetkeyEpoch: bigint,
// 	neededSymmetricKeyEpoch: bigint
// ): Promise<DerivedKeyMaterial> {
// 	const mapKey = chatIdVetKeyEpochToString(chatId, currentVetkeyEpoch);
// 	const cur = chatIdStringToEpochKeyState.get(mapKey);
// 	if (!cur) {
// 		chatIdStringToEpochKeyState.set(mapKey, {
// 			status: 'missing'
// 		});
// 		return await fastForwardSymmetricRatchetWithoutSavingUntil(
// 			chatId,
// 			currentVetkeyEpoch,
// 			neededSymmetricKeyEpoch
// 		);
// 	}
// 	if (cur.status === 'error') {
// 		throw new Error('Failed to get epoch key: ' + cur.error);
// 	}
// 	if (cur.status !== 'ready') {
// 		throw new Error('Epoch key is not ready for symmetric ratchet');
// 	}
// 	const { key, symmetricKeyEpoch: currentSymmetricKeyEpoch } = cur;
// 	if (currentSymmetricKeyEpoch >= neededSymmetricKeyEpoch) {
// 		return DerivedKeyMaterial.fromCryptoKey(key);
// 	}

// 	let derivedKeyState = { epochKey: key, symmetricKeyEpoch: currentSymmetricKeyEpoch };
// 	while (derivedKeyState.symmetricKeyEpoch < neededSymmetricKeyEpoch) {
// 		derivedKeyState = {
// 			epochKey: await deriveNextSymmetricRatchetEpochCryptoKey(
// 				derivedKeyState.epochKey,
// 				derivedKeyState.symmetricKeyEpoch
// 			),
// 			symmetricKeyEpoch: derivedKeyState.symmetricKeyEpoch + 1n
// 		};
// 	}
// 	return DerivedKeyMaterial.fromCryptoKey(derivedKeyState.epochKey);
// }
