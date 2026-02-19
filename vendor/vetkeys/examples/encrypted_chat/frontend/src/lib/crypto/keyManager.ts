import { SymmetricRatchetState } from './symmetricRatchet';
import { Principal } from '@dfinity/principal';

export class KeyManager {
	#symmetricRatchetStates: Map<string, Map<bigint, SymmetricRatchetState>> = new Map();

	constructor() {}

	getCurrentChatIdStrs(): string[] {
		return Array.from(this.#symmetricRatchetStates.keys());
	}

	inductSymmetricRatchetState(chatId: string, vetKeyEpoch: bigint, state: SymmetricRatchetState) {
		if (this.#symmetricRatchetStates.get(chatId)?.has(vetKeyEpoch)) {
			throw new Error(
				`KeyManager.inductState: Symmetric ratchet state for chatId ${chatId} and vetKeyEpoch ${vetKeyEpoch} already exists`
			);
		}
		console.log(
			`KeyManager.inductState: Inducting state for chatId ${chatId} and vetKeyEpoch ${vetKeyEpoch} with creation time ${state.getCreationTime().toUTCString()} and ratchet epoch ${state.getCurrentEpoch().toString()}`
		);
		this.#symmetricRatchetStates.set(chatId, new Map([[vetKeyEpoch, state]]));
	}

	async encryptNow(
		chatId: string,
		sender: Principal,
		senderMessageId: bigint,
		message: Uint8Array
	): Promise<{ encryptedBytes: Uint8Array; vetKeyEpoch: bigint; symmetricRatchetEpoch: bigint }> {
		const { vetKeyEpoch, symmetricRatchetState } = this.lastVetKeyEpoch(chatId);
		const { encryptedBytes, symmetricRatchetEpoch } = await symmetricRatchetState.encryptNow(
			sender,
			senderMessageId,
			message
		);

		return { encryptedBytes, vetKeyEpoch, symmetricRatchetEpoch };
	}

	async decryptAtTimeAndEvolveIfNeeded(
		chatId: string,
		sender: Principal,
		senderMessageId: bigint,
		vetKeyEpoch: bigint,
		encryptedBytes: Uint8Array,
		time: Date
	): Promise<Uint8Array> {
		const symmetricRatchetState = this.#symmetricRatchetStates.get(chatId)?.get(vetKeyEpoch);
		if (!symmetricRatchetState) {
			throw new Error(
				`KeyManager.decryptAtTimeAndEvolveIfNeeded: No symmetric ratchet states found for chatId ${chatId} and vetKeyEpoch ${vetKeyEpoch}`
			);
		}
		return await symmetricRatchetState.decryptAtTimeAndEvolveIfNeeded(
			sender,
			senderMessageId,
			encryptedBytes,
			time
		);
	}

	doesChatHaveKeys(chatId: string): boolean {
		return this.#symmetricRatchetStates.has(chatId);
	}

	doesChatHaveRatchetStateForEpoch(chatId: string, vetKeyEpoch: bigint): boolean {
		return this.#symmetricRatchetStates.get(chatId)?.has(vetKeyEpoch) ?? false;
	}

	private lastVetKeyEpoch(chatId: string): {
		vetKeyEpoch: bigint;
		symmetricRatchetState: SymmetricRatchetState;
	} {
		const chatIdEpochStates = this.#symmetricRatchetStates.get(chatId);
		if (!chatIdEpochStates) {
			throw new Error(
				`KeyManager.lastVetKeyEpoch: No symmetric ratchet states found for chatId ${chatId}`
			);
		}
		let last = null;

		for (const [vetKeyEpoch, symmetricRatchetState] of chatIdEpochStates.entries()) {
			if (last === null || vetKeyEpoch > last.vetKeyEpoch) {
				last = { vetKeyEpoch, symmetricRatchetState };
			}
		}
		if (last === null) {
			throw new Error(
				`Bug: KeyManager.lastVetKeyEpoch: chatIdEpochStates.size === 0 for chatId ${chatId}`
			);
		}
		return last;
	}
}
