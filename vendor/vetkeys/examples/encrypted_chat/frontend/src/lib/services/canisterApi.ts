import type { ActorSubclass } from '@dfinity/agent';
import type { SymmetricRatchetStats } from '../types';
import type {
	_SERVICE,
	ChatId,
	EncryptedMessage,
	GroupChatMetadata,
	UserMessage,
	VetKeyEpochMetadata
} from '../../declarations/encrypted_chat/encrypted_chat.did';
import { Principal } from '@dfinity/principal';
import { stringifyBigInt } from '$lib/utils';
import { TransportSecretKey, EncryptedVetKey, DerivedPublicKey, VetKey } from '@dfinity/vetkeys';

// Dummy API service that simulates backend calls
// In real implementation, these would make actual API calls to the backend

export class CanisterAPI {
	async createDirectChat(
		actor: ActorSubclass<_SERVICE>,
		receiver: Principal,
		symmetricKeyRotationDurationMinutes: bigint,
		messageExpirationDurationMinutes: bigint
	): Promise<{ creationDate: Date }> {
		const result = await actor.create_direct_chat(
			receiver,
			symmetricKeyRotationDurationMinutes,
			messageExpirationDurationMinutes
		);
		if ('Err' in result) {
			throw new Error(result.Err);
		} else {
			return { creationDate: new Date(Number(result.Ok / BigInt(1_000_000))) };
		}
	}

	async createGroupChat(
		actor: ActorSubclass<_SERVICE>,
		otherParticipants: Principal[],
		symmetricKeyRotationDurationMinutes: bigint,
		messageExpirationDurationMinutes: bigint
	): Promise<GroupChatMetadata> {
		const result = await actor.create_group_chat(
			otherParticipants,
			symmetricKeyRotationDurationMinutes,
			messageExpirationDurationMinutes
		);
		if ('Ok' in result) {
			return result.Ok;
		} else {
			throw new Error(result.Err);
		}
	}

	async sendDirectMessage(
		actor: ActorSubclass<_SERVICE>,
		receiver: Principal,
		message: UserMessage
	): Promise<{ chatMessageId: bigint }> {
		const result = await actor.send_direct_message(message, receiver);
		console.log(
			`sendDirectMessage: ${stringifyBigInt(message)} to ${receiver.toText()} with result ${stringifyBigInt(result)}`
		);
		if ('Ok' in result) {
			return { chatMessageId: result.Ok };
		} else {
			throw new Error(result.Err);
		}
	}

	async sendGroupMessage(
		actor: ActorSubclass<_SERVICE>,
		groupChatId: bigint,
		message: UserMessage
	): Promise<{ chatMessageId: bigint }> {
		const result = await actor.send_group_message(message, groupChatId);
		console.log(
			`sendGroupMessage: ${stringifyBigInt(message)} to ${groupChatId} with result ${stringifyBigInt(result)}`
		);
		if ('Ok' in result) {
			return { chatMessageId: result.Ok };
		} else {
			throw new Error(result.Err);
		}
	}

	async getChatIdsAndCurrentNumbersOfMessages(
		actor: ActorSubclass<_SERVICE>
	): Promise<{ chatId: ChatId; numMessages: bigint }[]> {
		const chatIds = await actor.get_my_chat_ids();
		return chatIds.map(([chatId, numMessages]) => {
			return { chatId, numMessages };
		});
	}

	async getLatestVetKeyEpochMetadata(
		actor: ActorSubclass<_SERVICE>,
		chatId: ChatId
	): Promise<VetKeyEpochMetadata> {
		const metadata = await actor.get_latest_chat_vetkey_epoch_metadata(chatId);
		console.log(
			`getLatestVetKeyEpochMetadata: ${stringifyBigInt(chatId)} with result ${stringifyBigInt(metadata)}`
		);
		if ('Ok' in metadata) {
			return metadata.Ok;
		} else {
			throw new Error(metadata.Err);
		}
	}

	async getVetKeyEpochMetadata(
		actor: ActorSubclass<_SERVICE>,
		chatId: ChatId,
		vetKeyEpoch: bigint
	): Promise<VetKeyEpochMetadata> {
		const metadata = await actor.get_vetkey_epoch_metadata(chatId, vetKeyEpoch);
		console.log(
			`getLatestVetKeyEpochMetadata: ${stringifyBigInt(chatId)} with result ${stringifyBigInt(metadata)}`
		);
		if ('Ok' in metadata) {
			return metadata.Ok;
		} else {
			throw new Error(metadata.Err);
		}
	}

	async getDerivedPublicKey(
		actor: ActorSubclass<_SERVICE>,
		chatId: ChatId,
		vetKeyEpoch: bigint
	): Promise<DerivedPublicKey> {
		const bytes = await actor.chat_public_key(chatId, vetKeyEpoch);
		console.log(
			`getDerivedPublicKey: ${stringifyBigInt(chatId)} with result ${stringifyBigInt(bytes)}`
		);
		return DerivedPublicKey.deserialize(Uint8Array.from(bytes));
	}

	async getVetKey(
		actor: ActorSubclass<_SERVICE>,
		chatId: ChatId,
		vetKeyEpoch: bigint
	): Promise<VetKey> {
		const tsk = TransportSecretKey.random();
		const result = await actor.derive_chat_vetkey(chatId, [vetKeyEpoch], tsk.publicKeyBytes());
		console.log(`getVetKey: ${stringifyBigInt(chatId)} with result ${stringifyBigInt(result)}`);
		if ('Ok' in result) {
			const encryptedVetKey = EncryptedVetKey.deserialize(Uint8Array.from(result.Ok));
			const derivedPublicKey = await this.getDerivedPublicKey(actor, chatId, vetKeyEpoch);
			const vetKey = encryptedVetKey.decryptAndVerify(tsk, derivedPublicKey, new Uint8Array());
			return vetKey;
		} else {
			throw new Error(result.Err);
		}
	}

	getRatchetStats(): SymmetricRatchetStats {
		const now = Date.now();
		const last = new Date(now - 1000 * 60 * 60 * Math.random() * 24);
		const next = new Date(now + 1000 * 60 * 60 * Math.random() * 24);
		return {
			currentEpoch: Math.floor(Math.random() * 30) + 1,
			messagesInCurrentEpoch: Math.floor(Math.random() * 200),
			lastRotation: last,
			nextScheduledRotation: next
		};
	}

	async fetchEncryptedMessages(
		actor: ActorSubclass<_SERVICE>,
		chatId: ChatId,
		startId: bigint,
		limit: bigint | undefined
	): Promise<EncryptedMessage[]> {
		const result = await actor.get_messages(chatId, startId, limit ? [Number(limit)] : []);
		console.log(
			`fetchEncryptedMessages: ${stringifyBigInt(chatId)} from ${startId.toString()} with limit ${limit} with result ${stringifyBigInt(result)}`
		);
		return result;
	}
}

export const canisterAPI = new CanisterAPI();
