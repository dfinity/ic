import { auth, getActor, getMyPrincipal } from '$lib/stores/auth.svelte';
import type { ActorSubclass } from '@dfinity/agent';
import type {
	_SERVICE,
	ChatId,
	EncryptedMessage,
	EncryptedMessageMetadata
} from '../../declarations/encrypted_chat/encrypted_chat.did';
import { KeyManager } from '$lib/crypto/keyManager';
import { RatchetInitializationService } from './ratchetInitializationService';
import { SymmetricRatchetEpochError, VetKeyEpochError, type Message } from '$lib/types';
import { canisterAPI } from './canisterApi';
import {
	chatIdFromString,
	chatIdsNumMessagesToSummary,
	chatIdToString,
	randomNonce
} from '$lib/utils';
import * as cbor from 'cbor-x';
import type { SymmetricRatchetState } from '$lib/crypto/symmetricRatchet';

type MessageContent = {
	textContent: string;
	fileData?: { name: string; size: number; type: string; data: Uint8Array };
};

export class EncryptedMessagingService {
	#ratchetInitializationService: RatchetInitializationService;
	#keyManager: KeyManager;

	#sendingQueue: Map<string, Uint8Array[]>;

	#receivingQueue: Map<string, Message[]>;
	#receivingQueueToDecrypt: Map<string, EncryptedMessage[]>;
	#chatIdToCurrentNumberOfRemoteMessages: Map<string, bigint>;
	#chatIdToCurrentNumberOfFetchedMessages: Map<string, bigint>;

	#backgroundWorker: BackgroundWorker;

	constructor() {
		this.#ratchetInitializationService = new RatchetInitializationService();
		this.#keyManager = new KeyManager();

		// Initialize sending and receiving queues
		this.#sendingQueue = new Map();
		this.#receivingQueue = new Map();
		this.#receivingQueueToDecrypt = new Map();

		this.#chatIdToCurrentNumberOfRemoteMessages = new Map();
		this.#chatIdToCurrentNumberOfFetchedMessages = new Map();

		// Start the background worker to handle encryption, sending, polling, and decryption
		this.#backgroundWorker = new BackgroundWorker();
	}

	start() {
		// Start the worker loop
		// The worker will periodically:
		// 1. Take outgoing messages from the sending queue, encrypt using RatchetInitializationService, and send via the actor.
		// 2. Poll for new encrypted messages from the canister, queue them for decryption.
		// 3. Decrypt received messages using RatchetInitializationService and put them into the receiving queue.
		void this.#backgroundWorker.start(
			async () => {
				await this.#pollForNewMessages();
				await this.#decryptReceivedMessages();
			},
			async () => this.#handleOutgoingMessages()
		);
	}

	inductSymmetricRatchetState(
		chatIdStr: string,
		vetKeyEpoch: bigint,
		symmetricRatchetState: SymmetricRatchetState
	) {
		this.#keyManager.inductSymmetricRatchetState(chatIdStr, vetKeyEpoch, symmetricRatchetState);
	}

	skipMessagesAvailableLocally(chatId: ChatId, numMessages: bigint) {
		console.log(
			'skipMessagesAvailableLocally: chatId',
			chatIdToString(chatId),
			'numMessages',
			numMessages.toString()
		);
		this.#chatIdToCurrentNumberOfFetchedMessages.set(chatIdToString(chatId), numMessages);
	}

	getCurrentChatIds(): ChatId[] {
		return this.#keyManager.getCurrentChatIdStrs().map(chatIdFromString);
	}

	enqueueSendMessage(chatId: ChatId, content: Uint8Array) {
		this.#sendingQueue.set(chatIdToString(chatId), [
			...(this.#sendingQueue.get(chatIdToString(chatId)) || []),
			content
		]);
	}

	takeReceivedMessages(): Map<string, Message[]> {
		const messages = this.#receivingQueue;
		this.#receivingQueue = new Map();
		return messages;
	}

	signalStopWorker() {
		this.#backgroundWorker.abortController.abort();
	}

	/**
	 * Handle outgoing messages: encrypt and send
	 */
	async #handleOutgoingMessages(): Promise<void> {
		for (const [chatId, contents] of this.#sendingQueue.entries()) {
			while (true) {
				const content = contents.shift();
				if (!content) {
					break;
				}
				await this.#handleOutgoingMessage(chatId, content);
			}
			this.#sendingQueue.delete(chatId);
		}
	}

	async #handleOutgoingMessage(chatIdStr: string, content: Uint8Array) {
		const MAX_RETRIES = 50;
		const TIMEOUT_MS = 1000;

		const nonce = randomNonce();
		for (let i = 0; i < MAX_RETRIES; i++) {
			try {
				const encrypted = await this.#keyManager.encryptNow(
					chatIdStr,
					getMyPrincipal(),
					nonce,
					content
				);
				await sendMessage(
					getActor(),
					chatIdFromString(chatIdStr),
					encrypted.vetKeyEpoch,
					encrypted.symmetricRatchetEpoch,
					nonce,
					encrypted.encryptedBytes
				);
				break;
			} catch (e) {
				console.info('#handleOutgoingMessage: VetKeyEpochError', e);
				if (e instanceof VetKeyEpochError) {
					const ratchetState =
						await this.#ratchetInitializationService.initializeRatchetStateAndReshareAndCacheIfNeeded(
							chatIdFromString(chatIdStr),
							e.requiredVetKeyEpoch
						);
					this.#keyManager.inductSymmetricRatchetState(
						chatIdStr,
						e.requiredVetKeyEpoch,
						ratchetState
					);
				} else if (e instanceof SymmetricRatchetEpochError) {
					console.log('#handleOutgoingMessage: Symmetric ratchet epoch error', e);
				} else {
					// Errors in sending are non-fatal.
					console.error('#handleOutgoingMessage: Unknown error', e);
				}
				await new Promise((resolve) => setTimeout(resolve, TIMEOUT_MS));
			}
		}
	}

	/**
	 * Poll for new messages from canister
	 */
	async #pollForNewMessages(): Promise<void> {
		if (auth.state.label !== 'initialized') return;

		// Get chat IDs and check for new messages
		const chatIds = await canisterAPI.getChatIdsAndCurrentNumbersOfMessages(getActor());

		const summary = chatIdsNumMessagesToSummary(chatIds);
		console.log('fetched ' + chatIds.length + ' chats: ' + summary);

		for (const { chatId, numMessages } of chatIds) {
			if (!this.#keyManager.doesChatHaveKeys(chatIdToString(chatId))) {
				console.log(
					'#pollForNewMessages: chatId',
					chatIdToString(chatId),
					'does not have keys, initializing'
				);
				const latestVetKeyEpoch = (
					await canisterAPI.getLatestVetKeyEpochMetadata(getActor(), chatId)
				).epoch_id;
				const ratchetState =
					await this.#ratchetInitializationService.initializeRatchetStateAndReshareAndCacheIfNeeded(
						chatId,
						latestVetKeyEpoch
					);
				this.#keyManager.inductSymmetricRatchetState(
					chatIdToString(chatId),
					latestVetKeyEpoch,
					ratchetState
				);
			}

			const currentNumberOfFetchedMessages =
				this.#chatIdToCurrentNumberOfFetchedMessages.get(chatIdToString(chatId)) ?? 0n;
			this.#chatIdToCurrentNumberOfRemoteMessages.set(chatIdToString(chatId), numMessages);

			console.log(
				`#pollForNewMessages: new messages for chatId: ${chatIdToString(chatId)}, currentNumberOfFetchedMessages: ${currentNumberOfFetchedMessages}, numMessages: ${numMessages}`
			);

			// Get messages starting from the last known message ID
			const startId = 0n + currentNumberOfFetchedMessages;

			try {
				const messages = await canisterAPI.fetchEncryptedMessages(
					getActor(),
					chatId,
					startId,
					undefined
				);

				console.log(
					`#pollForNewMessages: fetched ${messages.length} messages for chatId ${chatIdToString(
						chatId
					)}, currentNumberOfFetchedMessages: ${currentNumberOfFetchedMessages}, numMessages: ${numMessages}, new fetched messages count: ${currentNumberOfFetchedMessages + BigInt(messages.length)}`
				);

				console.log(
					'#pollForNewMessages: old map this.#chatIdToCurrentNumberOfFetchedMessages ',
					this.#chatIdToCurrentNumberOfFetchedMessages
				);

				this.#chatIdToCurrentNumberOfFetchedMessages.set(
					chatIdToString(chatId),
					currentNumberOfFetchedMessages + BigInt(messages.length)
				);

				console.log(
					'#pollForNewMessages: new map this.#chatIdToCurrentNumberOfFetchedMessages ',
					this.#chatIdToCurrentNumberOfFetchedMessages
				);

				this.#receivingQueueToDecrypt.set(chatIdToString(chatId), [
					...(this.#receivingQueueToDecrypt.get(chatIdToString(chatId)) || []),
					...messages
				]);
			} catch (error) {
				// Polling errors are non-fatal if some messages are too big to receive several at once,
				// and polling just one message works
				console.info(
					'Failed to poll for new messages, trying again to pull just one message...',
					error
				);
				const messages = await canisterAPI.fetchEncryptedMessages(getActor(), chatId, startId, 1n);

				this.#chatIdToCurrentNumberOfFetchedMessages.set(
					chatIdToString(chatId),
					currentNumberOfFetchedMessages + BigInt(messages.length)
				);

				this.#receivingQueueToDecrypt.set(chatIdToString(chatId), [
					...(this.#receivingQueueToDecrypt.get(chatIdToString(chatId)) || []),
					...messages
				]);
			}
		}
	}

	/**
	 * Decrypt received messages and put into receiving queue
	 */
	async #decryptReceivedMessages(): Promise<void> {
		if (this.#receivingQueueToDecrypt.size !== 0) {
			console.log(
				'#decryptReceivedMessages: decrypting',
				this.#receivingQueueToDecrypt.size,
				'messages'
			);
		}
		for (const [chatIdStr, encryptedMessages] of this.#receivingQueueToDecrypt.entries()) {
			for (const encryptedMessage of encryptedMessages) {
				const decrypted = await this.#decryptMessage(chatIdStr, encryptedMessage);
				this.#receivingQueueToDecrypt.get(chatIdStr)?.shift();
				this.#receivingQueue.set(chatIdStr, [
					...(this.#receivingQueue.get(chatIdStr) || []),
					decrypted
				]);
			}
			this.#receivingQueueToDecrypt.delete(chatIdStr);
		}
	}

	async #decryptMessage(chatIdStr: string, encryptedMessage: EncryptedMessage): Promise<Message> {
		console.log(
			'#decryptMessage: decrypting',
			encryptedMessage.metadata.chat_message_id.toString(),
			'for chatId',
			chatIdStr
		);
		for (let i = 0; i < 2; i++) {
			try {
				const decrypted = await this.#keyManager.decryptAtTimeAndEvolveIfNeeded(
					chatIdStr,
					encryptedMessage.metadata.sender,
					encryptedMessage.metadata.nonce,
					encryptedMessage.metadata.vetkey_epoch,
					new Uint8Array(encryptedMessage.content),
					new Date(Number(encryptedMessage.metadata.timestamp / 1_000_000n))
				);

				return this.#parseMessage(chatIdStr, encryptedMessage.metadata, decrypted);
			} catch (error) {
				if (
					i === 0 &&
					!this.#keyManager.doesChatHaveRatchetStateForEpoch(
						chatIdStr,
						encryptedMessage.metadata.vetkey_epoch
					)
				) {
					console.info(
						`#decryptMessage: Failed to decrypt message ${encryptedMessage.metadata.chat_message_id.toString()}, trying again... Caught error: ${error instanceof Error ? error.message : 'Unknown error'}`
					);
					const ratchetState =
						await this.#ratchetInitializationService.initializeRatchetStateAndReshareAndCacheIfNeeded(
							chatIdFromString(chatIdStr),
							encryptedMessage.metadata.vetkey_epoch
						);
					this.#keyManager.inductSymmetricRatchetState(
						chatIdStr,
						encryptedMessage.metadata.vetkey_epoch,
						ratchetState
					);
				} else {
					throw error;
				}
			}
		}

		throw Error('unreachable code');
	}

	#parseMessage(
		chatIdStr: string,
		metadata: EncryptedMessageMetadata,
		decrypted: Uint8Array
	): Message {
		const messageContent = cbor.decode(decrypted) as MessageContent;

		return {
			messageId: metadata.chat_message_id.toString(),
			chatId: chatIdStr,
			senderId: metadata.sender.toText(),
			content: messageContent.textContent,
			timestamp: new Date(Number(metadata.timestamp / 1_000_000n)),
			fileData: messageContent.fileData,
			vetkeyEpoch: Number(metadata.vetkey_epoch),
			symmetricRatchetEpoch: Number(metadata.symmetric_key_epoch)
		};
	}
}

class BackgroundWorker {
	abortController: AbortController;

	constructor() {
		this.abortController = new AbortController();
	}

	async start(
		receiverFunction: () => Promise<void>,
		senderFunction: () => Promise<void>
	): Promise<void> {
		const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

		const run = async (fn: () => Promise<void>) => {
			while (!this.abortController.signal.aborted) {
				try {
					await fn();
				} catch (error) {
					console.error('Background worker error:', error);
				}
				if (this.abortController.signal.aborted) break;
				await sleep(500);
			}
		};

		const tasks = [run(receiverFunction), run(senderFunction)];

		if (this.abortController.signal.aborted) {
			await Promise.all(tasks);
			return;
		}

		// Resolve after an abort signal and after both loops finish
		await new Promise<void>((resolve) => {
			this.abortController.signal.addEventListener('abort', () => resolve(), { once: true });
		});

		await Promise.all(tasks);
	}
}

async function sendMessage(
	actor: ActorSubclass<_SERVICE>,
	chatId: ChatId,
	vetKeyEpoch: bigint,
	symmetricRatchetEpoch: bigint,
	nonce: bigint,
	encryptedBytes: Uint8Array
) {
	// Create UserMessage for the canister
	const userMessage = {
		vetkey_epoch: vetKeyEpoch,
		content: encryptedBytes,
		symmetric_key_epoch: symmetricRatchetEpoch,
		nonce: nonce
	};

	// Send to canister using the appropriate method based on chat type
	try {
		if ('Direct' in chatId) {
			const receiver =
				getMyPrincipal().toText() === chatId.Direct[0].toText()
					? chatId.Direct[1]
					: chatId.Direct[0];
			await canisterAPI.sendDirectMessage(actor, receiver, userMessage);
		} else {
			await canisterAPI.sendGroupMessage(actor, chatId.Group, userMessage);
		}
	} catch (e) {
		if (e instanceof Error && e.message.toLowerCase().includes('wrong vetkey epoch')) {
			throw new VetKeyEpochError(
				e.message,
				(await canisterAPI.getLatestVetKeyEpochMetadata(actor, chatId)).epoch_id
			);
		} else if (
			e instanceof Error &&
			e.message.toLowerCase().includes('wrong symmetric ratchet epoch')
		) {
			throw new SymmetricRatchetEpochError(e.message);
		} else {
			throw e;
		}
	}
}
